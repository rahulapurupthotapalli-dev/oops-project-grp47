"""SQLite Persistent Storage Layer implementing the REPOSITORY Pattern.
Preserves users, IT services, incidents, investigation notes, audit history, and notifications.
"""
from datetime import datetime, timedelta
import json
import sqlite3
from contextlib import contextmanager
from threading import local, RLock
from typing import Any, Dict, List, Optional

from .enums import EscalationTier, Priority, Role, SLAStatus, Status
from .events import Event, Observer
from .exceptions import EntityNotFound, IncidentNotFound, ServiceNotFound, UserNotFound
from .models import (DEFAULT_SLA, Administrator, Employee, Incident, ITService, SLAPolicy,
                     Technician, User)
from .repository import Repository


def _iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


class SQLiteDatabase:
    """Manages SQLite schema creation and connections."""

    def __init__(self, db_path: str = "iitsm.db"):
        self.db_path = db_path
        self._local = local()
        self._lock = RLock()
        self._mem_conn = sqlite3.connect(":memory:", check_same_thread=False) if db_path == ":memory:" else None
        if self._mem_conn:
            self._mem_conn.row_factory = sqlite3.Row
        self._init_db()

    @contextmanager
    def get_connection(self):
        active = getattr(self._local, "connection", None)
        if active is not None:
            yield active
            return
        with self._lock:
            conn = self._mem_conn or sqlite3.connect(self.db_path, timeout=15)
            conn.row_factory = sqlite3.Row
            self._local.connection = conn
            try:
                with conn:
                    yield conn
            finally:
                self._local.connection = None
                if conn is not self._mem_conn:
                    conn.close()

    @contextmanager
    def transaction(self):
        """Reserve the write lock before reading IDs, ownership or workload."""
        with self.get_connection() as conn:
            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            yield conn

    def _init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executescript("""
            CREATE TABLE IF NOT EXISTS settings (
                name TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL,
                password_hash TEXT,
                department TEXT,
                office_location TEXT,
                skills TEXT,
                experience_years INTEGER DEFAULT 1,
                max_workload INTEGER DEFAULT 5,
                available INTEGER DEFAULT 1,
                escalation_tier INTEGER DEFAULT 1,
                admin_title TEXT,
                total_resolved INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS services (
                name TEXT PRIMARY KEY,
                criticality INTEGER NOT NULL,
                default_category TEXT DEFAULT 'APPLICATION',
                sla_json TEXT
            );

            CREATE TABLE IF NOT EXISTS categories (
                name TEXT PRIMARY KEY,
                keywords TEXT
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                description TEXT NOT NULL,
                service_name TEXT NOT NULL,
                impact INTEGER NOT NULL,
                urgency INTEGER NOT NULL,
                affected_users INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                category TEXT,
                priority INTEGER,
                status TEXT NOT NULL,
                assigned_to_id TEXT,
                escalation_tier INTEGER DEFAULT 1,
                response_due TEXT,
                resolution_due TEXT,
                acknowledged_at TEXT,
                resolved_at TEXT,
                closed_at TEXT,
                resolution TEXT,
                feedback TEXT,
                related_ids TEXT,
                warnings TEXT,
                violations TEXT,
                FOREIGN KEY (reporter_id) REFERENCES users(id),
                FOREIGN KEY (service_name) REFERENCES services(name),
                FOREIGN KEY (assigned_to_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS incident_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                author_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            );

            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                incident_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                description TEXT NOT NULL,
                created_at TEXT NOT NULL,
                old_state TEXT,
                new_state TEXT,
                recipients TEXT
            );

            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            );
            """)


class SQLiteUserRepository(Repository):
    """SQLite implementation for Users (polymorphic Employee, Technician, Administrator)."""

    def __init__(self, db: SQLiteDatabase):
        self._db = db

    def save(self, user: User):
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            skills_str = ",".join(user.skills) if hasattr(user, "skills") else ""
            dept = getattr(user, "department", None)
            loc = getattr(user, "office_location", None)
            exp = getattr(user, "experience_years", 1)
            max_wl = getattr(user, "max_workload", 5)
            avail = 1 if getattr(user, "available", True) else 0
            tier = user.escalation_tier.value if hasattr(user, "escalation_tier") else 1
            admin_title = getattr(user, "admin_title", None)
            resolved = getattr(user, "total_resolved", 0)

            cur.execute("""
            INSERT INTO users (
                id, name, email, role, password_hash, department, office_location,
                skills, experience_years, max_workload, available, escalation_tier, admin_title, total_resolved
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name,
                email=excluded.email,
                role=excluded.role,
                password_hash=excluded.password_hash,
                department=excluded.department,
                office_location=excluded.office_location,
                skills=excluded.skills,
                experience_years=excluded.experience_years,
                max_workload=excluded.max_workload,
                available=excluded.available,
                escalation_tier=excluded.escalation_tier,
                admin_title=excluded.admin_title,
                total_resolved=excluded.total_resolved
            """, (
                user.id, user.name, user.email, user.role.value, user.password_hash,
                dept, loc, skills_str, exp, max_wl, avail, tier, admin_title, resolved
            ))

    def get(self, user_id: str) -> User:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cur.fetchone()
            if not row:
                raise UserNotFound(f"User {user_id} not found in database")
            return self._row_to_user(row)

    def all(self) -> List[User]:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users ORDER BY id ASC")
            return [self._row_to_user(r) for r in cur.fetchall()]

    def count(self) -> int:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM users")
            return cur.fetchone()[0]

    def _row_to_user(self, r: sqlite3.Row) -> User:
        role = Role(r["role"])
        if role is Role.EMPLOYEE:
            return Employee(
                user_id=r["id"],
                name=r["name"],
                email=r["email"],
                department=r["department"] or "General",
                office_location=r["office_location"] or "HQ",
                password_hash=r["password_hash"]
            )
        elif role is Role.TECHNICIAN:
            skills = {s.strip() for s in r["skills"].split(",") if s.strip()} if r["skills"] else set()
            tier = EscalationTier(r["escalation_tier"] or 1)
            t = Technician(
                user_id=r["id"],
                name=r["name"],
                email=r["email"],
                skills=skills,
                experience_years=r["experience_years"] if r["experience_years"] is not None else 1,
                max_workload=r["max_workload"] or 5,
                available=bool(r["available"]),
                escalation_tier=tier,
                password_hash=r["password_hash"]
            )
            t.total_resolved = r["total_resolved"] or 0
            # Load active incident IDs for workload tracking
            with self._db.get_connection() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id FROM incidents WHERE assigned_to_id = ? AND status NOT IN ('RESOLVED', 'VERIFIED', 'CLOSED')", (t.id,))
                t._active = {row["id"] for row in cur.fetchall()}
            return t
        else:
            return Administrator(
                user_id=r["id"],
                name=r["name"],
                email=r["email"],
                admin_title=r["admin_title"] or "IT Systems Administrator",
                password_hash=r["password_hash"]
            )


def decode_policy(value):
    if not value:
        return None
    if value == "DEFAULT":
        return DEFAULT_SLA
    return SLAPolicy({Priority[key]: tuple(timedelta(seconds=n) for n in pair)
                      for key, pair in json.loads(value).items()})


class SQLiteServiceRepository(Repository):
    """SQLite implementation for IT Services."""

    def __init__(self, db: SQLiteDatabase):
        self._db = db

    def save(self, service: ITService):
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            sla_val = json.dumps({p.name: [t.total_seconds() for t in service.sla_policy.targets_for(p)]
                                  for p in Priority}) if service.sla_policy else None
            cur.execute("""
            INSERT INTO services (name, criticality, default_category, sla_json) VALUES (?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                criticality=excluded.criticality,
                default_category=excluded.default_category,
                sla_json=excluded.sla_json
            """, (service.name, service.criticality, getattr(service, "default_category", "APPLICATION"), sla_val))

    def get(self, service_name: str) -> ITService:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM services WHERE name = ?", (service_name,))
            row = cur.fetchone()
            if not row:
                raise ServiceNotFound(f"IT Service {service_name} not found")
            policy = decode_policy(row["sla_json"])
            return ITService(row["name"], row["criticality"], policy, row["default_category"])

    def all(self) -> List[ITService]:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM services ORDER BY name ASC")
            return [ITService(r["name"], r["criticality"], decode_policy(r["sla_json"]), r["default_category"]) for r in cur.fetchall()]

    def count(self) -> int:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM services")
            return cur.fetchone()[0]


class SQLiteIncidentRepository(Repository):
    """SQLite implementation for Incidents, supporting multi-criteria search and analytics."""

    def __init__(self, db: SQLiteDatabase, user_repo: SQLiteUserRepository, service_repo: SQLiteServiceRepository):
        self._db = db
        self._user_repo = user_repo
        self._service_repo = service_repo

    def transaction(self):
        return self._db.transaction()

    def next_id(self):
        # Called inside the same write transaction as the incident insert.
        with self._db.get_connection() as conn:
            maximum = conn.execute(
                "SELECT MAX(CAST(substr(id, 4) AS INTEGER)) FROM incidents WHERE id LIKE 'INC%'"
            ).fetchone()[0]
            return max(1000, maximum or 0) + 1

    def save(self, inc: Incident):
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            INSERT INTO incidents (
                id, reporter_id, description, service_name, impact, urgency, affected_users,
                created_at, category, priority, status, assigned_to_id, escalation_tier,
                response_due, resolution_due, acknowledged_at, resolved_at, closed_at,
                resolution, feedback, related_ids, warnings, violations
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                reporter_id=excluded.reporter_id,
                description=excluded.description,
                service_name=excluded.service_name,
                impact=excluded.impact,
                urgency=excluded.urgency,
                affected_users=excluded.affected_users,
                created_at=excluded.created_at,
                category=excluded.category,
                priority=excluded.priority,
                status=excluded.status,
                assigned_to_id=excluded.assigned_to_id,
                escalation_tier=excluded.escalation_tier,
                response_due=excluded.response_due,
                resolution_due=excluded.resolution_due,
                acknowledged_at=excluded.acknowledged_at,
                resolved_at=excluded.resolved_at,
                closed_at=excluded.closed_at,
                resolution=excluded.resolution,
                feedback=excluded.feedback,
                related_ids=excluded.related_ids,
                warnings=excluded.warnings,
                violations=excluded.violations
            """, (
                inc.id,
                inc.reporter.id,
                inc.description,
                inc.service.name,
                inc.impact,
                inc.urgency,
                inc.affected_users,
                _iso(inc.created_at),
                inc.category,
                inc.priority.value if inc.priority else None,
                inc.status.value,
                inc.assigned_to.id if inc.assigned_to else None,
                inc.escalation_tier.value if hasattr(inc, "escalation_tier") else 1,
                _iso(inc.response_due),
                _iso(inc.resolution_due),
                _iso(inc.acknowledged_at),
                _iso(inc.resolved_at),
                _iso(inc.closed_at),
                inc.resolution,
                inc.feedback,
                ",".join(inc.related),
                ",".join(inc.warnings),
                ",".join(inc.violations)
            ))

            # Save notes if any
            if inc.notes:
                for created_at, author_id, content in inc.notes:
                    cur.execute("""
                    SELECT 1 FROM incident_notes WHERE incident_id = ? AND author_id = ? AND created_at = ?
                    """, (inc.id, author_id, _iso(created_at)))
                    if not cur.fetchone():
                        cur.execute("""
                        INSERT INTO incident_notes (incident_id, author_id, content, created_at)
                        VALUES (?, ?, ?, ?)
                        """, (inc.id, author_id, content, _iso(created_at)))


    def get(self, incident_id: str) -> Incident:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
            row = cur.fetchone()
            if not row:
                raise IncidentNotFound(f"Incident {incident_id} not found")
            return self._row_to_incident(row)

    def all(self) -> List[Incident]:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM incidents ORDER BY created_at DESC")
            return [self._row_to_incident(r) for r in cur.fetchall()]

    def count(self) -> int:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM incidents")
            return cur.fetchone()[0]

    def _row_to_incident(self, r: sqlite3.Row) -> Incident:
        reporter = self._user_repo.get(r["reporter_id"])
        service = self._service_repo.get(r["service_name"])
        inc = Incident(
            incident_id=r["id"],
            reporter=reporter,
            description=r["description"],
            service=service,
            impact=r["impact"],
            urgency=r["urgency"],
            affected_users=r["affected_users"],
            created_at=_parse_iso(r["created_at"]),
            category=r["category"]
        )
        if r["priority"]:
            inc.priority = Priority(r["priority"])
        if r["assigned_to_id"]:
            try:
                inc.assigned_to = self._user_repo.get(r["assigned_to_id"])
            except Exception:
                inc.assigned_to = None

        if r["escalation_tier"]:
            inc.escalation_tier = EscalationTier(r["escalation_tier"])

        inc.response_due = _parse_iso(r["response_due"])
        inc.resolution_due = _parse_iso(r["resolution_due"])
        inc.acknowledged_at = _parse_iso(r["acknowledged_at"])
        inc.resolved_at = _parse_iso(r["resolved_at"])
        inc.closed_at = _parse_iso(r["closed_at"])
        inc.resolution = r["resolution"]
        inc.feedback = r["feedback"]
        inc.related = [x.strip() for x in r["related_ids"].split(",") if x.strip()] if r["related_ids"] else []
        inc.warnings = {x.strip().removesuffix("_APPROACHING") for x in r["warnings"].split(",") if x.strip()} if r["warnings"] else set()
        inc.violations = {x.strip().removesuffix("_BREACHED") for x in r["violations"].split(",") if x.strip()} if r["violations"] else set()

        # Set internal state
        target_status = Status(r["status"])
        from .states import STATE_FOR
        inc._state = STATE_FOR[target_status]()

        # Load notes
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT author_id, content, created_at FROM incident_notes WHERE incident_id = ? ORDER BY created_at ASC", (inc.id,))
            inc.notes = [(_parse_iso(nrow["created_at"]), nrow["author_id"], nrow["content"]) for nrow in cur.fetchall()]

        return inc

    def search_incidents(self, filters: Dict[str, Any]) -> List[Incident]:
        """Multi-criteria search supporting 8+ distinct criteria."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params = []

        if filters.get("incident_id"):
            query += " AND id LIKE ?"
            params.append(f"%{filters['incident_id'].strip().upper()}%")

        if filters.get("status"):
            query += " AND status = ?"
            params.append(filters["status"].strip().upper())

        if filters.get("priority"):
            val = filters["priority"]
            p_val = val.value if hasattr(val, "value") else int(str(val).replace("P", ""))
            query += " AND priority = ?"
            params.append(p_val)

        if filters.get("category"):
            query += " AND category = ?"
            params.append(filters["category"].strip().upper())

        if filters.get("service"):
            query += " AND service_name = ?"
            params.append(filters["service"].strip())

        reporter = filters.get("reporter_id") or filters.get("reporter")
        if reporter:
            query += " AND reporter_id = ?"
            params.append(reporter.strip())

        tech = filters.get("technician_id") or filters.get("technician")
        if tech:
            query += " AND assigned_to_id = ?"
            params.append(tech.strip())

        if filters.get("from_date"):
            query += " AND created_at >= ?"
            params.append(filters["from_date"])

        if filters.get("to_date"):
            query += " AND created_at <= ?"
            params.append(filters["to_date"])

        kw_val = filters.get("search_text") or filters.get("keyword") or filters.get("q")
        if kw_val:
            kw = f"%{kw_val.strip().lower()}%"
            query += " AND (LOWER(description) LIKE ? OR LOWER(id) LIKE ?)"
            params.extend([kw, kw])

        query += " ORDER BY created_at DESC"

        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            incidents = [self._row_to_incident(r) for r in cur.fetchall()]

        # Filter by computed SLA status in memory if requested
        if filters.get("sla_status"):
            target_sla = filters["sla_status"]
            from .sla import incident_sla_status
            now = datetime.now()
            return [inc for inc in incidents if incident_sla_status(inc, now) == target_sla]

        return incidents


class SQLiteAuditLog(Observer):
    """Observer pattern: writes immutable audit events directly to SQLite."""

    def __init__(self, db: SQLiteDatabase):
        self._db = db

    def update(self, event: Event):
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            rec_str = ",".join(event.recipients) if event.recipients else ""
            cur.execute("""
            INSERT INTO audit_logs (event_type, incident_id, actor, description, created_at, old_state, new_state, recipients)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.type,
                event.incident_id,
                event.actor,
                event.description,
                _iso(event.at),
                event.old_state,
                event.new_state,
                rec_str
            ))

    def history(self, incident_id: str) -> List[Dict[str, Any]]:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM audit_logs WHERE incident_id = ? ORDER BY created_at ASC", (incident_id,))
            return [dict(r) for r in cur.fetchall()]

    def recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]


class SQLiteNotificationObserver(Observer):
    """Observer pattern: stores in-app and simulated email notifications into SQLite."""

    def __init__(self, db: SQLiteDatabase):
        self._db = db
        self.NOTIFY = {"INCIDENT_CREATED", "INCIDENT_ASSIGNED", "PRIORITY_CALCULATED", "SLA_WARNING",
                       "SLA_VIOLATED", "INCIDENT_RESOLVED", "INCIDENT_CLOSED", "ASSIGNMENT_FAILED",
                       "INCIDENT_ESCALATED"}

    def update(self, event: Event):
        if event.type not in self.NOTIFY:
            return
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            now_str = _iso(event.at)
            for recipient_id in event.recipients:
                subject = f"[{event.incident_id}] {event.type}"
                # In-App
                cur.execute("""
                INSERT INTO notifications (recipient_id, channel, subject, body, created_at)
                VALUES (?, 'IN_APP', ?, ?, ?)
                """, (recipient_id, subject, event.description, now_str))
                # Simulated Email
                cur.execute("""
                INSERT INTO notifications (recipient_id, channel, subject, body, created_at)
                VALUES (?, 'SIMULATED_EMAIL', ?, ?, ?)
                """, (recipient_id, subject, f"Email alert to {recipient_id}: {event.description}", now_str))

    def get_user_notifications(self, user_id: str, limit: int = 30) -> List[Dict[str, Any]]:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
            SELECT * FROM notifications WHERE recipient_id = ? ORDER BY created_at DESC LIMIT ?
            """, (user_id, limit))
            return [dict(r) for r in cur.fetchall()]

    def get_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM notifications ORDER BY created_at DESC LIMIT ?", (limit,))
            return [dict(r) for r in cur.fetchall()]
