"""I-ITSM FastAPI Server.
Full-stack RESTful backend providing authentication, incident lifecycle management,
swappable assignment strategies, automated SLA monitoring, AI resolution diagnostics,
and multi-criteria analytics dashboards.
"""
import asyncio
from contextlib import asynccontextmanager
from datetime import date, datetime, timedelta
import json
import logging
import sqlite3
import os
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Header, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from iitsm.auth import PasswordHasher
from iitsm.bootstrap import build_sqlite_system
from iitsm.enums import EscalationTier, Priority, Role, Status
from iitsm.exceptions import (AuthenticationFailed, DuplicateIncident, EntityNotFound,
                              InvalidInput, InvalidStateTransition, MissingSLAConfiguration,
                              TechnicianUnavailable, UnauthorizedOperation, WorkloadExceeded)
from iitsm.exceptions import ITSMError
from iitsm.sla import incident_sla_status
from iitsm.models import SLAPolicy, DEFAULT_SLA, Administrator, Employee, Incident, ITService, Technician
from iitsm.seeder import seed_database
from iitsm.sqlite_repository import SQLiteDatabase, SQLiteServiceRepository, SQLiteUserRepository
from iitsm.strategies import (LoadBasedAssignment, RoundRobinAssignment,
                              SkillBasedAssignment)

# Database path
DB_PATH = os.getenv("IITSM_DB_PATH", os.path.join(os.path.dirname(__file__), "iitsm.db"))
db = SQLiteDatabase(DB_PATH)

# Seed database with sample data on startup
with db.transaction():
    seed_database(db, force=False)

# Build system
system = build_sqlite_system(DB_PATH)
analytics = system.analytics
ai_engine = system.ai
token_mgr = system.auth.tokens

# Background SLA Sweep Task
sla_sweep_task = None


async def run_sla_sweep_periodically():
    """Background task to periodically evaluate SLA compliance and auto-escalate breached tickets."""
    while True:
        try:
            await asyncio.sleep(60)  # Sweep every 60 seconds
            await asyncio.to_thread(sweep_slas, "SLA_DAEMON")
        except asyncio.CancelledError:
            break
        except Exception:
            logging.exception("Scheduled SLA sweep failed")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global sla_sweep_task
    sla_sweep_task = asyncio.create_task(run_sla_sweep_periodically())
    yield
    if sla_sweep_task:
        sla_sweep_task.cancel()
        await sla_sweep_task


app = FastAPI(
    title="Intelligent IT Service Management (I-ITSM) API",
    description="Enterprise Incident & Service Management with OOP Architecture and Intelligent Automation",
    version="1.0.0",
    lifespan=lifespan
)

allowed_origins = [o.strip() for o in os.getenv("IITSM_ALLOWED_ORIGINS", "").split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----------------------------------------------------------------- Dependency Helpers
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Authorization header")
    token = authorization.split(" ")[1]
    try:
        user_info = token_mgr.decode_token(token)
        user = system.users.get(user_info["sub"])
        return user
    except (AuthenticationFailed, EntityNotFound, ValueError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid or expired session")


@app.exception_handler(ITSMError)
async def domain_error(request, exc):
    codes = {UnauthorizedOperation: 403, EntityNotFound: 404, DuplicateIncident: 409,
             InvalidStateTransition: 409, TechnicianUnavailable: 409, WorkloadExceeded: 409,
             InvalidInput: 422, MissingSLAConfiguration: 409, AuthenticationFailed: 401}
    code = next((value for kind, value in codes.items() if isinstance(exc, kind)), 400)
    return JSONResponse({"detail": str(exc)}, status_code=code)


@app.exception_handler(sqlite3.OperationalError)
async def database_error(request, exc):
    logging.error("Database operation failed", exc_info=exc)
    return JSONResponse({"detail": "Database temporarily unavailable"}, status_code=503)


def require_role(allowed_roles: List[Role]):
    def checker(user=Depends(get_current_user)):
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation restricted to roles: {[r.value for r in allowed_roles]}. Current role: {user.role.value}"
            )
        return user
    return checker


# ----------------------------------------------------------------- Pydantic DTO Schemas
class LoginRequest(BaseModel):
    user_id_or_email: str
    password: str


class IncidentCreateRequest(BaseModel):
    description: str
    service_name: str
    impact: int = Field(ge=1, le=5)
    urgency: int = Field(ge=1, le=5)
    affected_users: int = Field(ge=1, default=1)
    category: Optional[str] = None


class AcknowledgeRequest(BaseModel):
    notes: Optional[str] = None


class InvestigationNoteRequest(BaseModel):
    content: str


class ResolveRequest(BaseModel):
    resolution: str


class VerifyRequest(BaseModel):
    feedback: Optional[str] = None


class EscalateRequest(BaseModel):
    reason: Optional[str] = "Manual escalation requested"


class ReassignRequest(BaseModel):
    technician_id: Optional[str] = None
    strategy: Optional[str] = None  # "SKILL", "LOAD", "ROUND_ROBIN"


class StrategyChangeRequest(BaseModel):
    strategy: str  # "SKILL", "LOAD", "ROUND_ROBIN"


class CategoryRegisterRequest(BaseModel):
    name: str
    keywords: List[str]


class ServiceCreateRequest(BaseModel):
    name: str
    criticality: int = Field(ge=1, le=5)
    default_category: str = "APPLICATION"


class UserCreateRequest(BaseModel):
    id: str
    name: str
    email: str
    role: Role
    password: str = Field(min_length=8)
    department: Optional[str] = "Engineering"
    office_location: Optional[str] = "HQ"
    skills: Optional[List[str]] = []
    experience_years: int = Field(default=1, ge=0)
    max_workload: int = Field(default=5, ge=1)
    escalation_tier: int = Field(default=1, ge=1, le=4)
    admin_title: Optional[str] = "IT Systems Administrator"

    @field_validator("role", mode="before")
    @classmethod
    def normalize_role(cls, value):
        return value.strip().upper() if isinstance(value, str) else value


# ----------------------------------------------------------------- Helper Serializers
def serialize_incident(inc: Incident) -> Dict[str, Any]:
    return {
        "id": inc.id,
        "reporter": {
            "id": inc.reporter.id,
            "name": inc.reporter.name,
            "email": inc.reporter.email,
            "department": getattr(inc.reporter, "department", "General")
        },
        "description": inc.description,
        "service": {
            "name": inc.service.name,
            "criticality": inc.service.criticality,
            "default_category": getattr(inc.service, "default_category", "APPLICATION")
        } if inc.service else None,
        "impact": inc.impact,
        "urgency": inc.urgency,
        "affected_users": inc.affected_users,
        "category": inc.category,
        "priority": {
            "value": inc.priority.value if inc.priority else None,
            "name": inc.priority.name if inc.priority else None
        } if inc.priority else None,
        "status": inc.status.value,
        "assigned_to": {
            "id": inc.assigned_to.id,
            "name": inc.assigned_to.name,
            "email": inc.assigned_to.email,
            "skills": sorted(inc.assigned_to.skills),
            "tier": inc.assigned_to.escalation_tier.title if hasattr(inc.assigned_to, "escalation_tier") else "Technician",
            "workload": inc.assigned_to.workload,
            "max_workload": inc.assigned_to.max_workload
        } if inc.assigned_to else None,
        "escalation_tier": {
            "value": inc.escalation_tier.value if hasattr(inc, "escalation_tier") else 1,
            "title": inc.escalation_tier.title if hasattr(inc, "escalation_tier") else "Tier 1: Support Technician"
        },
        "created_at": inc.created_at.isoformat() if inc.created_at else None,
        "response_due": inc.response_due.isoformat() if inc.response_due else None,
        "resolution_due": inc.resolution_due.isoformat() if inc.resolution_due else None,
        "acknowledged_at": inc.acknowledged_at.isoformat() if inc.acknowledged_at else None,
        "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        "closed_at": inc.closed_at.isoformat() if inc.closed_at else None,
        "resolution": inc.resolution,
        "feedback": inc.feedback,
        "related": inc.related,
        "sla_status": incident_sla_status(inc, datetime.now()),
        "warnings": sorted(inc.warnings),
        "violations": sorted(inc.violations),
        "notes_count": len(inc.notes)
    }


def serialize_user(user) -> Dict[str, Any]:
    data = {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role.value
    }
    if isinstance(user, Employee):
        data["department"] = user.department
        data["office_location"] = user.office_location
    elif isinstance(user, Technician):
        data["skills"] = sorted(user.skills)
        data["experience_years"] = user.experience_years
        data["max_workload"] = user.max_workload
        data["workload"] = user.workload
        data["available"] = user.available
        data["escalation_tier"] = {
            "value": user.escalation_tier.value,
            "title": user.escalation_tier.title
        }
        data["total_resolved"] = getattr(user, "total_resolved", 0)
    elif isinstance(user, Administrator):
        data["admin_title"] = user.admin_title
    return data


# ----------------------------------------------------------------- API Routes: Authentication
@app.post("/api/auth/login")
def login(req: LoginRequest):
    try:
        user, token = system.auth.authenticate(req.user_id_or_email, req.password)
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": serialize_user(user)
        }
    except AuthenticationFailed as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))


@app.get("/api/auth/me")
def get_me(user=Depends(get_current_user)):
    return serialize_user(user)


@app.get("/api/auth/demo-users")
def get_demo_users():
    """Returns sample users across all roles and tiers for 1-click evaluation switching."""
    return [{"id": uid, "name": system.users.get(uid).name} for uid in
            ("emp1", "tech_t1_1", "tech_t2_1", "tech_t3_1", "admin1")]



# ----------------------------------------------------------------- API Routes: Incidents
@app.get("/api/incidents")
def list_incidents(
    incident_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    technician_id: Optional[str] = Query(None),
    reporter_id: Optional[str] = Query(None),
    sla_status: Optional[str] = Query(None),
    from_date: Optional[date] = Query(None),
    to_date: Optional[date] = Query(None),
    q: Optional[str] = Query(None),
    user=Depends(get_current_user)
):
    filters = {
        "incident_id": incident_id,
        "status": status,
        "priority": priority,
        "category": category,
        "service": service,
        "technician_id": technician_id,
        "reporter_id": reporter_id,
        "sla_status": sla_status,
        "from_date": from_date.isoformat() if from_date else None,
        "to_date": to_date.isoformat() + "T23:59:59.999999" if to_date else None,
        "search_text": q
    }
    # Enforce role scoping: employees can strictly and solely view their own reported incidents
    if user.role == Role.EMPLOYEE:
        filters["reporter_id"] = user.id

    if from_date and to_date and from_date > to_date:
        raise InvalidInput("Start date must be on or before end date")
    if user.role is Role.TECHNICIAN:
        filters["technician_id"] = user.id
    if priority and priority.upper() not in {p.name for p in Priority} | {"1", "2", "3", "4"}:
        raise InvalidInput("Priority must be P1, P2, P3 or P4")
    filters["priority"] = priority.upper() if priority else None
    incidents = system.incidents.search_incidents(filters)
    return [serialize_incident(inc) for inc in incidents]


@app.post("/api/incidents")
def report_incident(req: IncidentCreateRequest, user=Depends(get_current_user)):
    inc = system.service.report(
        reporter_id=user.id,
        description=req.description,
        service_name=req.service_name,
        impact=req.impact,
        urgency=req.urgency,
        affected_users=req.affected_users,
        category=req.category
    )
    return serialize_incident(inc)


def check_visibility(inc, user):
    if user.role is Role.EMPLOYEE and inc.reporter.id != user.id:
        raise UnauthorizedOperation("Only the reporter may access this ticket")
    if user.role is Role.TECHNICIAN and (not inc.assigned_to or inc.assigned_to.id != user.id):
        raise UnauthorizedOperation("This incident belongs to another queue")


@app.get("/api/incidents/{incident_id}")
def get_incident_details(incident_id: str, user=Depends(get_current_user)):
    inc = system.incidents.get(incident_id)
    check_visibility(inc, user)
    data = serialize_incident(inc)
    # Attach notes
    data["notes"] = [
        {"created_at": n[0].isoformat() if n[0] else None, "author_id": n[1], "content": n[2]}
        for n in inc.notes
    ]
    # Attach audit trail
    data["audit_trail"] = system.audit.history(inc.id)
    return data


@app.post("/api/incidents/{incident_id}/acknowledge")
def acknowledge_incident(incident_id: str, req: AcknowledgeRequest = None, user=Depends(get_current_user)):
    if req and req.notes and not req.notes.strip():
        raise InvalidInput("Note cannot be blank")
    inc = system.service.acknowledge(user.id, incident_id, req.notes if req else None)
    return serialize_incident(inc)


@app.post("/api/incidents/{incident_id}/investigate")
def start_investigation(incident_id: str, user=Depends(get_current_user)):
    inc = system.service.start_investigation(user.id, incident_id)
    return serialize_incident(inc)


@app.post("/api/incidents/{incident_id}/notes")
def add_note(incident_id: str, req: InvestigationNoteRequest, user=Depends(get_current_user)):
    system.service.add_note(user.id, incident_id, req.content)
    inc = system.incidents.get(incident_id)
    return serialize_incident(inc)


@app.post("/api/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: str, req: ResolveRequest, user=Depends(get_current_user)):
    inc = system.service.resolve(user.id, incident_id, req.resolution)
    return serialize_incident(inc)


@app.post("/api/incidents/{incident_id}/verify")
def verify_incident(incident_id: str, req: VerifyRequest, user=Depends(get_current_user)):
    inc = system.service.verify(user.id, incident_id, req.feedback)
    return serialize_incident(inc)


@app.post("/api/incidents/{incident_id}/close")
def close_incident(incident_id: str, user=Depends(get_current_user)):
    inc = system.service.close(user.id, incident_id)
    return serialize_incident(inc)


@app.post("/api/incidents/{incident_id}/escalate")
def escalate_incident(incident_id: str, req: EscalateRequest, user=Depends(require_role([Role.ADMIN, Role.TECHNICIAN]))):
    with system.incidents.transaction():
        check_visibility(system.incidents.get(incident_id), user)
        inc = system.service.escalate(incident_id, reason=req.reason, actor=user.id)
    return serialize_incident(inc)


@app.get("/api/incidents/{incident_id}/recommend-technicians")
def recommend_technicians(incident_id: str, user=Depends(require_role([Role.ADMIN]))):
    return system.service.recommend_technicians(incident_id)


@app.post("/api/incidents/{incident_id}/reassign")
def reassign_incident(incident_id: str, req: ReassignRequest, user=Depends(require_role([Role.ADMIN]))):
    strategy = assignment_strategy(req.strategy) if req.strategy else None
    inc = system.service.assign(incident_id, actor=user.id, technician_id=req.technician_id, strategy=strategy)
    return serialize_incident(inc)


@app.get("/api/incidents/{incident_id}/ai-diagnostics")
def get_ai_diagnostics(incident_id: str, user=Depends(require_role([Role.ADMIN, Role.TECHNICIAN]))):
    inc = system.incidents.get(incident_id)
    check_visibility(inc, user)
    return ai_engine.analyze_incident(inc)


# ----------------------------------------------------------------- API Routes: Admin & System Settings
class EmployeeRegistration(BaseModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    email: str
    password: str = Field(min_length=8)


def create_unique_user(new_user):
    with db.transaction() as conn:
        existing = conn.execute(
            "SELECT 1 FROM users WHERE lower(id) IN (lower(?), lower(?)) OR lower(email) IN (lower(?), lower(?))",
            (new_user.id, new_user.email, new_user.id, new_user.email)
        ).fetchone()
        if existing:
            raise HTTPException(409, "User ID or email already registered")
        SQLiteUserRepository(db).save(new_user)


@app.post("/api/auth/register", status_code=201)
def register_employee(req: EmployeeRegistration):
    employee = Employee(req.id.strip(), req.name.strip(), req.email.strip(),
                        password_hash=PasswordHasher.hash_password(req.password))
    create_unique_user(employee)
    return serialize_user(employee)


@app.get("/api/admin/users")
def list_admin_users(role: Optional[str] = Query(None), user=Depends(require_role([Role.ADMIN]))):
    users = system.users.all()
    if role:
        users = [u for u in users if u.role.value == role.upper()]
    return [serialize_user(u) for u in users]


@app.post("/api/admin/users")
def create_admin_user(req: UserCreateRequest, user=Depends(require_role([Role.ADMIN]))):
    pw_hash = PasswordHasher.hash_password(req.password)
    role_enum = req.role
    if role_enum == Role.EMPLOYEE:
        new_u = Employee(req.id, req.name, req.email, req.department or "General",
                         req.office_location or "HQ", pw_hash)
    elif role_enum == Role.TECHNICIAN:
        tier = EscalationTier(req.escalation_tier or 1)
        new_u = Technician(req.id, req.name, req.email, req.skills or [], req.experience_years,
                           req.max_workload or 5, True, tier, pw_hash)
    elif role_enum == Role.ADMIN:
        new_u = Administrator(req.id, req.name, req.email, req.admin_title or "Administrator", pw_hash)
    else:
        raise HTTPException(status_code=400, detail="Invalid role")

    create_unique_user(new_u)
    return serialize_user(new_u)


class TechnicianCapacity(BaseModel):
    available: bool
    max_workload: int = Field(ge=1)


@app.put("/api/admin/technicians/{user_id}/capacity")
def set_capacity(user_id: str, req: TechnicianCapacity, user=Depends(require_role([Role.ADMIN]))):
    with db.transaction():
        repository = SQLiteUserRepository(db)
        technician = repository.get(user_id)
        if not isinstance(technician, Technician):
            raise InvalidInput("Select a technician")
        if req.max_workload < technician.workload:
            raise WorkloadExceeded("Capacity cannot fall below the active incident count")
        technician.available, technician.max_workload = req.available, req.max_workload
        repository.save(technician)
        return serialize_user(technician)


@app.get("/api/admin/services")
def list_services(user=Depends(get_current_user)):
    services = system.services.all()
    return [{
        "name": s.name,
        "criticality": s.criticality,
        "sla_targets": {p.name: [t.total_seconds() / 60 for t in s.sla_policy.targets_for(p)]
                        for p in Priority} if s.sla_policy else None,
        "default_category": getattr(s, "default_category", "APPLICATION")
    } for s in services]


@app.post("/api/admin/services")
def create_service(req: ServiceCreateRequest, user=Depends(require_role([Role.ADMIN]))):
    s = ITService(req.name, req.criticality, DEFAULT_SLA, req.default_category)
    with db.transaction() as conn:
        if conn.execute("SELECT 1 FROM services WHERE name = ?", (s.name,)).fetchone():
            raise HTTPException(409, "Service already exists")
        SQLiteServiceRepository(db).save(s)
    return {"name": s.name, "criticality": s.criticality, "default_category": s.default_category}


class SLATarget(BaseModel):
    response_minutes: int = Field(gt=0, le=525600)
    resolution_minutes: int = Field(gt=0, le=525600)


@app.put("/api/admin/services/{service_name}/sla")
def configure_sla(service_name: str, targets: Dict[str, SLATarget], user=Depends(require_role([Role.ADMIN]))):
    if set(targets) != {p.name for p in Priority}:
        raise InvalidInput("Supply a response and resolution target for each of P1, P2, P3 and P4")
    if any(t.response_minutes > t.resolution_minutes for t in targets.values()):
        raise InvalidInput("Response target must be at or before resolution target")
    service = system.services.get(service_name)
    service.sla_policy = SLAPolicy({Priority[name]: (timedelta(minutes=t.response_minutes),
                                                    timedelta(minutes=t.resolution_minutes))
                                    for name, t in targets.items()})
    system.services.save(service)
    return {"service": service.name, "targets": targets}


@app.get("/api/admin/categories")
def list_categories(user=Depends(get_current_user)):
    return {
        "categories": system.catalog.names(),
        "catalog": {k: sorted(v) for k, v in system.catalog._kw.items()}
    }


@app.post("/api/admin/categories/suggest")
def suggest_category(payload: Dict[str, str], user=Depends(get_current_user)):
    desc = payload.get("description", "")
    suggested = system.catalog.suggest(desc)
    return {"suggested_category": suggested}


@app.post("/api/admin/categories")
def register_category(req: CategoryRegisterRequest, user=Depends(require_role([Role.ADMIN]))):
    name = req.name.strip().upper()
    if not name:
        raise InvalidInput("Category name cannot be empty")
    keywords = [word.strip().lower() for word in req.keywords if word.strip()]
    with db.transaction() as conn:
        conn.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", ("category:" + name, json.dumps(keywords)))
        system.catalog.register(name, keywords)
    return {"message": f"Category {req.name.upper()} registered successfully", "categories": system.catalog.names()}


@app.get("/api/admin/strategy")
def get_strategy(user=Depends(get_current_user)):
    return {
        "active_strategy": type(system.service._assignment).__name__,
        "available_strategies": ["SkillBasedAssignment", "LoadBasedAssignment", "RoundRobinAssignment"]
    }


def assignment_strategy(name):
    strategies = {"SKILL": SkillBasedAssignment, "LOAD": LoadBasedAssignment, "ROUND_ROBIN": RoundRobinAssignment}
    try:
        return strategies[name.upper()]()
    except KeyError:
        raise InvalidInput("Choose SKILL, LOAD or ROUND_ROBIN")


@app.post("/api/admin/strategy")
def set_strategy(req: StrategyChangeRequest, user=Depends(require_role([Role.ADMIN]))):
    strategy_obj = assignment_strategy(req.strategy)
    with db.transaction() as conn:
        conn.execute("INSERT OR REPLACE INTO settings VALUES ('strategy', ?)", (req.strategy.upper(),))
        system.service.set_assignment_strategy(strategy_obj)
    return {
        "message": f"Assignment strategy updated to {type(strategy_obj).__name__}",
        "active_strategy": type(strategy_obj).__name__
    }


@app.post("/api/admin/sla-sweep")
def trigger_sla_sweep(user=Depends(require_role([Role.ADMIN]))):
    return sweep_slas(user.id)


def sweep_slas(actor):
    breached = []

    def on_breach(inc, reason):
        result = system.service.escalate(inc.id, reason=reason, actor=actor)
        if result.escalation_tier != inc.escalation_tier:
            breached.append(inc.id)

    emitted = system.sla.sweep(system.incidents.all(), on_escalate=on_breach)
    warnings = [e for e in emitted if e[1] == "SLA_WARNING"]
    violations = [e for e in emitted if e[1] == "SLA_VIOLATED"]
    return {
        "total_warnings": len(warnings),
        "total_violations": len(violations),
        "escalated_incident_ids": breached
    }


# ----------------------------------------------------------------- API Routes: Analytics & Audit
@app.get("/api/analytics/overview")
def get_analytics_overview(user=Depends(get_current_user)):
    if user.role is Role.ADMIN:
        return analytics.overview()
    field = "reporter_id" if user.role is Role.EMPLOYEE else "technician_id"
    return analytics.overview(system.incidents.search_incidents({field: user.id}))


@app.get("/api/analytics/workload")
def get_analytics_workload(user=Depends(require_role([Role.ADMIN, Role.TECHNICIAN]))):
    rows = analytics.technician_workload_report()
    return rows if user.role is Role.ADMIN else [r for r in rows if r["technician_id"] == user.id]


@app.get("/api/analytics/services")
def get_analytics_services(user=Depends(require_role([Role.ADMIN]))):
    return analytics.service_analysis_report()


@app.get("/api/audit")
def get_audit_trail(incident_id: Optional[str] = Query(None), limit: int = Query(50, ge=1, le=200), user=Depends(require_role([Role.ADMIN]))):
    if incident_id:
        return system.audit.history(incident_id)
    return system.audit.recent(limit)


@app.get("/api/notifications")
def get_my_notifications(user=Depends(get_current_user)):
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM notifications WHERE recipient_id = ? ORDER BY created_at DESC LIMIT 30", (user.id,))
        rows = [dict(r) for r in cur.fetchall()]
        return rows


with db.get_connection() as connection:
    for setting in connection.execute("SELECT name, value FROM settings"):
        if setting["name"] == "strategy":
            system.service.set_assignment_strategy(assignment_strategy(setting["value"]))
        elif setting["name"].startswith("category:"):
            system.catalog.register(setting["name"][9:], json.loads(setting["value"]))


# ----------------------------------------------------------------- Single Page Application UI
static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
def serve_spa():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>I-ITSM Platform Running. Static index.html loading...</h1>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
