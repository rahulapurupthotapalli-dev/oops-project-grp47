"""Database seeder: populates comprehensive initial data for development and grading.
Sets up realistic users across all 4 escalation tiers, IT services, categories, and
25+ incidents in diverse lifecycle states.
"""
from datetime import datetime, timedelta
import random
from typing import Optional

from .auth import PasswordHasher
from .enums import EscalationTier, Priority, Role, Status
from .models import Administrator, Employee, ITService, Incident, Technician, DEFAULT_SLA
from .sqlite_repository import (SQLiteDatabase, SQLiteIncidentRepository,
                               SQLiteServiceRepository, SQLiteUserRepository,
                               SQLiteAuditLog, SQLiteNotificationObserver)


def seed_database(db: SQLiteDatabase, force: bool = False):
    """Populates the database with full realistic data if empty or forced."""
    user_repo = SQLiteUserRepository(db)
    service_repo = SQLiteServiceRepository(db)
    incident_repo = SQLiteIncidentRepository(db, user_repo, service_repo)

    if user_repo.count() > 0 and not force:
        return

    # 1. Clean existing records if force
    if force:
        with db.get_connection() as conn:
            conn.executescript("""
            DELETE FROM incident_notes;
            DELETE FROM audit_logs;
            DELETE FROM notifications;
            DELETE FROM incidents;
            DELETE FROM users;
            DELETE FROM services;
            """)

    now = datetime.now()
    default_pw_hash = PasswordHasher.hash_password("password123")

    # 2. Seed IT Services
    services = [
        ITService("Payment Gateway", criticality=5, sla_policy=DEFAULT_SLA, default_category="APPLICATION"),
        ITService("Identity & SSO Service", criticality=5, sla_policy=DEFAULT_SLA, default_category="AUTHENTICATION"),
        ITService("Corporate VPN", criticality=4, sla_policy=DEFAULT_SLA, default_category="NETWORK"),
        ITService("Internal ERP System", criticality=4, sla_policy=DEFAULT_SLA, default_category="DATABASE"),
        ITService("Cloud Compute Cluster", criticality=4, sla_policy=DEFAULT_SLA, default_category="CLOUD"),
        ITService("Customer Web Portal", criticality=4, sla_policy=DEFAULT_SLA, default_category="APPLICATION"),
        ITService("Office Local Area Network", criticality=3, sla_policy=DEFAULT_SLA, default_category="NETWORK"),
        ITService("Email & Collaboration", criticality=3, sla_policy=DEFAULT_SLA, default_category="GENERAL"),
    ]
    for s in services:
        service_repo.save(s)

    # 3. Seed Users
    # 2 Admins
    admins = [
        Administrator("admin1", "Chakradhar Reddy", "chakri.admin@iitsm.internal",
                      admin_title="Chief Information Officer", password_hash=default_pw_hash),
        Administrator("admin2", "Sarah Jenkins", "sarah.admin@iitsm.internal",
                      admin_title="IT Operations Director", password_hash=default_pw_hash),
    ]
    for a in admins:
        user_repo.save(a)

    # 8 Technicians across Tiers 1-4
    technicians = [
        # Tier 1 - Support Engineers
        Technician("tech_t1_1", "Alex Rivera", "alex.t1@iitsm.internal",
                   skills={"NETWORK", "HARDWARE"}, experience_years=2, max_workload=5,
                   escalation_tier=EscalationTier.TIER_1_TECHNICIAN, password_hash=default_pw_hash),
        Technician("tech_t1_2", "Maria Chen", "maria.t1@iitsm.internal",
                   skills={"APPLICATION", "AUTHENTICATION"}, experience_years=3, max_workload=5,
                   escalation_tier=EscalationTier.TIER_1_TECHNICIAN, password_hash=default_pw_hash),
        Technician("tech_t1_3", "Samir Patel", "samir.t1@iitsm.internal",
                   skills={"DATABASE", "STORAGE"}, experience_years=2, max_workload=4,
                   escalation_tier=EscalationTier.TIER_1_TECHNICIAN, password_hash=default_pw_hash),

        # Tier 2 - Team Leads / Senior Specialists
        Technician("tech_t2_1", "David Kim", "david.lead@iitsm.internal",
                   skills={"NETWORK", "CLOUD", "SECURITY"}, experience_years=6, max_workload=6,
                   escalation_tier=EscalationTier.TIER_2_TEAM_LEAD, password_hash=default_pw_hash),
        Technician("tech_t2_2", "Rachel Vance", "rachel.lead@iitsm.internal",
                   skills={"APPLICATION", "DATABASE", "AUTHENTICATION"}, experience_years=7, max_workload=6,
                   escalation_tier=EscalationTier.TIER_2_TEAM_LEAD, password_hash=default_pw_hash),

        # Tier 3 - Systems Architects / Principal Engineers
        Technician("tech_t3_1", "Marcus Brody", "marcus.sysadmin@iitsm.internal",
                   skills={"CLOUD", "STORAGE", "DATABASE", "SECURITY"}, experience_years=10, max_workload=8,
                   escalation_tier=EscalationTier.TIER_3_SYSTEM_ADMIN, password_hash=default_pw_hash),
        Technician("tech_t3_2", "Elena Rostova", "elena.architect@iitsm.internal",
                   skills={"NETWORK", "APPLICATION", "SECURITY"}, experience_years=11, max_workload=8,
                   escalation_tier=EscalationTier.TIER_3_SYSTEM_ADMIN, password_hash=default_pw_hash),

        # Tier 4 - IT Operations Manager
        Technician("tech_t4_1", "Vikramaditya Rao", "vikram.manager@iitsm.internal",
                   skills={"NETWORK", "APPLICATION", "DATABASE", "SECURITY", "CLOUD", "HARDWARE", "STORAGE", "AUTHENTICATION"},
                   experience_years=15, max_workload=10,
                   escalation_tier=EscalationTier.TIER_4_IT_MANAGER, password_hash=default_pw_hash),
    ]
    for t in technicians:
        user_repo.save(t)

    # 5 Employees (Reporters)
    employees = [
        Employee("emp1", "Priya Sharma", "priya.sharma@corp.internal", department="Finance", office_location="Mumbai HQ", password_hash=default_pw_hash),
        Employee("emp2", "James Wilson", "james.wilson@corp.internal", department="Engineering", office_location="Bangalore Tech Park", password_hash=default_pw_hash),
        Employee("emp3", "Ananya Iyer", "ananya.iyer@corp.internal", department="Marketing", office_location="Hyderabad Center", password_hash=default_pw_hash),
        Employee("emp4", "Carlos Mendez", "carlos.mendez@corp.internal", department="Customer Support", office_location="Delhi Hub", password_hash=default_pw_hash),
        Employee("emp5", "Emma Watson", "emma.watson@corp.internal", department="Human Resources", office_location="London Office", password_hash=default_pw_hash),
    ]
    for e in employees:
        user_repo.save(e)

    # 4. Seed 25 Realistic Incidents
    # Template: (id, reporter_idx, desc, service_idx, impact, urgency, affected, age_hours, cat, priority, status, tech_idx, res, feedback)
    raw_incidents = [
        # Resolved/Closed incidents for Historical Resolution Engine
        ("INC1001", 0, "Global VPN gateway timeout during peak morning hours causing connection dropouts",
         2, 4, 4, 150, 48, "NETWORK", Priority.P2, Status.CLOSED, 3,
         "Flushed state tables and updated MTU size to 1420 bytes on edge router gateway. Verified stable ping.",
         "VPN connection restored immediately. Good turnaround time."),
        ("INC1002", 1, "PostgreSQL database connection pool exhaustion in checkout transactions module",
         0, 5, 5, 300, 36, "DATABASE", Priority.P1, Status.CLOSED, 4,
         "Scaled HikariCP connection pool from 50 to 150 and terminated stale client threads holding row locks.",
         "Payment checkout back to normal."),
        ("INC1003", 2, "SSO login failing with HTTP 500 internal server error on identity provider portal",
         1, 5, 4, 250, 30, "AUTHENTICATION", Priority.P1, Status.CLOSED, 1,
         "Rotated expired SAML signing certificate and restarted the Redis authorization session cache.",
         "Seamless single sign-on restored for all branches."),
        ("INC1004", 3, "Cloud compute instance throttling in primary AWS region due to CPU credit exhaustion",
         4, 4, 3, 80, 24, "CLOUD", Priority.P2, Status.RESOLVED, 5,
         "Upgraded instance tier from t3.large to c5.2xlarge and rebalanced load across 3 availability zones.",
         None),
        ("INC1005", 4, "Corporate laptop docking station dual monitors display flickering intermittently",
         6, 2, 2, 1, 20, "HARDWARE", Priority.P4, Status.RESOLVED, 0,
         "Updated DisplayLink driver firmware to v11.4 and replaced worn USB-C connection cable.",
         None),
        ("INC1006", 0, "Storage volume /var/log reached 98% disk capacity on production billing node",
         0, 4, 4, 120, 18, "STORAGE", Priority.P2, Status.CLOSED, 2,
         "Purged rotated logs older than 7 days and reconfigured logrotate retention schedule to daily.",
         "Disk utilization dropped to 42%."),

        # Active Incidents in Various States
        ("INC1007", 1, "Payment gateway checkout throwing 504 gateway timeout for credit card settlements",
         0, 5, 5, 450, 2, "APPLICATION", Priority.P1, Status.IN_PROGRESS, 1,
         None, None),
        ("INC1008", 2, "Corporate VPN rejecting credentials for engineering remote subnet workers",
         2, 4, 4, 65, 4, "NETWORK", Priority.P2, Status.IN_PROGRESS, 3,
         None, None),
        ("INC1009", 3, "Corporate VPN unable to connect from home network with handshake failure",
         2, 3, 3, 20, 3, "NETWORK", Priority.P3, Status.ACKNOWLEDGED, 0,
         None, None),
        ("INC1010", 4, "Customer web portal order history table taking over 12 seconds to load",
         5, 3, 3, 110, 5, "DATABASE", Priority.P3, Status.ASSIGNED, 4,
         None, None),
        ("INC1011", 0, "ERP system inventory synchronization job failed with deadlock exception",
         3, 4, 4, 85, 6, "DATABASE", Priority.P2, Status.IN_PROGRESS, 2,
         None, None),
        ("INC1012", 1, "Office local Wi-Fi access point in 3rd floor cafeteria dropping client associations",
         6, 3, 2, 40, 8, "NETWORK", Priority.P3, Status.ACKNOWLEDGED, 0,
         None, None),
        ("INC1013", 2, "Identity provider 2FA push notifications arriving with 15 minute delay",
         1, 4, 4, 180, 1, "AUTHENTICATION", Priority.P2, Status.ASSIGNED, 1,
         None, None),
        ("INC1014", 3, "Email server quarantined legitimate vendor invoices as suspected phishing",
         7, 3, 3, 15, 12, "SECURITY", Priority.P3, Status.RESOLVED, 5,
         "Whitelisted vendor domain sender IP and updated SPF/DKIM verification rule in spam filter.",
         None),
        ("INC1015", 4, "Finance department printer paper feeder jammed and display board unresponsive",
         6, 1, 2, 8, 14, "HARDWARE", Priority.P4, Status.ASSIGNED, 0,
         None, None),

        # Incidents near or breaching SLA to demonstrate SLA sweeps and Escalation
        ("INC1016", 0, "CRITICAL: Database primary node failover failed, standby out of sync",
         3, 5, 5, 500, 5, "DATABASE", Priority.P1, Status.IN_PROGRESS, 5,
         None, None),
        ("INC1017", 1, "Customer web portal payment webhook endpoint returning HTTP 500 errors",
         5, 5, 4, 220, 3, "APPLICATION", Priority.P1, Status.ACKNOWLEDGED, 4,
         None, None),
        ("INC1018", 2, "Office fiber optic trunk line packet loss exceeding 40 percent",
         6, 4, 4, 300, 7, "NETWORK", Priority.P2, Status.IN_PROGRESS, 6,
         None, None),
        ("INC1019", 3, "Cloud compute worker nodes failing Kubernetes liveness probes repeatedly",
         4, 4, 4, 150, 4, "CLOUD", Priority.P2, Status.ASSIGNED, 3,
         None, None),
        ("INC1020", 4, "Employee self-service password reset portal unreachable from mobile devices",
         1, 3, 3, 90, 9, "AUTHENTICATION", Priority.P3, Status.ACKNOWLEDGED, 1,
         None, None),

        # Fresh Incidents (NEW / CLASSIFIED)
        ("INC1021", 0, "Scheduled payroll batch export report hanging on calculation phase",
         3, 4, 3, 15, 0.5, "APPLICATION", Priority.P2, Status.CLASSIFIED, None,
         None, None),
        ("INC1022", 1, "Conference room A video codec HDMI input no audio transmission",
         6, 2, 2, 6, 0.2, "HARDWARE", Priority.P4, Status.NEW, None,
         None, None),
        ("INC1023", 2, "Payment gateway recurring subscription billing webhook signature mismatch",
         0, 5, 4, 95, 0.8, "APPLICATION", Priority.P1, Status.CLASSIFIED, None,
         None, None),
        ("INC1024", 3, "AWS S3 file attachment uploads timing out with SignatureDoesNotMatch",
         4, 3, 3, 35, 1.2, "CLOUD", Priority.P3, Status.ASSIGNED, 5,
         None, None),
        ("INC1025", 4, "Suspicious phishing email campaign targeting customer service representatives",
         7, 5, 5, 50, 0.4, "SECURITY", Priority.P1, Status.IN_PROGRESS, 6,
         None, None)
    ]

    for item in raw_incidents:
        inc_id, rep_idx, desc, srv_idx, impact, urgency, affected, age_h, cat, prio, status, tech_idx, res, fb = item
        created_time = now - timedelta(hours=age_h)
        reporter = employees[rep_idx]
        service = services[srv_idx]

        inc = Incident(
            incident_id=inc_id,
            reporter=reporter,
            description=desc,
            service=service,
            impact=impact,
            urgency=urgency,
            affected_users=affected,
            created_at=created_time,
            category=cat
        )
        inc.priority = prio

        # SLA deadlines
        resp_delta, res_delta = DEFAULT_SLA.targets_for(prio)
        inc.response_due = created_time + resp_delta
        inc.resolution_due = created_time + res_delta

        # Status and assignment
        if tech_idx is not None:
            tech = technicians[tech_idx]
            inc.assigned_to = tech
            if status not in (Status.RESOLVED, Status.CLOSED):
                try:
                    tech.take(inc.id)
                except Exception:
                    pass

        if status in (Status.ACKNOWLEDGED, Status.IN_PROGRESS, Status.RESOLVED, Status.VERIFIED, Status.CLOSED):
            inc.acknowledged_at = created_time + timedelta(minutes=random.randint(2, 10))

        if status in (Status.RESOLVED, Status.VERIFIED, Status.CLOSED):
            inc.resolution = res
            inc.resolved_at = created_time + timedelta(minutes=random.randint(15, 60))

        if status in (Status.VERIFIED, Status.CLOSED):
            inc.feedback = fb

        if status == Status.CLOSED:
            inc.closed_at = (inc.resolved_at or created_time) + timedelta(minutes=15)

        # SLA Warnings and Violations check
        if status not in (Status.RESOLVED, Status.VERIFIED, Status.CLOSED):
            if now > inc.resolution_due:
                inc.violations.add("RESOLUTION")
            elif now > inc.created_at + (res_delta * 0.8):
                inc.warnings.add("RESOLUTION")

            if not inc.acknowledged_at and now > inc.response_due:
                inc.violations.add("RESPONSE")

        # Escalation tier setting
        if "RESOLUTION" in inc.violations or prio == Priority.P1:
            inc.escalation_tier = EscalationTier.TIER_2_TEAM_LEAD

        # Transition state object
        from .states import STATE_FOR
        inc._state = STATE_FOR[status]()

        # Add sample investigation note if in progress or resolved
        if status in (Status.IN_PROGRESS, Status.RESOLVED, Status.CLOSED) and inc.assigned_to:
            inc.notes.append((created_time + timedelta(minutes=12), inc.assigned_to.id,
                              f"Initial triage performed by {inc.assigned_to.name}. Telemetry logs inspected."))

        incident_repo.save(inc)

    # 5. Populate initial audit logs and notifications
    from .events import Event
    audit_log = SQLiteAuditLog(db)
    for inc in incident_repo.all()[:10]:
        audit_log.update(
            Event(
                type="INCIDENT_CREATED",
                incident_id=inc.id,
                actor=inc.reporter.id,
                description=f"Incident created: {inc.description[:50]}...",
                at=inc.created_at,
                old_state=None,
                new_state="NEW",
                recipients=(inc.reporter.id,)
            )
        )
        if inc.assigned_to:
            audit_log.update(
                Event(
                    type="INCIDENT_ASSIGNED",
                    incident_id=inc.id,
                    actor="SYSTEM",
                    description=f"Auto-assigned to {inc.assigned_to.name} [{inc.assigned_to.id}]",
                    at=inc.created_at + timedelta(minutes=1),
                    old_state="CLASSIFIED",
                    new_state="ASSIGNED",
                    recipients=(inc.reporter.id, inc.assigned_to.id)
                )
            )
