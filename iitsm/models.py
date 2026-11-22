"""Domain model: users (inheritance + polymorphism), services, SLA policy, incident."""
from abc import ABC, abstractmethod
from datetime import datetime, timedelta

from .enums import EscalationTier, Priority, Role, Status
from .exceptions import (InvalidInput, MissingSLAConfiguration, TechnicianUnavailable,
                         WorkloadExceeded)
from .states import IncidentState, NewState


# ----------------------------------------------------------------- users
class User(ABC):
    role: Role

    def __init__(self, user_id: str, name: str, email: str, password_hash: str = None):
        if not user_id.strip() or not name.strip() or "@" not in email:
            raise InvalidInput("user needs an id, a name and a valid email")
        self._id, self._name, self._email = user_id, name, email
        self.password_hash = password_hash or ""

    id = property(lambda self: self._id)
    name = property(lambda self: self._name)
    email = property(lambda self: self._email)

    @abstractmethod
    def can(self, action: str) -> bool:
        """Role-based authorization: each subclass defines its own permissions."""

    def __repr__(self): return f"{type(self).__name__}({self._id})"


class Employee(User):
    role = Role.EMPLOYEE
    _ALLOWED = frozenset({"incident:create", "incident:view", "incident:feedback", "incident:verify"})

    def __init__(self, user_id: str, name: str, email: str, department: str = "General",
                 office_location: str = "HQ", password_hash: str = None):
        super().__init__(user_id, name, email, password_hash)
        self.department = department
        self.office_location = office_location

    def can(self, action): return action in self._ALLOWED


class Technician(User):
    role = Role.TECHNICIAN
    _ALLOWED = frozenset({"incident:view", "incident:acknowledge", "incident:investigate", "incident:resolve"})

    def __init__(self, user_id, name, email, skills, experience_years=1, max_workload=5,
                 available=True, escalation_tier=EscalationTier.TIER_1_TECHNICIAN, password_hash=None):
        super().__init__(user_id, name, email, password_hash)
        self._skills = frozenset(s.upper() for s in skills)
        self.experience_years, self.max_workload, self.available = experience_years, max_workload, available
        self.escalation_tier = escalation_tier if isinstance(escalation_tier, EscalationTier) else EscalationTier(escalation_tier)
        self._active: set = set()
        self.total_resolved: int = 0

    skills = property(lambda self: self._skills)
    workload = property(lambda self: len(self._active))

    def can(self, action): return action in self._ALLOWED
    def has_capacity(self): return self.available and self.workload < self.max_workload

    def take(self, incident_id: str):
        if not self.available:
            raise TechnicianUnavailable(f"{self.id} is not available")
        if incident_id not in self._active and self.workload >= self.max_workload:
            raise WorkloadExceeded(f"{self.id} already has {self.workload} active incidents")
        self._active.add(incident_id)

    def release(self, incident_id: str):
        self._active.discard(incident_id)

    def record_resolution(self, incident_id: str):
        self.release(incident_id)
        self.total_resolved += 1


class Administrator(User):
    role = Role.ADMIN

    def __init__(self, user_id: str, name: str, email: str, admin_title: str = "IT Systems Administrator",
                 password_hash: str = None):
        super().__init__(user_id, name, email, password_hash)
        self.admin_title = admin_title

    def can(self, action): return True


# ------------------------------------------------------- service and SLA
class SLAPolicy:
    """Maps every priority to (response target, resolution target)."""

    def __init__(self, targets: dict):
        missing = set(Priority) - set(targets)
        if missing:
            raise MissingSLAConfiguration(f"SLA policy lacks targets for {sorted(p.name for p in missing)}")
        self._targets = dict(targets)

    def targets_for(self, priority: Priority):
        return self._targets[priority]


m, h = (lambda x: timedelta(minutes=x)), (lambda x: timedelta(hours=x))
DEFAULT_SLA = SLAPolicy({Priority.P1: (m(5), m(30)), Priority.P2: (m(15), h(2)),
                         Priority.P3: (h(1), h(8)), Priority.P4: (h(4), h(24))})


class ITService:
    def __init__(self, name: str, criticality: int, sla_policy: SLAPolicy = None, default_category: str = "APPLICATION"):
        if not name.strip() or not 1 <= criticality <= 5:
            raise InvalidInput("service needs a name and business criticality 1-5")
        self.name, self.criticality, self.sla_policy = name, criticality, sla_policy
        self.default_category = default_category

    id = property(lambda self: self.name)


# -------------------------------------------------------------- incident
class Incident:
    def __init__(self, incident_id, reporter, description, service, impact, urgency,
                 affected_users, created_at: datetime, category: str = None):
        self.id, self.reporter, self.description, self.service = incident_id, reporter, description, service
        self.impact, self.urgency, self.affected_users = impact, urgency, affected_users
        self.created_at, self.category = created_at, category
        self.priority: Priority = None
        self.assigned_to: Technician = None
        self.escalation_tier: EscalationTier = EscalationTier.TIER_1_TECHNICIAN
        self.response_due = self.resolution_due = None
        self.acknowledged_at = self.resolved_at = self.closed_at = None
        self.notes: list = []
        self.resolution = self.feedback = None
        self.related: list = []
        self.warnings: set = set()
        self.violations: set = set()
        self._state: IncidentState = NewState()

    status = property(lambda self: self._state.status)

    def move_to(self, target: Status):
        """Delegates to the current State object; illegal moves raise InvalidStateTransition."""
        old = self.status
        self._state = self._state.next(target)
        return old, self.status

