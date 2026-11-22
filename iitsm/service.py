"""Application service: orchestrates the whole incident lifecycle. All collaborators are injected
(composition + dependency inversion), so strategies can be swapped at runtime."""
from datetime import datetime
from functools import wraps
from contextlib import nullcontext

from .enums import Role, Status
from .events import Event
from .exceptions import (DuplicateIncident, InvalidInput, InvalidStateTransition, ITSMError, TechnicianUnavailable,
                         UnauthorizedOperation, WorkloadExceeded)
from .models import Incident, Technician


def atomic(method):
    @wraps(method)
    def wrapped(self, *args, **kwargs):
        with self._transaction():
            return method(self, *args, **kwargs)
    return wrapped


class IncidentFactory:
    """FACTORY pattern: validation + ID generation in one place."""
    def __init__(self, next_id=None):
        self._next_id = next_id
        self._seq = 1000

    def create(self, reporter, description, service, impact, urgency, affected_users, created_at):
        if not description or not description.strip():
            raise InvalidInput("description is required")
        if not (1 <= impact <= 5 and 1 <= urgency <= 5):
            raise InvalidInput("impact and urgency must be between 1 and 5")
        if affected_users < 1:
            raise InvalidInput("affected_users must be at least 1")
        self._seq = self._next_id() if self._next_id else self._seq + 1
        return Incident(f"INC{self._seq}", reporter, description.strip(), service, impact, urgency,
                        affected_users, created_at)


class IncidentService:
    def __init__(self, incidents, users, services, bus, priority, assignment, catalog,
                 duplicates, sla, clock=datetime.now):
        self._incidents, self._users, self._services, self._bus = incidents, users, services, bus
        self._priority, self._assignment, self._catalog = priority, assignment, catalog
        self._duplicates, self._sla, self._clock = duplicates, sla, clock
        self._transaction = getattr(incidents, "transaction", nullcontext)
        self._factory = IncidentFactory(getattr(incidents, "next_id", None))

    def set_assignment_strategy(self, strategy): self._assignment = strategy
    def set_priority_strategy(self, strategy): self._priority = strategy

    # ---- helpers
    def _user(self, uid, action):
        user = self._users.get(uid)
        if not user.can(action):
            raise UnauthorizedOperation(f"{user.role.value} {uid} may not perform {action}")
        return user

    def _emit(self, etype, inc, actor, desc, old=None, new=None):
        rec = {inc.reporter.id} | ({inc.assigned_to.id} if inc.assigned_to else set())
        self._bus.publish(Event(etype, inc.id, actor, desc, self._clock(),
                                old.name if old else None, new.name if new else None, tuple(sorted(rec))))

    def _move(self, inc, target, actor, etype, desc):
        old, new = inc.move_to(target)
        self._incidents.save(inc)
        self._emit(etype, inc, actor, desc, old, new)

    def _my_incident(self, tech_id, inc_id, action):
        tech, inc = self._user(tech_id, action), self._incidents.get(inc_id)
        if not inc.assigned_to or inc.assigned_to.id != tech.id:
            raise UnauthorizedOperation(f"{inc_id} is not assigned to {tech_id}")
        return tech, inc

    # ---- workflow
    @atomic
    def report(self, reporter_id, description, service_name, impact, urgency,
               affected_users=1, category=None) -> Incident:
        reporter = self._user(reporter_id, "incident:create")
        service = self._services.get(service_name)
        open_same = [i for i in self._incidents.all() if (i.service.name if i.service else None) == service.name and i.status is not Status.CLOSED]
        related = self._duplicates.find(description, open_same)
        for other, score in related:
            if score >= 0.99 and other.reporter.id == reporter.id:
                raise DuplicateIncident(f"you already reported this as {other.id}")

        inc = self._factory.create(reporter, description, service, impact, urgency, affected_users, self._clock())
        inc.category = self._catalog.require(category) if category else self._catalog.suggest(description)
        inc.priority = self._priority.calculate(inc)
        self._sla.apply(inc)
        inc.related = [o.id for o, _ in related]
        self._incidents.save(inc)
        self._emit("INCIDENT_CREATED", inc, reporter.id, f"{inc.id} created by {reporter.id}")
        if inc.related:
            self._emit("DUPLICATE_SUSPECTED", inc, "SYSTEM", f"{inc.id} may be related to {', '.join(inc.related)}")

        self._move(inc, Status.CLASSIFIED, "SYSTEM", "INCIDENT_CLASSIFIED", f"Classified as {inc.category}")
        self._emit("PRIORITY_CALCULATED", inc, "SYSTEM", f"Priority calculated as {inc.priority.name}")
        try:
            inc = self.assign(inc.id)
        except (TechnicianUnavailable, WorkloadExceeded) as exc:
            self._emit("ASSIGNMENT_FAILED", inc, "SYSTEM", f"Auto-assignment failed: {exc}")
        return inc

    @atomic
    def assign(self, incident_id, actor="SYSTEM", technician_id=None, strategy=None) -> Incident:
        inc = self._incidents.get(incident_id)
        if inc.status not in (Status.CLASSIFIED, Status.ASSIGNED, Status.ACKNOWLEDGED, Status.IN_PROGRESS):
            raise InvalidStateTransition("Only active, classified incidents can be assigned")
        techs = [u for u in self._users.all() if isinstance(u, Technician)]
        strategy = strategy or self._assignment
        tech = self._users.get(technician_id) if technician_id else strategy.select(inc, techs)
        if not isinstance(tech, Technician):
            raise InvalidInput("Assignee must be a technician")
        previous = inc.assigned_to
        tech.take(inc.id)
        inc.assigned_to = tech
        target = Status.ASSIGNED if inc.status is Status.CLASSIFIED else inc.status
        description = f"Assigned to {tech.id}"
        if not technician_id:
            description += f" using {type(strategy).__name__}"
        if inc.status in (Status.CLASSIFIED, Status.ASSIGNED):
            self._move(inc, target, actor, "INCIDENT_ASSIGNED", description)
        else:
            self._incidents.save(inc)
            self._emit("INCIDENT_ASSIGNED", inc, actor, description, target, target)
        if previous is not None and previous.id != tech.id:
            previous.release(inc.id)
        return inc

    @atomic
    def acknowledge(self, tech_id, inc_id, note=None):
        _, inc = self._my_incident(tech_id, inc_id, "incident:acknowledge")
        if inc.status is not Status.ASSIGNED:
            raise InvalidStateTransition("Only assigned incidents can be acknowledged")
        inc.acknowledged_at = self._clock()
        self._move(inc, Status.ACKNOWLEDGED, tech_id, "INCIDENT_ACKNOWLEDGED", f"{tech_id} acknowledged {inc_id}")
        return self.add_note(tech_id, inc_id, note) if note else inc

    @atomic
    def start_investigation(self, tech_id, inc_id):
        _, inc = self._my_incident(tech_id, inc_id, "incident:investigate")
        if inc.status is Status.RESOLVED:
            inc.assigned_to.take(inc.id)
            inc.resolved_at = None
            inc.resolution = None
            inc.feedback = None
        self._move(inc, Status.IN_PROGRESS, tech_id, "INVESTIGATION_STARTED", "Investigation started")
        return inc

    @atomic
    def add_note(self, tech_id, inc_id, note):
        inc = self._incidents.get(inc_id)
        if inc.reporter.id != tech_id:
            self._my_incident(tech_id, inc_id, "incident:investigate")
        if inc.status is Status.CLOSED:
            raise InvalidStateTransition("Closed incidents cannot receive notes")
        if not note or not note.strip():
            raise InvalidInput("Note cannot be blank")
        note = note.strip()
        inc.notes.append((self._clock(), tech_id, note))
        self._incidents.save(inc)
        self._emit("NOTE_ADDED", inc, tech_id, note)
        return inc

    @atomic
    def resolve(self, tech_id, inc_id, resolution):
        tech, inc = self._my_incident(tech_id, inc_id, "incident:resolve")
        if not resolution or not resolution.strip():
            raise InvalidInput("resolution details are required")
        if inc.status is not Status.IN_PROGRESS:
            raise InvalidStateTransition("Start investigating before resolving an incident")
        inc.resolution, inc.resolved_at = resolution.strip(), self._clock()
        self._move(inc, Status.RESOLVED, tech_id, "INCIDENT_RESOLVED", f"Resolved: {inc.resolution}")
        tech.record_resolution(inc.id)
        self._users.save(tech)
        return inc

    @atomic
    def verify(self, user_id, inc_id, feedback=None):
        user, inc = self._user(user_id, "incident:verify"), self._incidents.get(inc_id)
        if user.role is Role.EMPLOYEE and inc.reporter.id != user.id:
            raise UnauthorizedOperation("only the reporter can verify this incident")
        if inc.status is not Status.RESOLVED:
            raise InvalidStateTransition("Only resolved incidents can be verified")
        inc.feedback = feedback
        self._move(inc, Status.VERIFIED, user_id, "INCIDENT_VERIFIED", "Resolution verified")
        return inc

    @atomic
    def close(self, user_id, inc_id):
        self._user(user_id, "incident:close")
        inc = self._incidents.get(inc_id)
        if inc.status is not Status.VERIFIED:
            raise InvalidStateTransition("Only verified incidents can be closed")
        inc.closed_at = self._clock()
        self._move(inc, Status.CLOSED, user_id, "INCIDENT_CLOSED", "Incident closed")
        return inc

    @atomic
    def escalate(self, incident_id, reason="Automatic escalation triggered", actor="SYSTEM") -> Incident:
        inc = self._incidents.get(incident_id)
        if inc.status in (Status.RESOLVED, Status.VERIFIED, Status.CLOSED):
            return inc
        current_tier = inc.escalation_tier
        next_tier = current_tier.next_tier()
        if next_tier == current_tier:
            return inc
        inc.escalation_tier = next_tier

        # Try to find available technician with tier >= next_tier
        techs = [u for u in self._users.all() if isinstance(u, Technician) and u.has_capacity()]
        tier_matched = [t for t in techs if t.escalation_tier >= next_tier]
        target_pool = tier_matched

        desc = f"Escalated from {current_tier.title} to {next_tier.title}: {reason}"
        if target_pool and (not inc.assigned_to or inc.assigned_to.escalation_tier < next_tier):
            chosen = min(target_pool, key=lambda t: (t.workload / t.max_workload, -t.experience_years))
            previous = inc.assigned_to
            chosen.take(inc.id)
            inc.assigned_to = chosen
            if inc.status is Status.CLASSIFIED:
                inc.move_to(Status.ASSIGNED)
            if previous and previous.id != chosen.id:
                previous.release(inc.id)
            desc += f" (Reassigned to {chosen.name} [{chosen.id}])"

        self._incidents.save(inc)
        self._emit("INCIDENT_ESCALATED", inc, actor, desc)
        return inc

    def recommend_technicians(self, incident_id) -> list:
        inc = self._incidents.get(incident_id)
        techs = [u for u in self._users.all() if isinstance(u, Technician) and u.available]
        recommendations = []
        for t in techs:
            skill_matched = inc.category in t.skills
            skill_score = 1.0 if skill_matched else 0.20
            cap_score = 1.0 - (t.workload / t.max_workload) if t.max_workload > 0 else 0.0
            exp_score = min(1.0, t.experience_years / 10.0)
            hist_score = min(1.0, getattr(t, "total_resolved", 0) / 15.0)

            composite = (0.40 * skill_score) + (0.30 * cap_score) + (0.20 * exp_score) + (0.10 * hist_score)
            score_100 = round(composite * 100, 1)

            recommendations.append({
                "technician_id": t.id,
                "name": t.name,
                "skills": sorted(t.skills),
                "experience_years": t.experience_years,
                "tier": t.escalation_tier.title if hasattr(t, "escalation_tier") else "Technician",
                "current_workload": t.workload,
                "max_workload": t.max_workload,
                "skill_matched": skill_matched,
                "composite_score": score_100,
                "has_capacity": t.has_capacity()
            })
        return sorted(recommendations, key=lambda r: -r["composite_score"])

