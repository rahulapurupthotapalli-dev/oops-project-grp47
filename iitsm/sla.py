from datetime import datetime
from contextlib import nullcontext

from .enums import SLAStatus, Status
from .events import Event
from .exceptions import MissingSLAConfiguration


class SLAMonitor:
    def __init__(self, bus, warn_ratio: float = 0.8, repository=None):
        self._bus, self._warn = bus, warn_ratio
        self._repository = repository

    def apply(self, inc):
        policy = inc.service.sla_policy
        if policy is None:
            raise MissingSLAConfiguration(f"service {inc.service.name} has no SLA policy")
        response, resolution = policy.targets_for(inc.priority)
        inc.response_due, inc.resolution_due = inc.created_at + response, inc.created_at + resolution

    def _status(self, start, due, reached, now) -> SLAStatus:
        if reached is not None:
            return SLAStatus.MET if reached <= due else SLAStatus.VIOLATED
        ratio = (now - start) / (due - start)
        return SLAStatus.VIOLATED if ratio >= 1 else SLAStatus.AT_RISK if ratio >= self._warn else SLAStatus.ON_TRACK

    def evaluate(self, inc, now: datetime) -> dict:
        return {"RESPONSE": self._status(inc.created_at, inc.response_due, inc.acknowledged_at, now),
                "RESOLUTION": self._status(inc.created_at, inc.resolution_due, inc.resolved_at, now)}

    def sweep(self, incidents, now: datetime = None, escalation_callback=None, on_escalate=None) -> list:
        """Run periodically (background thread/scheduler). Emits each warning/violation once."""
        if now is None:
            now = datetime.now()
        cb = on_escalate or escalation_callback
        emitted = []
        for snapshot in incidents:
            repo = self._repository
            with repo.transaction() if repo else nullcontext():
                inc = repo.get(snapshot.id) if repo else snapshot
                if inc.status is Status.NEW or not inc.response_due or not inc.resolution_due:
                    continue
                new_breaches = []
                changes = []
                for kind, state in self.evaluate(inc, now).items():
                    if state is SLAStatus.VIOLATED and kind not in inc.violations:
                        inc.violations.add(kind)
                        new_breaches.append(kind)
                        event_type = "SLA_VIOLATED"
                    elif state is SLAStatus.AT_RISK and kind not in inc.warnings:
                        inc.warnings.add(kind)
                        event_type = "SLA_WARNING"
                    else:
                        continue
                    changes.append((inc.id, event_type, kind))
                if changes and repo:
                    repo.save(inc)
                recipients = {inc.reporter.id}
                if inc.assigned_to:
                    recipients.add(inc.assigned_to.id)
                for _, event_type, kind in changes:
                    self._bus.publish(Event(event_type, inc.id, "SYSTEM", f"{kind} {event_type}", now,
                                            recipients=tuple(sorted(recipients))))
                emitted.extend(changes)
                if new_breaches and cb and inc.resolved_at is None:
                    cb(inc, " and ".join(new_breaches) + " SLA violation")
        return emitted


def incident_sla_status(inc, now):
    if not inc.response_due or not inc.resolution_due:
        return "UNCONFIGURED"
    states = SLAMonitor(None).evaluate(inc, now).values()
    if inc.violations or SLAStatus.VIOLATED in states:
        return "VIOLATED"
    if SLAStatus.AT_RISK in states:
        return "AT_RISK"
    return "MET" if all(s is SLAStatus.MET for s in states) else "ON_TRACK"
