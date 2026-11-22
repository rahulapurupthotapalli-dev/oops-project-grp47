"""OBSERVER pattern (event bus, audit log, notifications) + ADAPTER-style notifier interface."""
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Event:
    type: str
    incident_id: str
    actor: str
    description: str
    at: datetime
    old_state: str = None
    new_state: str = None
    recipients: tuple = ()


class Observer(ABC):
    @abstractmethod
    def update(self, event: Event) -> None: ...


class EventBus:
    def __init__(self):
        self._observers: list = []
        self.failures: list = []

    def subscribe(self, observer: Observer, *, required=False):
        self._observers.append((observer, required))

    def publish(self, event: Event):
        for obs, required in self._observers:
            try:
                obs.update(event)
            except Exception as exc:  # one broken observer must never break the workflow
                if required:
                    raise
                self.failures.append((obs, exc))


class AuditLog(Observer):
    """Append-only history of every important action."""
    def __init__(self): self._records: list = []
    def update(self, event): self._records.append(event)
    records = property(lambda self: tuple(self._records))
    def history(self, incident_id): return tuple(e for e in self._records if e.incident_id == incident_id)


class Notifier(ABC):
    """Contract for a delivery channel. A new channel (SMS, push) = one new subclass."""
    @abstractmethod
    def send(self, recipient_id: str, subject: str, body: str) -> None: ...


class InAppNotifier(Notifier):
    def __init__(self): self.inbox = defaultdict(list)
    def send(self, recipient_id, subject, body): self.inbox[recipient_id].append((subject, body))


class EmailNotifier(Notifier):
    """Simulated email; swap the body of send() for real SMTP without touching anything else."""
    def __init__(self): self.outbox: list = []
    def send(self, recipient_id, subject, body): self.outbox.append({"to": recipient_id, "subject": subject, "body": body})


class NotificationObserver(Observer):
    NOTIFY = {"INCIDENT_CREATED", "INCIDENT_ASSIGNED", "PRIORITY_CALCULATED", "SLA_WARNING",
              "SLA_VIOLATED", "INCIDENT_RESOLVED", "INCIDENT_CLOSED", "ASSIGNMENT_FAILED"}

    def __init__(self, notifiers): self._notifiers = list(notifiers)

    def update(self, event):
        if event.type not in self.NOTIFY:
            return
        for rid in event.recipients:
            for n in self._notifiers:
                n.send(rid, f"[{event.incident_id}] {event.type}", event.description)
