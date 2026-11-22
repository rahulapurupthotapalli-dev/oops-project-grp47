"""STATE pattern: each lifecycle stage is an object that knows its legal successors."""
from abc import ABC, abstractmethod

from .enums import Status
from .exceptions import InvalidStateTransition


class IncidentState(ABC):
    status: Status

    @abstractmethod
    def allowed(self) -> frozenset: ...

    def next(self, target: Status) -> "IncidentState":
        if target not in self.allowed():
            raise InvalidStateTransition(f"{self.status.name} -> {target.name} is not allowed")
        return STATE_FOR[target]()


class NewState(IncidentState):
    status = Status.NEW
    def allowed(self): return frozenset({Status.CLASSIFIED})

class ClassifiedState(IncidentState):
    status = Status.CLASSIFIED
    def allowed(self): return frozenset({Status.ASSIGNED})

class AssignedState(IncidentState):
    status = Status.ASSIGNED
    def allowed(self): return frozenset({Status.ACKNOWLEDGED, Status.ASSIGNED})  # ASSIGNED->ASSIGNED = reassignment

class AcknowledgedState(IncidentState):
    status = Status.ACKNOWLEDGED
    def allowed(self): return frozenset({Status.IN_PROGRESS})

class InProgressState(IncidentState):
    status = Status.IN_PROGRESS
    def allowed(self): return frozenset({Status.RESOLVED})

class ResolvedState(IncidentState):
    status = Status.RESOLVED
    def allowed(self): return frozenset({Status.VERIFIED, Status.IN_PROGRESS})  # reopen if fix rejected

class VerifiedState(IncidentState):
    status = Status.VERIFIED
    def allowed(self): return frozenset({Status.CLOSED})

class ClosedState(IncidentState):
    status = Status.CLOSED
    def allowed(self): return frozenset()


STATE_FOR = {s.status: s for s in (NewState, ClassifiedState, AssignedState, AcknowledgedState,
                                   InProgressState, ResolvedState, VerifiedState, ClosedState)}
