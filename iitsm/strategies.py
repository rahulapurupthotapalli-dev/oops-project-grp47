"""STRATEGY pattern: interchangeable priority and technician-assignment algorithms."""
from abc import ABC, abstractmethod

from .enums import Priority
from .exceptions import TechnicianUnavailable


class PriorityStrategy(ABC):
    @abstractmethod
    def calculate(self, incident) -> Priority: ...


class WeightedScorePriority(PriorityStrategy):
    """score = impact x urgency x business criticality (each 1-5), x1.25 if many users are affected."""
    def __init__(self, p1=60, p2=30, p3=10, crowd_threshold=50, crowd_multiplier=1.25):
        self.p1, self.p2, self.p3 = p1, p2, p3
        self.crowd_threshold, self.crowd_multiplier = crowd_threshold, crowd_multiplier

    def score(self, inc) -> float:
        s = inc.impact * inc.urgency * inc.service.criticality
        return s * self.crowd_multiplier if inc.affected_users >= self.crowd_threshold else s

    def calculate(self, inc) -> Priority:
        s = self.score(inc)
        if s >= self.p1: return Priority.P1
        if s >= self.p2: return Priority.P2
        if s >= self.p3: return Priority.P3
        return Priority.P4


class AssignmentStrategy(ABC):
    @abstractmethod
    def select(self, incident, technicians): ...

    @staticmethod
    def _available(technicians):
        pool = [t for t in technicians if t.has_capacity()]
        if not pool:
            raise TechnicianUnavailable("no technician is available with spare capacity")
        return pool


class SkillBasedAssignment(AssignmentStrategy):
    """Only technicians skilled in the incident category; most experienced, then least loaded."""
    key = "SKILL_BASED"

    def select(self, incident, technicians):
        skilled = [t for t in self._available(technicians) if incident.category in t.skills]
        if not skilled:
            raise TechnicianUnavailable(f"no available technician has skill {incident.category}")
        return max(skilled, key=lambda t: (t.experience_years, -t.workload))


class LoadBasedAssignment(AssignmentStrategy):
    """Least-loaded available technician, regardless of skill."""
    key = "LOAD_BASED"

    def select(self, incident, technicians):
        return min(self._available(technicians), key=lambda t: t.workload)


class RoundRobinAssignment(AssignmentStrategy):
    """Rotates assignment cyclically across all available technicians."""
    key = "ROUND_ROBIN"

    def __init__(self):
        self._cursor = 0

    def select(self, incident, technicians):
        pool = sorted(self._available(technicians), key=lambda t: t.id)
        chosen = pool[self._cursor % len(pool)]
        self._cursor += 1
        return chosen

