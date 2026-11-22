from enum import Enum, IntEnum


class Role(Enum):
    EMPLOYEE = "EMPLOYEE"
    TECHNICIAN = "TECHNICIAN"
    ADMIN = "ADMIN"


class Priority(IntEnum):
    P1 = 1  # Critical
    P2 = 2  # High
    P3 = 3  # Medium
    P4 = 4  # Low


class Status(Enum):
    NEW = "NEW"
    CLASSIFIED = "CLASSIFIED"
    ASSIGNED = "ASSIGNED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    VERIFIED = "VERIFIED"
    CLOSED = "CLOSED"


class SLAStatus(Enum):
    ON_TRACK = "ON_TRACK"
    AT_RISK = "AT_RISK"
    VIOLATED = "VIOLATED"
    MET = "MET"


class EscalationTier(IntEnum):
    TIER_1_TECHNICIAN = 1
    TIER_2_TEAM_LEAD = 2
    TIER_3_SYSTEM_ADMIN = 3
    TIER_4_IT_MANAGER = 4

    @property
    def title(self) -> str:
        titles = {
            1: "Tier 1: Support Technician",
            2: "Tier 2: Technical Team Lead",
            3: "Tier 3: Systems Administrator",
            4: "Tier 4: IT Operations Manager"
        }
        return titles[self.value]

    def next_tier(self) -> "EscalationTier":
        if self.value < 4:
            return EscalationTier(self.value + 1)
        return self

