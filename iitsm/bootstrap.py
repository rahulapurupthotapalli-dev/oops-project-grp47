"""Composition root: wires every collaborator together in one place."""
from dataclasses import dataclass
from datetime import datetime

from .events import AuditLog, EmailNotifier, EventBus, InAppNotifier, NotificationObserver
from .exceptions import IncidentNotFound, ServiceNotFound, UserNotFound
from .intelligence import CategoryCatalog, DuplicateDetector
from .repository import InMemoryRepository
from .service import IncidentService
from .sla import SLAMonitor
from .strategies import SkillBasedAssignment, WeightedScorePriority


@dataclass
class System:
    service: IncidentService
    users: any
    services: any
    incidents: any
    bus: EventBus
    audit: any
    inapp: any
    email: any
    sla: SLAMonitor
    catalog: CategoryCatalog
    auth: any = None
    analytics: any = None
    ai: any = None


def build_system(clock=datetime.now) -> System:
    users, services = InMemoryRepository(UserNotFound), InMemoryRepository(ServiceNotFound)
    incidents = InMemoryRepository(IncidentNotFound)
    bus, audit, inapp, email = EventBus(), AuditLog(), InAppNotifier(), EmailNotifier()
    bus.subscribe(audit)
    bus.subscribe(NotificationObserver([inapp, email]))
    sla, catalog = SLAMonitor(bus), CategoryCatalog()
    svc = IncidentService(incidents, users, services, bus, WeightedScorePriority(),
                          SkillBasedAssignment(), catalog, DuplicateDetector(), sla, clock)
    return System(svc, users, services, incidents, bus, audit, inapp, email, sla, catalog)


def build_sqlite_system(db_path: str = "iitsm.db", clock=datetime.now) -> System:
    from .ai_assistant import AIAssistant, HistoricalResolutionMatcher
    from .analytics import DashboardAnalytics
    from .auth import AuthService
    from .sqlite_repository import (SQLiteAuditLog, SQLiteDatabase,
                                   SQLiteIncidentRepository, SQLiteNotificationObserver,
                                   SQLiteServiceRepository, SQLiteUserRepository)

    db = SQLiteDatabase(db_path)
    users = SQLiteUserRepository(db)
    services = SQLiteServiceRepository(db)
    incidents = SQLiteIncidentRepository(db, users, services)

    bus = EventBus()
    audit = SQLiteAuditLog(db)
    bus.subscribe(audit, required=True)

    inapp = InAppNotifier()
    email = EmailNotifier()
    bus.subscribe(NotificationObserver([inapp, email]))
    bus.subscribe(SQLiteNotificationObserver(db), required=True)

    sla = SLAMonitor(bus, repository=incidents)
    catalog = CategoryCatalog()
    svc = IncidentService(incidents, users, services, bus, WeightedScorePriority(),
                          SkillBasedAssignment(), catalog, DuplicateDetector(), sla, clock)

    auth = AuthService(users)
    analytics = DashboardAnalytics(incidents, users, services)
    matcher = HistoricalResolutionMatcher(incidents)
    ai = AIAssistant(matcher)

    return System(
        service=svc,
        users=users,
        services=services,
        incidents=incidents,
        bus=bus,
        audit=audit,
        inapp=inapp,
        email=email,
        sla=sla,
        catalog=catalog,
        auth=auth,
        analytics=analytics,
        ai=ai
    )

