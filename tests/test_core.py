from datetime import datetime, timedelta

import pytest

from iitsm.bootstrap import build_system
from iitsm.enums import Priority, Status
from iitsm.events import Observer
from iitsm.exceptions import *
from iitsm.models import (DEFAULT_SLA, Administrator, Employee, Incident, ITService, SLAPolicy, Technician)
from iitsm.strategies import LoadBasedAssignment


class Clock:
    def __init__(self): self.t = datetime(2026, 11, 20, 10, 0)
    def __call__(self): return self.t
    def advance(self, **kw): self.t += timedelta(**kw)


@pytest.fixture
def clock(): return Clock()


@pytest.fixture
def s(clock):
    s = build_system(clock)
    for u in (Employee("E102", "Asha", "asha@corp.in"), Employee("E103", "Kiran", "kiran@corp.in"),
              Technician("T205", "Ravi", "ravi@corp.in", {"APPLICATION", "DATABASE"}, experience_years=6, max_workload=2),
              Technician("T206", "Meena", "meena@corp.in", {"NETWORK"}, experience_years=2),
              Administrator("A1", "Root", "root@corp.in")):
        s.users.save(u)
    s.services.save(ITService("Payment", 5, DEFAULT_SLA))
    s.services.save(ITService("Wifi", 2, DEFAULT_SLA))
    return s


PAY = "Payment application unavailable"


def test_full_lifecycle_audit_and_workload(s):
    inc = s.service.report("E102", PAY, "Payment", 5, 5, affected_users=200)
    assert (inc.category, inc.priority, inc.assigned_to.id, inc.status) == ("APPLICATION", Priority.P1, "T205", Status.ASSIGNED)
    s.service.acknowledge("T205", inc.id); s.service.start_investigation("T205", inc.id)
    s.service.resolve("T205", inc.id, "Restarted payment gateway"); s.service.verify("E102", inc.id, "works")
    s.service.close("A1", inc.id)
    assert inc.status is Status.CLOSED and s.users.get("T205").workload == 0
    types = [e.type for e in s.audit.history(inc.id)]
    assert types[:4] == ["INCIDENT_CREATED", "INCIDENT_CLASSIFIED", "PRIORITY_CALCULATED", "INCIDENT_ASSIGNED"]
    assert types[-1] == "INCIDENT_CLOSED"


def test_new_to_closed_is_rejected(s, clock):
    inc = Incident("X1", s.users.get("E102"), "d", s.services.get("Wifi"), 1, 1, 1, clock())
    with pytest.raises(InvalidStateTransition):
        inc.move_to(Status.CLOSED)


def test_priority_levels_and_boundary(s):
    assert s.service.report("E102", "Wifi slow in lab", "Wifi", 1, 1).priority is Priority.P4   # 1*1*2=2
    assert s.service.report("E103", "Payment page slow", "Payment", 3, 3).priority is Priority.P2  # 45
    assert s.service.report("E103", "Payment typo on receipt", "Payment", 1, 2).priority is Priority.P3  # 10 boundary


def test_sla_deadlines(s, clock):
    inc = s.service.report("E102", PAY, "Payment", 5, 5)
    assert inc.response_due - inc.created_at == timedelta(minutes=5)
    assert inc.resolution_due - inc.created_at == timedelta(minutes=30)


def test_sla_warning_then_violation_only_once(s, clock):
    inc = s.service.report("E102", PAY, "Payment", 5, 5)
    clock.advance(minutes=4)
    assert s.sla.sweep(s.incidents.all(), clock()) == [(inc.id, "SLA_WARNING", "RESPONSE")]
    clock.advance(minutes=2)
    assert s.sla.sweep(s.incidents.all(), clock()) == [(inc.id, "SLA_VIOLATED", "RESPONSE")]
    assert s.sla.sweep(s.incidents.all(), clock()) == []


def test_skill_based_assignment_picks_network_tech(s):
    assert s.service.report("E102", "Wifi down in block C", "Wifi", 3, 3).assigned_to.id == "T206"


def test_strategy_swapped_at_runtime(s):
    s.service.report("E102", PAY, "Payment", 5, 5)            # T205 now has 1
    s.service.set_assignment_strategy(LoadBasedAssignment())
    assert s.service.report("E103", "Database slow for reports", "Payment", 2, 2).assigned_to.id == "T206"


def test_no_skilled_technician_leaves_incident_unassigned(s):
    inc = s.service.report("E102", "Cloud instance unreachable", "Payment", 3, 3, category="CLOUD")
    assert inc.status is Status.CLASSIFIED and inc.assigned_to is None
    assert "ASSIGNMENT_FAILED" in [e.type for e in s.audit.history(inc.id)]
    with pytest.raises(TechnicianUnavailable):
        s.service.assign(inc.id)


def test_workload_exceeded_and_unavailable():
    t = Technician("T1", "X", "x@c.in", {"NETWORK"}, max_workload=1)
    t.take("I1")
    with pytest.raises(WorkloadExceeded): t.take("I2")
    t.available = False
    with pytest.raises(TechnicianUnavailable): t.take("I3")


def test_authorization(s):
    inc = s.service.report("E102", PAY, "Payment", 5, 5)
    with pytest.raises(UnauthorizedOperation): s.service.close("E102", inc.id)
    with pytest.raises(UnauthorizedOperation): s.service.acknowledge("T206", inc.id)   # not the assignee
    with pytest.raises(UnauthorizedOperation): s.service.report("T205", "x", "Payment", 1, 1)


def test_illegal_workflow_order_via_service(s):
    inc = s.service.report("E102", PAY, "Payment", 5, 5)
    with pytest.raises(InvalidStateTransition): s.service.resolve("T205", inc.id, "fixed")


def test_related_and_exact_duplicate_detection(s):
    a = s.service.report("E102", PAY, "Payment", 5, 5)
    b = s.service.report("E103", "Unable to make payment", "Payment", 4, 4)
    assert b.related == [a.id]
    with pytest.raises(DuplicateIncident):
        s.service.report("E102", PAY, "Payment", 5, 5)


def test_invalid_inputs(s):
    with pytest.raises(InvalidInput): s.service.report("E102", "  ", "Payment", 3, 3)
    with pytest.raises(InvalidInput): s.service.report("E102", "slow", "Payment", 9, 3)
    with pytest.raises(InvalidInput): s.service.report("E102", "slow", "Payment", 3, 3, category="MAGIC")


def test_service_user_incident_not_found(s):
    with pytest.raises(ServiceNotFound): s.service.report("E102", "x y", "Nope", 3, 3)
    with pytest.raises(UserNotFound): s.service.report("E999", "x y", "Payment", 3, 3)
    with pytest.raises(IncidentNotFound): s.service.assign("INC0")


def test_missing_sla_configuration(s):
    with pytest.raises(MissingSLAConfiguration): SLAPolicy({Priority.P1: (1, 2)})
    s.services.save(ITService("Legacy", 3))
    with pytest.raises(MissingSLAConfiguration): s.service.report("E102", "Legacy app slow", "Legacy", 3, 3)


def test_new_category_without_touching_other_code(s):
    s.catalog.register("PRINTING", {"print", "toner"})
    assert s.catalog.suggest("toner empty") == "PRINTING"
    assert s.catalog.suggest("hello world") == "GENERAL"


def test_notifications_on_two_channels(s):
    inc = s.service.report("E102", PAY, "Payment", 5, 5)
    subjects = [sub for sub, _ in s.inapp.inbox["E102"]]
    assert f"[{inc.id}] INCIDENT_CREATED" in subjects
    assert any(m["to"] == "T205" for m in s.email.outbox)


def test_broken_observer_does_not_break_workflow(s):
    class Bad(Observer):
        def update(self, event): raise RuntimeError("boom")
    s.bus.subscribe(Bad())
    assert s.service.report("E102", PAY, "Payment", 5, 5).status is Status.ASSIGNED
    assert s.bus.failures
