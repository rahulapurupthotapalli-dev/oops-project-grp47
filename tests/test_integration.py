"""Regression coverage for the persistent application and its HTTP permission boundaries."""
import importlib.util
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from iitsm.auth import PasswordHasher
from iitsm.bootstrap import build_sqlite_system


@pytest.fixture
def api(tmp_path, monkeypatch):
    path = tmp_path / "incidents.db"
    monkeypatch.setenv("IITSM_DB_PATH", str(path))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    spec = importlib.util.spec_from_file_location("reviewed_app", Path(__file__).parents[1] / "app.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with TestClient(module.app) as client:
        yield client, module, path


def login(client, user, password="password123"):
    response = client.post("/api/auth/login", json={"user_id_or_email": user, "password": password})
    assert response.status_code == 200
    return {"Authorization": "Bearer " + response.json()["access_token"]}


def report(client, headers, description="Checkout stopped returning transaction receipts"):
    return client.post("/api/incidents", headers=headers, json={
        "description": description, "service_name": "Payment Gateway", "impact": 5, "urgency": 5
    })


def test_seeded_ids_survive_restart_and_concurrent_writes(api):
    client, app, path = api
    original = {i.id: i.description for i in app.system.incidents.all()}
    first = report(client, login(client, "emp1")).json()
    assert first["id"] == "INC1026"
    descriptions = ["Telephony", "Console", "Labels", "Invoice"]
    def create(text):
        other = build_sqlite_system(str(path))
        return other.service.report("emp1", text, "Payment Gateway", 2, 2).id
    with ThreadPoolExecutor(max_workers=4) as pool:
        ids = list(pool.map(create, descriptions))
    assert len(set(ids)) == len(descriptions)
    assert app.system.incidents.count() == 30
    assert all(app.system.incidents.get(k).description == v for k, v in original.items())


def test_browser_api_lifecycle_and_duplicate(api):
    c, app, _ = api
    employee, admin = login(c, "emp1"), login(c, "admin1")
    item = report(c, employee).json()
    uri = "/api/incidents/" + item["id"]
    assert report(c, employee).status_code == 409
    technician = login(c, item["assigned_to"]["id"])
    assert c.post(uri + "/resolve", headers=technician, json={"resolution":"too early"}).status_code == 409
    assert c.post(uri + "/acknowledge", headers=technician, json={"notes":"Can you confirm the time?"}).json()["notes_count"] == 1
    assert c.post(uri + "/notes", headers=employee, json={"content":"Started at noon."}).status_code == 200
    for action, who, payload, expected in [
        ("investigate", technician, {}, "IN_PROGRESS"), ("resolve", technician, {"resolution":"Recovered"}, "RESOLVED"),
        ("verify", employee, {"feedback":"Working again"}, "VERIFIED"), ("close", admin, {}, "CLOSED")]:
        assert c.post(uri + "/" + action, headers=who, json=payload).json()["status"] == expected
    assert c.post(uri + "/reassign", headers=admin, json={"technician_id":"tech_t1_1"}).status_code == 409
    assert len(c.get(uri, headers=employee).json()["notes"]) == 2
    assert c.get(uri, headers=employee).json()["audit_trail"][-1]["event_type"] == "INCIDENT_CLOSED"
    channels = {n["channel"] for n in c.get("/api/notifications", headers=employee).json() if item["id"] in n["subject"]}
    assert channels == {"IN_APP", "SIMULATED_EMAIL"}


def test_permissions_lists_reports_and_invalid_inputs(api):
    c, app, _ = api
    employee, other, tech = login(c,"emp1"), login(c,"emp2"), login(c,"tech_t1_1")
    item = report(c, employee).json()
    uri = "/api/incidents/" + item["id"]
    for url in ["/api/audit", "/api/analytics/overview", "/api/analytics/workload", "/api/admin/services"]:
        assert c.get(url).status_code == 401
    assert c.get(uri, headers=other).status_code == 403
    for route in ["ai-diagnostics", "recommend-technicians"]:
        assert c.get(uri + "/" + route, headers=other).status_code == 403
    for route in ["escalate", "reassign"]:
        assert c.post(uri + "/" + route, headers=other, json={}).status_code == 403
    rows = c.get("/api/incidents?technician_id=other", headers=tech).json()
    assert rows and all(i["assigned_to"]["id"] == "tech_t1_1" for i in rows)
    assert c.get("/api/incidents?priority=nonsense", headers=employee).status_code == 422
    assert c.get("/api/incidents/nonexistent", headers=employee).status_code == 404
    count = app.system.incidents.count()
    assert report(c, employee, " ").status_code == 422
    assert app.system.incidents.count() == count


def test_sla_markers_and_escalation_survive_restart(api):
    c, app, path = api
    inc = app.system.service.report("emp1", "Portal not loading receipts", "Payment Gateway", 5, 5)
    now = inc.resolution_due + timedelta(seconds=1)
    def escalate(item, reason):
        app.system.service.escalate(item.id, reason)
    events = app.system.sla.sweep([inc], now, on_escalate=escalate)
    assert len(events) == 2
    restarted = build_sqlite_system(str(path))
    stored = restarted.incidents.get(inc.id)
    assert stored.violations == {"RESPONSE", "RESOLUTION"}
    assert stored.escalation_tier.value == inc.escalation_tier.value + 1
    assert restarted.sla.sweep([inc], now) == []


def test_registration_duplicates_and_custom_service_policy(api):
    c, app, path = api
    registration = dict(id="newuser", name="New User", email="new@example.org", password="demo-passphrase")
    assert c.post("/api/auth/register", json=registration).status_code == 201
    assert c.post("/api/auth/register", json={**registration, "id":"EMP1"}).status_code == 409
    assert c.post("/api/auth/register", json={**registration, "id":"second"}).status_code == 409
    assert not PasswordHasher.verify_password("Pass123", "")
    hdr = login(c, "admin1")
    targets = {p: dict(response_minutes=2, resolution_minutes=11) for p in ("P1","P2","P3","P4")}
    assert c.put("/api/admin/services/Payment Gateway/sla", headers=hdr, json=targets).status_code == 200
    service = build_sqlite_system(str(path)).service
    inc = service.report("newuser","Subscription renewal broken","Payment Gateway",5,5)
    assert inc.response_due - inc.created_at == timedelta(minutes=2)
    assert inc.resolution_due - inc.created_at == timedelta(minutes=11)


def test_required_audit_failure_rolls_back_report(api):
    import sqlite3
    _, app, _ = api

    class FailingAudit:
        def update(self, event):
            raise sqlite3.OperationalError("audit storage unavailable")

    app.system.bus.subscribe(FailingAudit(), required=True)
    count = app.system.incidents.count()
    with pytest.raises(sqlite3.OperationalError):
        app.system.service.report("emp1", "Checkout options are blank", "Payment Gateway", 3, 3)
    assert app.system.incidents.count() == count
    assert not app.system.audit.history("INC1026")
    with app.db.get_connection() as connection:
        assert not connection.execute("SELECT 1 FROM notifications WHERE subject LIKE '[INC1026]%'").fetchone()


def test_capacity_and_new_catalog_settings(api):
    c, app, _ = api
    admin, employee = login(c, "admin1"), login(c, "emp1")
    url = "/api/admin/technicians/tech_t1_1/capacity"
    change = {"available":False, "max_workload":10}
    assert c.put(url, headers=employee, json=change).status_code == 403
    assert c.put(url, headers=admin, json=change).json()["available"] is False
    assert c.post("/api/admin/categories", headers=admin, json={"name":"Print", "keywords":["toner"]}).status_code == 200
    service = {"name":"Campus printing", "criticality":2}
    assert c.post("/api/admin/services", headers=admin, json=service).status_code == 200
    assert c.post("/api/admin/services", headers=admin, json=service).status_code == 409
    inc = c.post("/api/incidents", headers=employee, json={
        "description":"Toner low", "service_name":service["name"], "impact":1,"urgency":1
    }).json()
    assert (inc["category"], inc["status"]) == ("PRINT", "CLASSIFIED")
    response = c.post("/api/incidents/" + inc["id"] + "/reassign", headers=admin, json={"technician_id":"tech_t3_1"})
    assert response.json()["status"] == "ASSIGNED"
