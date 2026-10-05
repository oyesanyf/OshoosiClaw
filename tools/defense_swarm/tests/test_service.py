import pytest
from starlette.testclient import TestClient
from defense_swarm.service import app


@pytest.fixture
def client():
    return TestClient(app)


def test_health_endpoint(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["engine"] == "LangGraph StateGraph"


def test_investigate_benign_incident(client):
    payload = {
        "incident_id": "INC-TEST-BENIGN",
        "target_pid": 1100,
        "target_process_name": "cargo.exe",
        "target_path": r"C:\Users\dev\.cargo\bin\cargo.exe",
        "command_line": "cargo check",
        "initial_confidence": 0.20,
    }
    resp = client.post("/api/swarm/investigate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == "INC-TEST-BENIGN"
    assert data["status"] == "DE_ESCALATED"
    assert data["triage_verdict"] == "BENIGN"


def test_investigate_and_approval_flow(client):
    payload = {
        "incident_id": "INC-TEST-INTERRUPT",
        "target_pid": 5566,
        "target_process_name": "payload.exe",
        "target_path": r"C:\Temp\payload.exe",
        "command_line": "payload.exe -enc ZZZZZZ",
        "initial_confidence": 0.95,
    }
    # 1. Trigger investigation -> Should pause with WAITING_APPROVAL
    resp = client.post("/api/swarm/investigate", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == "INC-TEST-INTERRUPT"
    assert data["status"] == "WAITING_APPROVAL"

    # 2. Check pending approvals endpoint
    app_resp = client.get("/api/swarm/approvals")
    assert app_resp.status_code == 200
    pending = app_resp.json()
    assert any(p["incident_id"] == "INC-TEST-INTERRUPT" for p in pending)

    # 3. Check status endpoint
    st_resp = client.get("/api/swarm/status/INC-TEST-INTERRUPT")
    assert st_resp.status_code == 200
    assert st_resp.json()["status"] == "WAITING_APPROVAL"

    # 4. Approve incident
    resume_resp = client.post("/api/swarm/approve/INC-TEST-INTERRUPT?feedback=VerifiedMalicious")
    assert resume_resp.status_code == 200
    res_data = resume_resp.json()
    assert res_data["status"] == "COMPLETED"
    assert res_data["operator_approval_status"] == "APPROVED"
