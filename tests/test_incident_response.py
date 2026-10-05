import json
import sys
import time
from datetime import datetime
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "incident-response"))

import responder.main as responder_main  # noqa: E402
from responder.main import Settings, collect_evidence, create_app  # noqa: E402


def wait_for_terminal_state(client: TestClient) -> dict:
    for _ in range(100):
        status = client.get("/incidents/latest").json()
        if status["state"] in {"completed", "failed", "timed_out"}:
            return status
        time.sleep(0.01)
    raise AssertionError("incident did not finish")


def test_firing_alert_saves_evidence_and_runs_agent(tmp_path):
    def fake_agent(incident_dir, prompt, _settings):
        response = "Test inspected.\nTEST ALERT RECEIVED - no incident to fix\n"
        (incident_dir / "agent-response.md").write_text(response)
        return {"exit_code": 0, "response": response, "command": ["fake-agent"]}

    settings = Settings(
        repo_root=ROOT,
        incidents_dir=tmp_path,
        loki_url="http://127.0.0.1:1",
        tempo_url="http://127.0.0.1:1",
        telemetry_timeout_seconds=1,
    )
    client = TestClient(create_app(settings, fake_agent))
    response = client.post(
        "/alerts",
        json={
            "alerts": [
                {
                    "status": "firing",
                    "labels": {"alertname": "ResponderTest", "test": "true"},
                    "annotations": {
                        "summary": "Test notification; no incident to fix",
                        "endpoint": "/api/orders/{order_id}",
                        "time_window": "1 minute",
                    },
                }
            ]
        },
    )

    assert response.status_code == 202
    incident_id = response.json()["incident_ids"][0]
    status = wait_for_terminal_state(client)
    assert status["state"] == "completed"
    assert status["response"].rstrip().endswith(
        "TEST ALERT RECEIVED - no incident to fix"
    )

    incident_dir = tmp_path / incident_id
    assert json.loads((incident_dir / "context.json").read_text())["endpoint"] == (
        "/api/orders/{order_id}"
    )
    assert (incident_dir / "logs.json").exists()
    assert (incident_dir / "traces.json").exists()
    assert "explicitly marked as a test alert" in (
        incident_dir / "agent-prompt.md"
    ).read_text()


def test_resolved_alert_does_not_start_agent(tmp_path):
    called = False

    def fake_agent(_incident_dir, _prompt, _settings):
        nonlocal called
        called = True
        return {"exit_code": 0, "response": "unexpected"}

    settings = Settings(repo_root=ROOT, incidents_dir=tmp_path)
    client = TestClient(create_app(settings, fake_agent))
    response = client.post(
        "/alerts",
        json={"alerts": [{"status": "resolved", "labels": {"alertname": "5xx"}}]},
    )

    assert response.status_code == 202
    assert response.json() == {
        "accepted": 0,
        "ignored": 1,
        "incident_ids": [],
        "status_urls": [],
    }
    assert called is False
    assert list(tmp_path.iterdir()) == []


def test_firing_grafana_sentinel_end_time_uses_current_window(tmp_path, monkeypatch):
    queries = []

    def fake_get_json(base_url, path, params, timeout):
        queries.append((base_url, path, params, timeout))
        if path == "/api/search":
            return {"traces": []}
        return {"status": "success", "data": {"result": []}}

    monkeypatch.setattr(responder_main, "http_get_json", fake_get_json)
    settings = Settings(repo_root=ROOT, incidents_dir=tmp_path)
    evidence = collect_evidence(
        {
            "status": "firing",
            "startsAt": "2026-10-05T23:29:50Z",
            "endsAt": "0001-01-01T00:00:00Z",
            "annotations": {"time_window": "1 minute"},
        },
        settings,
    )

    query_start = datetime.fromisoformat(evidence["query_start"].replace("Z", "+00:00"))
    query_end = datetime.fromisoformat(evidence["query_end"].replace("Z", "+00:00"))
    assert query_start.year > 1970
    assert query_start < query_end
    assert len(queries) == 2
