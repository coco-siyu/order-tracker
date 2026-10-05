# Incident responder

The responder accepts Grafana webhook notifications at `POST /alerts`. For each
firing alert it creates a directory under `incidents/`, captures recent Order
Tracker logs from Loki and traces from Tempo, and starts Codex in non-interactive
mode. Resolved alerts are acknowledged but do not start an agent.

Start it from the repository root:

```bash
./incident-response/run.sh
```

The responder listens on <http://127.0.0.1:8001>. Check it with:

```bash
curl http://127.0.0.1:8001/healthz
```

Send the Homework 4 test notification:

```bash
curl -X POST http://127.0.0.1:8001/alerts \
  -H 'Content-Type: application/json' \
  -d '{"alerts":[{"status":"firing","labels":{"alertname":"ResponderTest","test":"true"},"annotations":{"summary":"Test notification; no incident to fix"}}]}'
```

The response contains an incident ID. Poll it until `state` is `completed`:

```bash
curl http://127.0.0.1:8001/incidents/latest
```

Generated incident files include the original alert, context, logs, traces,
agent prompt, agent output, and final status. The default command is `codex exec`
with workspace-only writes and no interactive approval prompts. Override the CLI
binary or wrapper with `INCIDENT_AGENT_COMMAND`, for example:

```bash
INCIDENT_AGENT_COMMAND=/path/to/codex ./incident-response/run.sh
```

Optional settings:

| Variable | Default | Purpose |
| --- | --- | --- |
| `LOKI_URL` | `http://127.0.0.1:3100` | Loki API base URL |
| `TEMPO_URL` | `http://127.0.0.1:3200` | Tempo API base URL |
| `INCIDENT_AGENT_TIMEOUT` | `900` | Headless agent timeout in seconds |
| `INCIDENT_DATA_DIR` | `incident-response/incidents` | Evidence directory |
| `INCIDENT_WEBHOOK_TOKEN` | unset | Optional bearer token required by `/alerts` |
