# Order Tracker

A small order tracking app for the AI Dev Tools Zoomcamp observability homework. It includes a web page, API, tests, and a Docker Compose setup. You add telemetry, alerts, and an incident responder in Homework 4.

The main user flow is creating an order and checking its status. Three sample orders are created on first startup.

## Run it

You need Docker with Compose. To run the tests, you also need Python 3.11+ and `uv`.

```bash
docker compose up --build -d --wait
```

Open <http://127.0.0.1:8000>. The API is at `/api/orders`, and the health check is at `/healthz`. Data is stored in a Docker volume and survives container recreation.

If port 8000 is occupied, set `ORDER_TRACKER_PORT`, for example:

```bash
ORDER_TRACKER_PORT=18080 docker compose up --build -d --wait
```

Run tests with `uv run --frozen pytest -q`. Stop the app with `docker compose down`. Add `-v` only if you also want to delete the order data.

## Observability

Docker Compose also starts an OpenTelemetry Collector, Prometheus, Loki,
Tempo, and Grafana. The application sends metrics, logs, and traces to the
Collector over OTLP/HTTP. The Collector exposes metrics for Prometheus and
forwards logs to Loki and traces to Tempo.

Open Grafana at <http://127.0.0.1:3000> and sign in with `admin` / `admin`.
The provisioned **Order Tracker Observability** dashboard shows request counts,
request rates by route and status, error rates, and recent application logs.

Generate a not-found lookup for the Homework 4 telemetry exercise:

```bash
curl -i http://127.0.0.1:8000/api/orders/standard-1002
```

Prometheus is available at <http://127.0.0.1:9090>, Loki at
<http://127.0.0.1:3100>, and Tempo at <http://127.0.0.1:3200> for local
troubleshooting. All observability configuration is stored in `observability/`.

## Incident responder

Start the automatic incident responder in a separate terminal:

```bash
./incident-response/run.sh
```

It accepts Grafana-compatible webhooks at `POST http://127.0.0.1:8001/alerts`.
For each firing alert it saves the alert, recent Loki logs, and recent Tempo
traces under `incident-response/incidents/`, then runs Codex headlessly. Check
the latest run with:

```bash
curl http://127.0.0.1:8001/incidents/latest
```

See `incident-response/README.md` for the test request and configuration.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/` | Web page |
| GET | `/healthz` | Database health check |
| GET | `/api/orders` | List orders |
| POST | `/api/orders` | Create an order |
| GET | `/api/orders/{id}` | Check an order |
| PATCH | `/api/orders/{id}` | Change an order status |

The app uses SQLite to keep setup small. Run one app container at a time. The course exercise is about detecting and handling an incident, not scaling the database.
