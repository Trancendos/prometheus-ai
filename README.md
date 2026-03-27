# Prometheus AI 🔥

> Monitoring, alerting, and Void Guardian service for the Trancendos mesh.
> Zero-cost compliant — no LLM calls, all rule-based detection.

**Port:** `3019`
**Architecture:** Trancendos Industry 6.0 / 2060 Standard

---

## Overview

Prometheus AI is the mesh-wide monitoring and threat detection service. It tracks all agents and services, records metrics, detects anomalies via z-score analysis, manages alert lifecycles, and guards The Void — a secure encrypted key-value store for sensitive mesh data.

---

## Core Capabilities

| Capability | Description |
|-----------|-------------|
| **Target Monitoring** | Track agents, services, databases, APIs, and system components |
| **Metric Recording** | Time-series metrics with min/max/avg aggregations (1000-point rolling window) |
| **Anomaly Detection** | Z-score based anomaly detection on metric streams |
| **Alert Management** | Raise, acknowledge, and track alerts across 4 severity levels |
| **Threat Scanning** | Periodic threat reports with recommendations |
| **Emergency Lockdown** | Mesh-wide lockdown initiation and lift |
| **Void Guardian** | Encrypted key-value store with access control and audit logging |

---

## Threat Levels

| Level | Description |
|-------|-------------|
| `green` | No unacknowledged alerts — mesh is healthy |
| `yellow` | 1–2 unacknowledged warnings |
| `orange` | Critical alerts present |
| `red` | Emergency alerts — immediate action required |

---

## API Reference

### Health

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service health + threat level + lockdown status |
| GET | `/metrics` | Runtime metrics + monitor stats |

### Monitoring Targets

| Method | Path | Description |
|--------|------|-------------|
| GET | `/targets` | List targets (filter by type) |
| GET | `/targets/:id` | Get a specific target |
| POST | `/targets` | Add a monitoring target |
| PATCH | `/targets/:id/toggle` | Enable/disable a target |
| DELETE | `/targets/:id` | Remove a target |

### Metrics

| Method | Path | Description |
|--------|------|-------------|
| GET | `/metrics-data` | List all metric series |
| GET | `/metrics-data/:targetId/:name` | Get a specific metric series |
| POST | `/metrics-data` | Record a metric value |

### Alerts

| Method | Path | Description |
|--------|------|-------------|
| GET | `/alerts` | List alerts (include acknowledged with `?includeAcknowledged=true`) |
| POST | `/alerts` | Raise an alert |
| PATCH | `/alerts/:id/acknowledge` | Acknowledge an alert |

### Threat Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/threat-level` | Current threat level |
| POST | `/threat-scan` | Run a threat scan |
| GET | `/threat-reports` | List recent threat reports |

### Emergency Lockdown

| Method | Path | Description |
|--------|------|-------------|
| GET | `/lockdown` | Lockdown status |
| POST | `/lockdown` | Initiate emergency lockdown |
| DELETE | `/lockdown` | Lift lockdown |

### Void Guardian

| Method | Path | Description |
|--------|------|-------------|
| GET | `/void` | List void keys |
| POST | `/void` | Store a value in the void |
| GET | `/void/:key` | Retrieve a value (requires `?requesterId=`) |
| DELETE | `/void/:key` | Delete a void entry |

### Stats

| Method | Path | Description |
|--------|------|-------------|
| GET | `/stats` | Monitor engine statistics |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3019` | HTTP server port |
| `HOST` | `0.0.0.0` | HTTP server host |
| `LOG_LEVEL` | `info` | Pino log level |
| `THREAT_INTERVAL_MS` | `300000` | Periodic threat assessment interval (ms) |

---

## Development

```bash
npm install
npm run dev       # tsx watch mode
npm run build     # compile TypeScript
npm start         # run compiled output
```

---

## Default Monitoring Targets

Prometheus AI seeds 6 default targets on startup:
- cornelius-ai, norman-ai, the-dr-ai, guardian-ai, dorris-ai, the-observatory

---

*Part of the Trancendos Industry 6.0 mesh — 2060 Standard*