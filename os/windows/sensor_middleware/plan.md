## Architecture Diagram (data flow)

```
 Sensor Agents
     │
     │  POST /api/v1/telemetry
     │  Authorization: Bearer <token>
     │  X-Sensor-Type: deepsensor | datasensor
     ▼
┌──────────────────┐
│  core_ingress    │  Validates auth → parses JSON array →
│  (HTTP/S :8443)  │  merges sensor_type into each event →
└────────┬─────────┘  publishes each event individually
         │
         │  NATS JetStream  (stream: SensorStream)
         │  subject: sensor.telemetry
         │
    ┌────┴────┬──────────────┐
    │         │              │
    ▼         ▼              ▼
┌────────┐ ┌────────┐ ┌────────┐
│ Splunk │ │Elastic │ │  SQL   │   Each worker:
│ Worker │ │ Worker │ │ Worker │   • Durable consumer group
│        │ │        │ │        │   • Batch assembly
│ CIM    │ │ ECS    │ │ JSON   │   • Exponential backoff retry (5x)
│ format │ │ format │ │ array  │   • Dead Letter Queue on final failure
└────────┘ └────────┘ └────────┘
    │         │              │
    ▼         ▼              ▼
 Splunk    Elastic      SQL Server
  HEC     Bulk API     Stored Proc
```

---

## Future-Proofing Roadmap

### Phase 1 — Current (Core Design Proven)
- [x] Per-event JetStream publishing with embedded sensor_type
- [x] CIM / ECS schema mapping
- [x] Exponential backoff with DLQ
- [x] SQL test webhook mode
- [x] Optional TLS on ingress
- [x] E2E QA harness with 30+ assertions
- [x] Automated build pipeline with MSVC provisioning

### Phase 2 — Hardening
- [ ] **Graceful shutdown** — Handle SIGTERM/SIGINT in `start_durable_worker` with `tokio::signal` for clean container stop
- [ ] **Request body limits** — Cap ingress payload at a configurable maximum (default 10 MB)
- [ ] **Health endpoint** — `GET /healthz` returning NATS connectivity status for K8s probes
- [ ] **Configurable cert verification** — `VerifyCert=True|False` per worker section instead of blanket `danger_accept_invalid_certs`
- [ ] **Connection pooling** — SQL worker: replace single `Mutex<Option<Client>>` with a pool for parallel batch execution
- [ ] **TLS for QA** — Generate self-signed certs in the QA harness and test the HTTPS path end-to-end

### Phase 3 — Observability & Scale
- [ ] **Metrics** — Prometheus `/metrics` endpoint or StatsD emission (events/sec, batch latency, error rate per worker)
- [ ] **Structured tracing** — JSON log output mode for SIEM ingestion of the middleware's own operational telemetry
- [ ] **Horizontal scaling validation** — Chaos test: run N instances of each worker and verify NATS load-balances events correctly
- [ ] **Back-pressure signaling** — If all retry attempts fail and DLQ is filling, emit a critical alert (webhook, SNMP trap, or JetStream advisory)
- [ ] **Schema versioning** — Version field in each event payload so workers can handle format evolution without downtime

### Phase 4 — Operational Maturity
- [ ] **CI/CD pipeline** — GitHub Actions or Azure DevOps YAML that runs `Build-SensorMiddleware.ps1` → `Invoke-MiddlewareQA.ps1` → publishes artifacts
- [ ] **Container images** — Multi-stage Dockerfiles (Rust builder → distroless runtime) for each binary
- [ ] **Config hot-reload** — Watch `config.ini` for changes and reconfigure without restart (batch sizes, endpoints)
- [ ] **mTLS between workers and SIEMs** — Client certificate auth for Splunk/Elastic connections