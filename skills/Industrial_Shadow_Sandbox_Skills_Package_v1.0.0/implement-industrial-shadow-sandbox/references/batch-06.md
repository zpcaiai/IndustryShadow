# Batch 06: Shadow Collector and lossless raw-event storage

## Context

- Completed dependencies: virtual OPC UA endpoint and canonical asset/signal registry.
- Collector owns acquisition, timestamp/quality preservation, ordering metadata, batching, and storage; it does not diagnose.
- Raw events must remain available because aggregation would destroy evidence for delay, dropout, reorder, and freeze faults.

## Outcome

- A separate collector process connects with read-only credentials, subscribes to allowed Nodes, persists every received notification, and reports connection/data freshness.
- Raw data can be queried by run, signal, and time window and exported as deterministic Parquet.
- Reconnect, duplicates, gaps, out-of-order events, quality codes, and backpressure remain observable.

## Inputs

- OPC UA endpoint identity and read-only client certificate from Batch 05.
- Published signal definitions and Node allowlist from Batch 02.
- Run context initially supplied by a development run token; Batch 10 replaces it with full orchestration.
- PostgreSQL and file storage from Batch 01.

## Code modules

- `services/collector/src/shadow_collector/client.py`: read-only OPC UA client lifecycle.
- `services/collector/src/shadow_collector/subscriptions.py`: MonitoredItem registration and reconnect.
- `services/collector/src/shadow_collector/normalization.py`: typed value/timestamp/quality envelope.
- `services/collector/src/shadow_collector/buffer.py`: bounded batching and backpressure.
- `services/collector/src/shadow_collector/writer.py`: raw-event and Parquet writers.
- `services/collector/src/shadow_collector/policy.py`: endpoint, namespace, Node, operation, and rate policy.
- `backend/src/shadow_sandbox/ingestion/entities.py`, `repository.py`, `query_service.py`, and `api.py`.
- `migrations/*_raw_signal_events.py`: partition-ready raw event and connection event tables.
- `schemas/events/raw-signal-event-v1.json` and `connection-event-v1.json`.
- `tests/integration/collector/` and Compose collector profile.

## Interfaces

- `RawSignalEventV1`: tenant/workspace/run/scenario/endpoint, NodeId, signal key, data type/value, source/server/received timestamps, status code, sequence, ingest version, and trace context.
- `ConnectionEventV1`: connect, disconnect, reconnect, certificate mismatch, subscription created/rebuilt, and policy denial.
- Collector config: `environment_type`, endpoint URI, application URI, certificate fingerprint, allowlisted namespace URIs/Node prefixes, maximum Nodes, interval, batch size, and storage policy.
- `GET /api/v1/runs/{run_id}/signals/{signal_key}/events?from=&to=&limit=`.
- `GET /api/v1/connectors/{id}/health` returns state, freshness, latency, gaps, backlog, and last error.
- `POST /api/v1/runs/{run_id}/exports/parquet` creates a content-addressed Parquet manifest.
- Collector code exposes no Write or Call method through its public adapter.

## Implementation requirements

1. Validate endpoint identity, certificate fingerprint, namespace, Node allowlist, and environment type before subscription.
2. Record raw source, server, and received timestamps and the original OPC UA status code.
3. Add collector sequence numbers without pretending they are server sequence numbers.
4. Detect and mark duplicates, reordering, gaps, clock skew, and interval drift while preserving the original event.
5. Use bounded queues; on pressure, expose degraded health and fail/stop according to policy rather than silently dropping.
6. Batch writes transactionally and make retry deduplication deterministic.
7. Rebuild subscriptions after reconnect and record the exact data gap.
8. Partition/index by run, signal, and timestamp; use Parquet for immutable bulk data.
9. Apply tenant/workspace context from a trusted run binding, not from event payloads.
10. Provide retention hooks but protect datasets referenced by replays/evaluations.
11. Instrument receive-to-persist latency, freshness, event rate, reconnects, gaps, duplicates, and backlog.
12. Make writes to a test OPC UA server impossible through the collector interface and dependency graph.

## Tests

- Unit: normalization for numeric/boolean/string/enum, status codes, timestamps, duplicate/reorder/gap markers, buffer behavior.
- Contract: every raw event validates against JSON Schema and query responses against OpenAPI.
- Integration: subscribe to the real virtual server for five virtual minutes and compare published versus persisted frame counts.
- Fault: restart server, delay notifications, force duplicate/reorder, fill buffer, and recover storage.
- Persistence: transaction retry does not duplicate logical events; Parquet row counts and hashes match source query.
- Security: disallowed endpoint/namespace/Node/certificate is denied; static dependency check confirms no write adapter.
- Performance: meet the MVP event rate with P95 receive-to-persist ≤1 second.
- Restart: collector resumes, reconstructs subscription, and records the gap without fabricating samples.

## Required evidence

- `docs/evidence/batch-06/manifest.json`.
- Browse/subscription allowlist and endpoint identity validation logs.
- Published-versus-persisted count comparison and gap/duplicate/reorder fault report.
- Raw-event JSON samples with non-sensitive values and Parquet manifest/hash.
- Database index/partition plan and migration output.
- P95 latency/backlog benchmark and OTel trace.
- Security/dependency test proving the collector has no callable Write/Call path.

## Definition of Done

- Collector persists real subscription notifications from the virtual OPC UA service through a separate process.
- Original values, three timestamps, status codes, sequence metadata, run/scenario IDs, and signal identity are queryable.
- Reconnect and storage-pressure tests expose gaps and degraded health without silent loss or fabricated data.
- Parquet export is repeatable, content-addressed, and row-count verified.
- Endpoint/namespace/Node policies are enforced before acquisition.
- MVP latency and event-rate targets pass on the declared reference environment.
- Diagnostic algorithms are absent from the collector boundary.

## Out of scope

- Root-cause analysis, anomaly scoring, historical import, and real factory endpoint deployment.
- Kafka or a distributed time-series cluster.

