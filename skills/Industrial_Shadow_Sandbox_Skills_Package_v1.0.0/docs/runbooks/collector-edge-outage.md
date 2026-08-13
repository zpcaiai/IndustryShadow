# Collector or Edge outage

The safe state is no new trusted data. Confirm endpoint identity before reconnecting;
never relax certificate, namespace, node allowlist, or read-only policy to recover.
Inspect sequence gaps, spool utilization, clock skew, and duplicate hashes. Reconnect
with bounded backoff, ingest buffered batches exactly once, and keep affected windows
`DEGRADED`/`UNTRUSTED` until gap and freshness checks pass.
