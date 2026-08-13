# Batch 05: Virtual OPC UA address space and subscriptions

## Context

- Completed dependencies: published asset model, deterministic simulator, clock, and snapshots.
- This batch exposes simulator state through OPC UA so the same collector contract can later consume simulated and real read-only data.
- The virtual server may expose simulation command nodes, but only inside the isolated simulator service and simulator namespace.

## Outcome

- A standard OPC UA client can browse the Pump Tank hierarchy, read metadata and values, and receive DataChange/Event/Alarm notifications.
- Values, source/server timestamps, status codes, units, data types, and access levels match the published asset model.
- Shadow Agent credentials cannot write or call methods, including command nodes.

## Inputs

- Asset model version, signal catalog, units, access modes, and NodeId templates from Batch 02.
- StateFrame stream, clock, simulator lifecycle, and commands from Batches 03–04.
- OPC UA application URI, endpoint, namespace URI, server/client test certificates, and security policy.
- Default publishing interval 500 ms and simulator step 100 ms.

## Code modules

- `services/simulator/src/shadow_simulator/opcua/server.py`: asyncua server lifecycle.
- `services/simulator/src/shadow_simulator/opcua/address_space.py`: hierarchy and NodeId creation.
- `services/simulator/src/shadow_simulator/opcua/publisher.py`: frame-to-node updates and timestamps.
- `services/simulator/src/shadow_simulator/opcua/events.py`: alarms, mode, fault, and lifecycle events.
- `services/simulator/src/shadow_simulator/opcua/security.py`: certificates, roles, and access enforcement.
- `services/simulator/src/shadow_simulator/opcua/commands.py`: simulator-only command bridge.
- `schemas/api/opcua-endpoint-metadata.json`.
- `deploy/compose/certs/`: generated development-only PKI path and generation script/config.
- `domain-packs/pump-tank-v1/signals/opcua-mapping.yaml`.
- `tests/contract/opcua/` and interoperability probe.

## Interfaces

- Address space: `Objects/Factory/Line1/{Tank101,Pump101,Valve101,Valve102,Heater101,System}`.
- Each variable exposes NodeId, BrowseName, data type, engineering unit, value, SourceTimestamp, ServerTimestamp, StatusCode, AccessLevel, and minimum sampling interval.
- Shadow role: Browse/Read/Subscribe only across all nodes; no MethodCall.
- Simulator operator role: may write only registered simulation command nodes within range.
- Internal endpoint registry returns application URI, certificate fingerprint, namespace URI, security mode, and simulator identity digest.
- OPC UA events include mode transition, simulator paused/resumed, fault lifecycle placeholder, alarm activation, and data-quality status.
- Node mapping is generated from the published registry; runtime code does not maintain a parallel hand-written signal list.

## Implementation requirements

1. Use a stable namespace URI and deterministic string NodeIds from the published signal keys.
2. Map supported scalar types and engineering units without silent coercion.
3. Set source timestamps from virtual time and server timestamps from the OPC UA server boundary; retain their distinction.
4. Publish simulator frames at the configured interval without mutating the model clock.
5. Implement DataChange subscriptions and at least one alarm/event path.
6. Enforce roles server-side. Anonymous access is disabled outside explicit development profile.
7. Reject out-of-range, wrong-type, non-command, or unauthorized writes with correct OPC UA status codes.
8. Do not expose arbitrary methods, file access, or dynamic Node creation.
9. Generate development certificates reproducibly; never commit private production keys.
10. Publish connection, subscription, notification, and rejected-write metrics and traces.
11. Fail startup if the asset mapping references missing or duplicate signals.
12. Add compatibility notes for asyncua version and tested OPC UA client.

## Tests

- Unit: address-space generation, type/unit mapping, timestamps, access levels, command validation.
- Contract: browse and compare every mapped Node against the published asset-model version.
- Subscription: change simulator commands and verify ordered DataChange notifications with expected timestamps.
- Event: trigger mode/alarm events and validate payload fields.
- Security: Shadow certificate attempts Write and Call on sensor, command, and method targets; all are rejected.
- Positive simulator operator: a permitted virtual command changes simulator state within range.
- Failure: invalid certificate, namespace mismatch, duplicate NodeId, server restart, and subscription reconnect.
- Interoperability: run an independent OPC UA client process, not only in-process calls.

## Required evidence

- `docs/evidence/batch-05/manifest.json`.
- Full browse-tree export and asset-model comparison report.
- Subscription event capture with source/server/received timestamps.
- OPC UA security test matrix including rejected Shadow writes and calls.
- Independent client interoperability log and tested library/client versions.
- Compose service health, certificate fingerprints, and server trace excerpts without private keys.
- Unit/contract/integration test reports and OpenAPI metadata schema digest.

## Definition of Done

- An independent client browses, reads, and subscribes to every required Pump Tank signal.
- Node metadata and access levels match the published asset registry.
- Simulator command updates cause correct process responses through a permitted simulator-only identity.
- Shadow identity write/call attempts are rejected and recorded.
- Events/alarms and timestamp semantics are proven by captured integration output.
- Server restart and client reconnect recover without changing stable NodeIds.
- No real endpoint or generic OPC UA write client is introduced.

## Out of scope

- Real OPC UA endpoint access, redundant servers, broad companion specifications, and production PKI automation.
- Collector persistence and diagnostic processing.

