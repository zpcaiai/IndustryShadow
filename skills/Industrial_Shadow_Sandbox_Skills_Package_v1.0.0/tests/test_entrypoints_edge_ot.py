from __future__ import annotations

import asyncio
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Self
from unittest.mock import patch

import httpx
from shadow_collector.runner import collect
from shadow_edge.spool import EncryptedSpool
from shadow_sandbox.cli import generate_schemas
from shadow_sandbox.common import DomainError
from shadow_sandbox.operations.opcua_probe import ReadonlyOpcUaProbe
from shadow_sandbox.runtime import RunOrchestrator
from shadow_sandbox.worker import MaintenanceWorker
from test_foundation import actor, manifest, store

from tools.validate_local_postgresql_restore import _local_database_url, _positive_int


class EntrypointAndEdgeTests(unittest.IsolatedAsyncioTestCase):
    def test_local_restore_entrypoint_only_accepts_loopback_and_positive_limits(self) -> None:
        with patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(
            DomainError, "is required"
        ):
            _local_database_url("SHADOW_TEST_POSTGRESQL_URL")
        with patch.dict(
            os.environ,
            {"SHADOW_TEST_POSTGRESQL_URL": "postgresql://user@database.example/test"},
            clear=True,
        ), self.assertRaisesRegex(DomainError, "loopback"):
            _local_database_url("SHADOW_TEST_POSTGRESQL_URL")
        with patch.dict(
            os.environ,
            {
                "SHADOW_TEST_POSTGRESQL_URL": "postgresql://user@127.0.0.1/test",
                "SHADOW_LOCAL_RESTORE_MAXIMUM_SECONDS": "0",
            },
            clear=True,
        ):
            self.assertEqual(
                "postgresql://user@127.0.0.1/test",
                _local_database_url("SHADOW_TEST_POSTGRESQL_URL"),
            )
            with self.assertRaisesRegex(DomainError, "positive"):
                _positive_int("SHADOW_LOCAL_RESTORE_MAXIMUM_SECONDS", 300)

    def test_cli_schema_generation_matches_route_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            generate_schemas(output)
            openapi = json.loads((output / "api/openapi.json").read_text(encoding="utf-8"))
            raw_event = json.loads(
                (output / "events/raw-signal-event-v1.json").read_text(encoding="utf-8")
            )
            self.assertIn("/api/v1/auth/config", openapi["paths"])
            self.assertFalse(raw_event["additionalProperties"])
            self.assertEqual(1, raw_event["properties"]["ingest_version"]["const"])

    def test_maintenance_worker_expires_and_recovers_stale_claims(self) -> None:
        database = store()
        run = RunOrchestrator(database).create(actor("Engineer"), manifest(), "worker-run")
        now = dt.datetime.now(dt.UTC)
        old = (now - dt.timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        expired = (now - dt.timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        database.execute(
            """INSERT INTO approvals
               (approval_id, run_id, workspace_id, plan_hash, simulator_digest,
                request_json, state, version, expires_at, created_at, updated_at)
               VALUES (?, ?, 'w1', ?, ?, '{}', 'PENDING', 1, ?, ?, ?)""",
            ("approval-worker", run["run_id"], "p" * 64, "s" * 64, expired, old, old),
        )
        database.execute(
            """INSERT INTO action_executions
               (action_id, run_id, approval_id, plan_hash, idempotency_key, state,
                request_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, 'STARTED', '{}', ?, ?)""",
            ("action-worker", run["run_id"], "approval-worker", "p" * 64, "worker-key", old, old),
        )
        worker = MaintenanceWorker(database)
        self.assertEqual(
            {"expired_approvals": 1, "interrupted_actions": 1}, worker.tick()
        )
        self.assertEqual("EXPIRED", database.query("SELECT state FROM approvals")[0]["state"])
        self.assertEqual(
            "RECOVERY_REQUIRED", database.query("SELECT state FROM action_executions")[0]["state"]
        )
        worker.stop()
        self.assertFalse(worker.running)
        database.close()

    def test_encrypted_spool_round_trip_idempotency_and_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "spool.db"
            with EncryptedSpool(path, b"k" * 32, 512) as spool:
                digest = spool.append(1, b"signed-edge-batch")
                self.assertEqual(digest, spool.append(1, b"signed-edge-batch"))
                self.assertEqual([(1, b"signed-edge-batch", digest)], list(spool.pending()))
                with self.assertRaisesRegex(DomainError, "another payload"):
                    spool.append(1, b"tampered")
                with self.assertRaisesRegex(DomainError, "another sequence"):
                    spool.append(2, b"signed-edge-batch")
                self.assertEqual(1, spool.acknowledge_through(1))
                self.assertEqual([], list(spool.pending()))
            with (
                EncryptedSpool(path, b"k" * 32, 64) as bounded,
                self.assertRaisesRegex(DomainError, "bounded capacity"),
            ):
                bounded.append(1, b"x" * 40)
        with self.assertRaisesRegex(DomainError, "AES-GCM"):
            EncryptedSpool(":memory:", b"short", 512)

    async def test_action_service_fails_closed_before_simulator_call(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "SHADOW_ENVIRONMENT": "test",
                "SHADOW_DATABASE_URL": f"sqlite:///{Path(directory) / 'action.db'}",
                "SHADOW_SIMULATOR_URL": "http://simulator.invalid",
                "SHADOW_SIMULATOR_DIGEST": "d" * 64,
                "SHADOW_INTERNAL_SERVICE_TOKEN": "service-token-contains-at-least-32-characters",
            },
            clear=False,
        ):
            from shadow_sandbox.action_api import create_app

            app = create_app()
            transport = httpx.ASGITransport(app=app)
            async with app.router.lifespan_context(app), httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                unauthorized = await client.get("/internal/v1/health")
                self.assertEqual(401, unauthorized.status_code)
                invalid = await client.post(
                    "/internal/v1/actions",
                    headers={
                        "X-Internal-Token": "service-token-contains-at-least-32-characters"
                    },
                    json={"unexpected": True},
                )
                self.assertEqual(400, invalid.status_code)
                self.assertEqual(
                    "urn:industrial-shadow:problem:action_request_invalid",
                    invalid.json()["type"],
                )


class CollectorAndOtProbeTests(unittest.TestCase):
    def test_collector_configuration_is_complete_and_structured(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(DomainError) as caught:
                asyncio.run(collect())
            self.assertEqual("COLLECTOR_CONFIGURATION_MISSING", caught.exception.code)
            self.assertIn("SHADOW_NODE_ALLOWLIST", caught.exception.context["missing"])

        fake_asyncua = types.ModuleType("asyncua")
        fake_asyncua.Client = object  # type: ignore[attr-defined]
        environment = {
            "SHADOW_ENDPOINT_URI": "opc.tcp://ot.example:4840",
            "SHADOW_APPLICATION_URI": "urn:ot:server",
            "SHADOW_CERTIFICATE_FINGERPRINT": "a" * 64,
            "SHADOW_NAMESPACE_URI": "urn:ot:namespace",
            "SHADOW_NODE_ALLOWLIST": "[]",
            "SHADOW_TRUSTED_RUN_CONTEXT": "{}",
        }
        with patch.dict(os.environ, environment, clear=True), patch.dict(
            sys.modules, {"asyncua": fake_asyncua}
        ):
            with self.assertRaises(DomainError) as caught:
                asyncio.run(collect())
            self.assertEqual("COLLECTOR_NODE_ALLOWLIST_INVALID", caught.exception.code)

    def test_readonly_ot_probe_checks_real_endpoint_identity_and_subscription(self) -> None:
        certificate = b"pinned-endpoint-certificate"
        fingerprint = hashlib.sha256(certificate).hexdigest()
        application_uri = "urn:industrial-shadow:test-server"
        namespace_uri = "urn:industrial-shadow:test-namespace"
        node_ids = ("ns=2;s=Tank.Level", "ns=2;s=Pump.Speed")

        class GoodStatus:
            @staticmethod
            def is_good() -> bool:
                return True

        class FakeNode:
            def __init__(self, node_id: str) -> None:
                self.nodeid = SimpleNamespace(to_string=lambda: node_id)

            async def read_data_value(self) -> object:
                return SimpleNamespace(
                    StatusCode=GoodStatus(),
                    SourceTimestamp=dt.datetime.now(dt.UTC),
                    ServerTimestamp=dt.datetime.now(dt.UTC),
                )

        class FakeSubscription:
            def __init__(self, handler: object) -> None:
                self.handler = handler
                self.deleted = False

            async def subscribe_data_change(self, nodes: list[FakeNode]) -> list[int]:
                for node in nodes:
                    self.handler.datachange_notification(node, 1.0, object())
                return list(range(1, len(nodes) + 1))

            async def unsubscribe(self, handles: list[int]) -> None:
                self.handles = handles

            async def delete(self) -> None:
                self.deleted = True

        endpoint = SimpleNamespace(
            Server=SimpleNamespace(
                ApplicationUri=application_uri
            ),
            ServerCertificate=certificate,
            SecurityMode="MessageSecurityMode.SignAndEncrypt",
            SecurityPolicyUri="http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256",
        )

        class FakeClient:
            def __init__(self, url: str) -> None:
                self.url = url
                self.nodes = SimpleNamespace(
                    objects=SimpleNamespace(get_children=self.get_children)
                )

            async def set_security_string(self, value: str) -> None:
                self.security = value

            async def connect_and_get_server_endpoints(self) -> list[object]:
                return [endpoint]

            async def __aenter__(self) -> Self:
                return self

            async def __aexit__(self, *_args: object) -> None:
                return None

            async def get_namespace_array(self) -> list[str]:
                return ["http://opcfoundation.org/UA/", namespace_uri]

            async def get_children(self) -> list[int]:
                return [1]

            def get_node(self, node_id: str) -> FakeNode:
                return FakeNode(node_id)

            async def create_subscription(
                self, _interval: int, handler: object
            ) -> FakeSubscription:
                return FakeSubscription(handler)

        fake_asyncua = types.ModuleType("asyncua")
        fake_asyncua.Client = FakeClient  # type: ignore[attr-defined]

        async def immediate_sleep(_seconds: float) -> None:
            return None

        probe = ReadonlyOpcUaProbe(
            endpoint_uri="opc.tcp://ot.example:4840",
            application_uri=application_uri,
            namespace_uri=namespace_uri,
            certificate_fingerprint=fingerprint,
            node_ids=node_ids,
            security_string="Basic256Sha256,SignAndEncrypt,client.pem,client-key.pem",
            observation_seconds=5,
        )
        with patch.dict(sys.modules, {"asyncua": fake_asyncua}), patch(
            "shadow_sandbox.operations.opcua_probe.asyncio.sleep", immediate_sleep
        ):
            evidence = asyncio.run(probe.run())
        self.assertEqual("PASSED", evidence.status)
        self.assertEqual(len(node_ids), evidence.metrics["notifications"])
        self.assertEqual((), tuple(check.name for check in evidence.checks if not check.passed))

    def test_ot_probe_rejects_write_capable_or_unpinned_profiles(self) -> None:
        arguments = {
            "endpoint_uri": "opc.tcp://ot.example:4840",
            "application_uri": "urn:server",
            "namespace_uri": "urn:namespace",
            "certificate_fingerprint": "a" * 64,
            "node_ids": ("ns=2;s=Level",),
            "security_string": "Basic256Sha256,None,client.pem,client-key.pem",
        }
        with self.assertRaises(DomainError) as caught:
            ReadonlyOpcUaProbe(**arguments)
        self.assertEqual("OPCUA_SECURITY_REQUIRED", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
