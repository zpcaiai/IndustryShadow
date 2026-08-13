from __future__ import annotations

import hashlib
import unittest

from shadow_collector.buffer import BoundedBuffer
from shadow_collector.client import CollectorPolicy, ReadonlySubscriptionClient
from shadow_collector.models import RawSignalNormalizer
from shadow_collector.writer import RawEventWriter
from shadow_sandbox.asset_registry import pump_tank_model
from shadow_sandbox.common import DomainError
from shadow_sandbox.runtime import RunOrchestrator
from shadow_simulator import SimulatorEngine
from shadow_simulator.opcua import VirtualOpcUaServer
from test_foundation import actor, manifest, store


class CollectorTests(unittest.TestCase):
    def test_subscribe_normalize_and_persist_without_control_surface(self) -> None:
        database = store()
        created = RunOrchestrator(database).create(
            actor("Engineer"), manifest(), "collector-run"
        )
        model = pump_tank_model()
        engine = SimulatorEngine(asset_model_digest=model.digest)
        server = VirtualOpcUaServer(model, engine)
        fingerprint = hashlib.sha256(b"development-certificate").hexdigest()
        policy = CollectorPolicy(
            "simulator",
            "opc.tcp://simulator:4840",
            server.application_uri,
            fingerprint,
            server.namespace_uri,
            ("nsu=urn:industrial-shadow:pump-tank;s=",),
        )
        client = ReadonlySubscriptionClient(policy, server)
        client.connect(
            application_uri=server.application_uri,
            certificate_fingerprint=fingerprint,
            namespace_uri=server.namespace_uri,
        )
        signal = next(item for item in model.signals if item.key == "Tank101.Level")
        normalizer = RawSignalNormalizer({signal.key: 500})
        received = []
        context = {
            "tenant_id": "t1",
            "workspace_id": "w1",
            "run_id": created["run_id"],
            "scenario_id": "normal",
            "endpoint_id": "sim-1",
        }
        client.subscribe(
            [signal.node_id],
            lambda item: received.append(
                normalizer.normalize(trusted_context=context, notification=item)
            ),
        )
        server.publish(engine.step())
        self.assertEqual(1, len(received))
        self.assertEqual(1, RawEventWriter(database).persist(received))
        self.assertEqual(0, RawEventWriter(database).persist(received))
        self.assertEqual(
            1, len(RawEventWriter(database).query(created["run_id"], signal.key))
        )
        self.assertFalse(hasattr(client, "write"))
        self.assertFalse(hasattr(client, "call"))

    def test_policy_and_backpressure_fail_closed(self) -> None:
        buffer = BoundedBuffer[int](2)
        buffer.put(1)
        buffer.put(2)
        with self.assertRaises(DomainError) as caught:
            buffer.put(3)
        self.assertEqual("COLLECTOR_BACKPRESSURE", caught.exception.code)
        policy = CollectorPolicy(
            "simulator", "x", "a", "f", "n", ("safe:",), maximum_nodes=1
        )
        with self.assertRaises(DomainError):
            policy.validate_nodes(["unsafe:1"])


if __name__ == "__main__":
    unittest.main()
