from __future__ import annotations

import asyncio
import importlib.util
import socket
import tempfile
import unittest
from pathlib import Path

from shadow_sandbox.asset_registry import pump_tank_model
from shadow_sandbox.common import DomainError
from shadow_simulator import ProcessCommand, SimulatorEngine
from shadow_simulator.faults import FaultRuntime, FaultSpec
from shadow_simulator.opcua import (
    AsyncUaSimulatorServer,
    OpcUaServerConfig,
    VirtualOpcUaServer,
)
from shadow_simulator.snapshot import SnapshotService
from test_foundation import store


class SimulatorTests(unittest.TestCase):
    def test_deterministic_and_metamorphic(self) -> None:
        model = pump_tank_model()
        first = SimulatorEngine(asset_model_digest=model.digest, seed=7)
        second = SimulatorEngine(asset_model_digest=model.digest, seed=7)
        a = first.run_until(5, ProcessCommand(pump_speed_rpm=1200))
        b = second.run_until(5, ProcessCommand(pump_speed_rpm=1200))
        self.assertEqual(
            [frame.frame_digest for frame in a], [frame.frame_digest for frame in b]
        )
        fast = SimulatorEngine(asset_model_digest=model.digest, seed=7)
        fast_frames = fast.run_until(5, ProcessCommand(pump_speed_rpm=3000))
        self.assertGreater(
            float(fast_frames[-1].true_values["Tank101.InletFlow"]),
            float(a[-1].true_values["Tank101.InletFlow"]),
        )

    def test_snapshot_restore_reproduces_future_frames(self) -> None:
        model = pump_tank_model()
        engine = SimulatorEngine(asset_model_digest=model.digest, seed=13)
        engine.run_until(2)
        database = store()
        with tempfile.TemporaryDirectory() as directory:
            snapshots = SnapshotService(database, directory)
            snapshot = snapshots.create("sim-1", engine, "test")
            expected = [frame.frame_digest for frame in engine.run_until(4)]
            snapshots.restore(engine, snapshot.snapshot_id)
            actual = [frame.frame_digest for frame in engine.run_until(4)]
        self.assertEqual(expected, actual)

    def test_sensor_fault_does_not_corrupt_true_state(self) -> None:
        model = pump_tank_model()
        runtime = FaultRuntime(
            [FaultSpec("sensor_bias", "Tank101.Level", "bias", 0, 2, {"value": 2.0})]
        )
        engine = SimulatorEngine(
            asset_model_digest=model.digest, fault_runtime=runtime, seed=1
        )
        frame = engine.step()
        difference = float(frame.observed_values["Tank101.Level"]) - float(
            frame.true_values["Tank101.Level"]
        )
        self.assertGreater(difference, 1.9)

    def test_multiplier_fault_applies_immediately_not_as_a_ramp(self) -> None:
        model = pump_tank_model()
        runtime = FaultRuntime(
            [
                FaultSpec(
                    "efficiency",
                    "Process.PumpEfficiency",
                    "multiplier",
                    0,
                    None,
                    {"value": 0.5},
                )
            ]
        )
        engine = SimulatorEngine(
            asset_model_digest=model.digest, fault_runtime=runtime, seed=2
        )
        frame = engine.step(
            ProcessCommand(pump_speed_rpm=3600, inlet_valve_percent=100)
        )
        self.assertAlmostEqual(
            float(frame.true_values["Tank101.InletFlow"]),
            engine.parameters.pump_max_flow_m3s
            * (engine.state.pump_speed_rpm / 3600)
            * (engine.state.inlet_valve_percent / 100)
            * 0.5,
        )

    def test_virtual_opcua_enforces_shadow_read_only(self) -> None:
        model = pump_tank_model()
        engine = SimulatorEngine(asset_model_digest=model.digest)
        server = VirtualOpcUaServer(model, engine)
        frame = engine.step()
        server.publish(frame)
        command = next(
            signal for signal in model.signals if signal.key == "Pump101.SpeedCommand"
        )
        with self.assertRaises(DomainError) as caught:
            server.write("shadow", command.node_id, 1000)
        self.assertEqual("OPCUA_WRITE_DENIED", caught.exception.code)
        server.write("simulator_operator", command.node_id, 1000)
        self.assertEqual(1000, engine.last_command.pump_speed_rpm)
        with self.assertRaises(DomainError):
            server.call("shadow", "anything", [])

    @unittest.skipUnless(importlib.util.find_spec("asyncua"), "asyncua not installed")
    def test_network_opcua_is_read_only_to_an_independent_client(self) -> None:
        async def exercise() -> None:
            from asyncua import Client, ua

            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = int(reservation.getsockname()[1])
            model = pump_tank_model()
            engine = SimulatorEngine(asset_model_digest=model.digest)
            server = AsyncUaSimulatorServer(
                model,
                engine,
                OpcUaServerConfig(
                    endpoint=f"opc.tcp://127.0.0.1:{port}/shadow",
                    allow_insecure_development=True,
                ),
            )
            await server.start()
            try:
                frame = engine.step()
                await server.publish(frame)
                async with Client(server.config.endpoint) as client:
                    node = client.get_node(
                        ua.NodeId.from_string(
                            f"ns={server.namespace_index};s=Pump101.SpeedActual"
                        )
                    )
                    self.assertAlmostEqual(
                        float(await node.read_value()),
                        float(frame.observed_values["Pump101.SpeedActual"]),
                    )
                    with self.assertRaises(ua.UaStatusCodeError):
                        await node.write_value(123.0)
            finally:
                await server.stop()

        asyncio.run(asyncio.wait_for(exercise(), timeout=30))

    @unittest.skipUnless(importlib.util.find_spec("asyncua"), "asyncua not installed")
    def test_secure_network_opcua_uses_pinned_client_certificate(self) -> None:
        async def exercise() -> None:
            from asyncua import Client, ua
            from asyncua.crypto.cert_gen import setup_self_signed_certificate
            from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            from cryptography.x509.oid import ExtendedKeyUsageOID

            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                server_key, server_certificate = (
                    root / "server.pem",
                    root / "server.der",
                )
                client_key, client_certificate = (
                    root / "client.pem",
                    root / "client.der",
                )
                host = socket.gethostname()
                server_uri = "urn:industrial-shadow:secure-test-server"
                client_uri = "urn:industrial-shadow:secure-test-client"
                await setup_self_signed_certificate(
                    server_key,
                    server_certificate,
                    server_uri,
                    host,
                    [ExtendedKeyUsageOID.SERVER_AUTH],
                    {"organizationName": "Industrial Shadow Test"},
                )
                await setup_self_signed_certificate(
                    client_key,
                    client_certificate,
                    client_uri,
                    host,
                    [ExtendedKeyUsageOID.CLIENT_AUTH],
                    {"organizationName": "Industrial Shadow Test"},
                )
                fingerprint = (
                    x509.load_der_x509_certificate(client_certificate.read_bytes())
                    .fingerprint(hashes.SHA256())
                    .hex()
                )
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = int(reservation.getsockname()[1])
                model = pump_tank_model()
                engine = SimulatorEngine(asset_model_digest=model.digest)
                server = AsyncUaSimulatorServer(
                    model,
                    engine,
                    OpcUaServerConfig(
                        endpoint=f"opc.tcp://127.0.0.1:{port}/shadow",
                        application_uri=server_uri,
                        certificate_path=server_certificate,
                        private_key_path=server_key,
                        trusted_client_fingerprints=frozenset({fingerprint}),
                    ),
                )
                await server.start()
                try:
                    client = Client(server.config.endpoint)
                    client.application_uri = client_uri
                    await client.set_security(
                        SecurityPolicyBasic256Sha256,
                        client_certificate,
                        client_key,
                        server_certificate=server_certificate.read_bytes(),
                    )
                    await client.load_client_certificate(str(client_certificate))
                    await client.load_private_key(client_key)
                    async with client:
                        node = client.get_node(
                            f"ns={server.namespace_index};s=Pump101.SpeedActual"
                        )
                        self.assertEqual(0.0, float(await node.read_value()))
                        with self.assertRaises(ua.UaStatusCodeError):
                            await node.write_value(123.0)
                finally:
                    await server.stop()

        asyncio.run(asyncio.wait_for(exercise(), timeout=60))


if __name__ == "__main__":
    unittest.main()
