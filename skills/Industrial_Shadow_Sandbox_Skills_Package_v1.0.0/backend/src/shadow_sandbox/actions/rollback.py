from shadow_simulator.snapshot import SnapshotService


def restore_pre_action(snapshots: SnapshotService, engine, snapshot_id: str) -> None:
    snapshots.restore(engine, snapshot_id)
