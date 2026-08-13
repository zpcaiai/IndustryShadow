from shadow_sandbox.common import DomainError


def read_parquet(path):
    try:
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise DomainError("PARQUET_DEPENDENCY_UNAVAILABLE", "PyArrow required", status=503) from exc
    for batch in pq.ParquetFile(path).iter_batches(batch_size=4096):
        yield from batch.to_pylist()
