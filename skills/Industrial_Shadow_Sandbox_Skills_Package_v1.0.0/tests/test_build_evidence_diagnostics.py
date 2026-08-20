from __future__ import annotations

from tools.build_evidence import redacted_diagnostic_tail


def test_redacted_diagnostic_tail_removes_environment_and_uri_credentials(
    monkeypatch,
) -> None:
    configured_url = "postgresql+psycopg://shadow_test:configured-password@127.0.0.1/db"
    monkeypatch.setenv("SHADOW_TEST_POSTGRESQL_URL", configured_url)
    output = (
        f"configured={configured_url}\n"
        "fallback=postgresql://other-user:other-password@example.test/db\n"
        "diagnostic=RESTORE_CATALOG_MISMATCH\n"
    )

    redacted = redacted_diagnostic_tail(output, maximum_characters=512)

    assert configured_url not in redacted
    assert "configured-password" not in redacted
    assert "other-password" not in redacted
    assert "<redacted>" in redacted
    assert "RESTORE_CATALOG_MISMATCH" in redacted
    assert len(redacted) <= 512
