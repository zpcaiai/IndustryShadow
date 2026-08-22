from __future__ import annotations

import pytest

from tools.build_evidence import (
    ansi_stripped_metric_count,
    normalize_log_output,
    redacted_diagnostic_tail,
)


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


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        (
            "first line  \ninternal  spaces\tstay \t\nblank\t \n",
            "first line\ninternal  spaces\tstay\nblank\n",
        ),
        (
            "\x1b[32mBuildKit  step\x1b[0m \t\r\nsecond\tline\t\r\n",
            "\x1b[32mBuildKit  step\x1b[0m\r\nsecond\tline\r\n",
        ),
        (
            "no final newline with  internal spaces \t",
            "no final newline with  internal spaces",
        ),
        ("already-clean\n", "already-clean\n"),
    ],
)
def test_normalize_log_output_only_removes_line_ending_spaces_and_tabs(
    output: str, expected: str
) -> None:
    normalized = normalize_log_output(output)

    assert normalized == expected
    assert normalized.count("\n") == output.count("\n")
    assert normalized.count("\r") == output.count("\r")


def test_ansi_stripped_metric_count_handles_exact_vitest_fragmentation() -> None:
    vitest_output = (
        "\x1b[2m      Tests \x1b[22m \x1b[1m\x1b[32m26 passed"
        "\x1b[39m\x1b[22m\x1b[90m (26)\x1b[39m\n"
    )

    assert ansi_stripped_metric_count(vitest_output, r"Tests\s+(\d+)\s+passed") == 26
    assert "\x1b[32m" in vitest_output


@pytest.mark.parametrize(
    ("output", "pattern", "expected"),
    [
        ("\x1b[32m182\x1b[0m passed, \x1b[33m3\x1b[0m skipped", r"(\d+)\s+passed", 182),
        ("\x1b[32m182\x1b[0m passed, \x1b[33m3\x1b[0m skipped", r"(\d+)\s+skipped", 3),
        ("\x1b[?25l\x1b[2K47 passed\x1b[?25h", r"(\d+)\s+passed", 47),
        ("no test summary", r"(\d+)\s+passed", 0),
    ],
)
def test_ansi_stripped_metric_count_handles_pytest_and_browser_summaries(
    output: str, pattern: str, expected: int
) -> None:
    assert ansi_stripped_metric_count(output, pattern) == expected
