"""Tests for pqready.core.models."""

from __future__ import annotations

from pqready.core.models import Finding, FindingCategory, ScanResult, Severity


def _f(severity: Severity, fid: str = "TLS-001") -> Finding:
    return Finding(
        id=fid,
        category=FindingCategory.TLS_CIPHER,
        severity=severity,
        title="t",
        description="d",
        location="loc",
        evidence="e",
        remediation="r",
        nist_ref="ref",
    )


def test_empty_result_is_pqc_ready_and_zero_score():
    r = ScanResult(target="x", scan_type="tls")
    assert r.risk_score == 0
    assert r.pqc_ready is True


def test_score_sums_per_severity_weights():
    r = ScanResult(
        target="x",
        scan_type="tls",
        findings=[
            _f(Severity.CRITICAL),  # 40
            _f(Severity.HIGH),      # 20
            _f(Severity.MEDIUM),    # 10
            _f(Severity.LOW),       # 5
            _f(Severity.INFO),      # 0
        ],
    )
    assert r.risk_score == 75


def test_score_is_capped_at_100():
    r = ScanResult(
        target="x",
        scan_type="tls",
        findings=[_f(Severity.CRITICAL) for _ in range(10)],  # 400 raw
    )
    assert r.risk_score == 100


def test_pqc_ready_false_on_any_critical_or_high():
    crit = ScanResult(target="x", scan_type="tls", findings=[_f(Severity.CRITICAL)])
    high = ScanResult(target="x", scan_type="tls", findings=[_f(Severity.HIGH)])
    assert crit.pqc_ready is False
    assert high.pqc_ready is False


def test_pqc_ready_true_on_only_medium_low_info():
    r = ScanResult(
        target="x",
        scan_type="tls",
        findings=[
            _f(Severity.MEDIUM),
            _f(Severity.LOW),
            _f(Severity.INFO),
        ],
    )
    assert r.pqc_ready is True


def test_severity_string_values_are_stable():
    # The HTML report and MCP responses depend on these string values.
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_finding_category_string_values_are_stable():
    assert FindingCategory.TLS_PQC.value == "tls_pqc"
    assert FindingCategory.SOURCE_IMPORT.value == "source_import"
    assert FindingCategory.CERT_FILE.value == "cert_file"
