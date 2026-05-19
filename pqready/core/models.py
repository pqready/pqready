"""Shared data models for pqready scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Finding severity, ordered roughly by quantum-era urgency."""

    CRITICAL = "critical"  # quantum-vulnerable NOW (RSA/EC in active use)
    HIGH = "high"          # weak params or legacy TLS
    MEDIUM = "medium"      # deprecated but not immediately exploitable
    LOW = "low"            # informational / best-practice gap
    INFO = "info"          # PQC-ready or neutral finding


class FindingCategory(str, Enum):
    """High-level grouping for findings, used by reporters."""

    TLS_CIPHER = "tls_cipher"
    TLS_VERSION = "tls_version"
    TLS_CERT = "tls_cert"
    TLS_PQC = "tls_pqc"
    SOURCE_IMPORT = "source_import"
    SOURCE_USAGE = "source_usage"
    CERT_FILE = "cert_file"


@dataclass
class Finding:
    """A single finding produced by a scanner."""

    id: str
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    location: str
    evidence: str
    remediation: str
    nist_ref: str
    pqc_ready: bool = False


@dataclass
class ScanResult:
    """Result of scanning one target (endpoint, file, or directory entry)."""

    target: str
    scan_type: str  # "tls" | "source" | "cert"
    findings: list[Finding] = field(default_factory=list)
    scanned_at: str = ""
    duration_ms: int = 0
    error: str | None = None

    @property
    def risk_score(self) -> int:
        """0-100 composite risk score."""
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH: 20,
            Severity.MEDIUM: 10,
            Severity.LOW: 5,
            Severity.INFO: 0,
        }
        raw = sum(weights[f.severity] for f in self.findings)
        return min(raw, 100)

    @property
    def pqc_ready(self) -> bool:
        """True if no CRITICAL or HIGH findings are present."""
        return not any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings
        )
