"""Source-code scanner for quantum-vulnerable cryptography usage."""

from __future__ import annotations

import ast
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path

from .models import Finding, FindingCategory, ScanResult, Severity

_MAX_FILE_BYTES = 1 * 1024 * 1024  # 1 MB

_PY_SUFFIXES = {".py"}
_CONFIG_SUFFIXES = {".yml", ".yaml", ".env", ".conf", ".toml", ".ini", ".cfg"}
_SCAN_SUFFIXES = _PY_SUFFIXES | _CONFIG_SUFFIXES

_SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}

# SRC-006 / SRC-007 regex patterns. Compiled once.
_CONFIG_RSA = re.compile(r"\b(RSA|rsa)\b")
_CONFIG_AES_CBC = re.compile(r"\bAES[-_]128[-_]CBC\b", re.IGNORECASE)
_OPEN_PEM = re.compile(
    r"""open\s*\(\s*['"][^'"]*\.(?:pem|crt|key|cer)['"]""", re.IGNORECASE
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def scan_source(path: str) -> list[ScanResult]:
    """Scan a file or directory tree for vulnerable cryptography patterns.

    Returns one ``ScanResult`` per file scanned (including files with no findings,
    so callers can see what was inspected).
    """

    root = Path(path)
    if not root.exists():
        return [
            ScanResult(
                target=str(root),
                scan_type="source",
                findings=[],
                scanned_at=_now_iso(),
                duration_ms=0,
                error=f"path does not exist: {root}",
            )
        ]

    results: list[ScanResult] = []
    for file_path in _iter_files(root):
        results.append(_scan_file(file_path))
    return results


def _iter_files(root: Path):
    if root.is_file():
        yield root
        return

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in place so os.walk doesn't descend into them.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIR_NAMES]
        for name in filenames:
            suffix = Path(name).suffix.lower()
            if suffix in _SCAN_SUFFIXES:
                yield Path(dirpath) / name


def _scan_file(path: Path) -> ScanResult:
    started = time.monotonic()
    result = ScanResult(
        target=str(path),
        scan_type="source",
        findings=[],
        scanned_at=_now_iso(),
    )

    try:
        size = path.stat().st_size
    except OSError as exc:
        result.error = f"stat failed: {exc}"
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    if size > _MAX_FILE_BYTES:
        result.error = f"file too large ({size} bytes); skipped"
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        result.error = "binary or unreadable file; skipped"
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    suffix = path.suffix.lower()
    if suffix in _PY_SUFFIXES:
        result.findings.extend(_scan_python(path, text))
    if suffix in _CONFIG_SUFFIXES:
        result.findings.extend(_scan_config(path, text))

    # SRC-007 applies to any text source that opens a key/cert file.
    result.findings.extend(_scan_open_pem(path, text))

    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def _scan_python(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ast.parse(text, filename=str(path))
    except SyntaxError:
        # Fall back to regex on unparseable files; do not fail the whole scan.
        return _scan_python_regex_fallback(path, text)

    visitor = _CryptoVisitor(path)
    visitor.visit(tree)
    findings.extend(visitor.findings)
    return findings


class _CryptoVisitor(ast.NodeVisitor):
    """AST visitor that flags vulnerable crypto usage in Python code."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[Finding] = []

    # SRC-001: PyCrypto / PyCryptodome
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "Crypto" or alias.name.startswith("Crypto."):
                self.findings.append(self._pycrypto(node, f"import {alias.name}"))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if module == "Crypto" or module.startswith("Crypto."):
            names = ", ".join(a.name for a in node.names)
            self.findings.append(self._pycrypto(node, f"from {module} import {names}"))

        # SRC-002: cryptography RSA primitives
        if module == "cryptography.hazmat.primitives.asymmetric" and any(
            a.name == "rsa" for a in node.names
        ):
            self.findings.append(
                Finding(
                    id="SRC-002",
                    category=FindingCategory.SOURCE_IMPORT,
                    severity=Severity.HIGH,
                    title="RSA primitives imported",
                    description=(
                        "Code imports the RSA module from `cryptography`. RSA is "
                        "quantum-vulnerable; any new uses should be on a migration "
                        "path to ML-KEM / ML-DSA."
                    ),
                    location=f"{self.path}:{node.lineno}",
                    evidence=f"from {module} import rsa",
                    remediation=(
                        "Audit RSA call sites; plan migration to FIPS 203 / 204."
                    ),
                    nist_ref="FIPS 204 (ML-DSA)",
                )
            )

        # SRC-004: ec import line (catches `from ... import ec`)
        if module == "cryptography.hazmat.primitives.asymmetric" and any(
            a.name == "ec" for a in node.names
        ):
            self.findings.append(
                Finding(
                    id="SRC-004",
                    category=FindingCategory.SOURCE_IMPORT,
                    severity=Severity.HIGH,
                    title="Elliptic-curve primitives imported",
                    description=(
                        "Elliptic-curve cryptography is quantum-vulnerable. Plan "
                        "migration to ML-KEM for KEX and ML-DSA for signatures."
                    ),
                    location=f"{self.path}:{node.lineno}",
                    evidence=f"from {module} import ec",
                    remediation="Identify EC call sites and plan PQC migration.",
                    nist_ref="FIPS 203 / FIPS 204",
                )
            )
        self.generic_visit(node)

    # SRC-003 & SRC-004 (call sites) & SRC-005
    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node)

        # SRC-003: RSA.generate(bits < 3072)
        if name.endswith("RSA.generate") or name == "RSA.generate":
            bits = _first_int_arg(node)
            if bits is not None and bits < 3072:
                self.findings.append(
                    Finding(
                        id="SRC-003",
                        category=FindingCategory.SOURCE_USAGE,
                        severity=Severity.CRITICAL,
                        title=f"RSA.generate() called with {bits}-bit key",
                        description=(
                            "RSA key generation below 3072 bits is unsafe today and "
                            "completely defeated by a future quantum adversary."
                        ),
                        location=f"{self.path}:{node.lineno}",
                        evidence=f"RSA.generate({bits})",
                        remediation=(
                            "Raise to ≥ 3072 bits as an interim step; plan migration "
                            "to ML-KEM (KEX) and ML-DSA (signatures)."
                        ),
                        nist_ref="FIPS 186-5 / FIPS 204",
                    )
                )

        # SRC-004: ec.generate_private_key(...) or EllipticCurvePrivateKey(...)
        if (
            name.endswith("ec.generate_private_key")
            or name.endswith("EllipticCurvePrivateKey")
        ):
            self.findings.append(
                Finding(
                    id="SRC-004",
                    category=FindingCategory.SOURCE_USAGE,
                    severity=Severity.HIGH,
                    title="Elliptic-curve key generated",
                    description=(
                        "EC keys are quantum-vulnerable. Track this call site for "
                        "PQC migration."
                    ),
                    location=f"{self.path}:{node.lineno}",
                    evidence=f"{name}(...)",
                    remediation="Plan migration to ML-DSA / ML-KEM.",
                    nist_ref="FIPS 203 / FIPS 204",
                )
            )

        # SRC-005: hashlib.md5(...) / hashlib.sha1(...)
        if name in ("hashlib.md5", "hashlib.sha1"):
            algo = name.split(".", 1)[1].upper()
            self.findings.append(
                Finding(
                    id="SRC-005",
                    category=FindingCategory.SOURCE_USAGE,
                    severity=Severity.MEDIUM,
                    title=f"Use of broken hash algorithm: {algo}",
                    description=(
                        f"{algo} is collision-broken (and pre-image weak for MD5). "
                        "Independent of PQC, this should be replaced."
                    ),
                    location=f"{self.path}:{node.lineno}",
                    evidence=name,
                    remediation="Use SHA-256 or SHA-3 family hashes.",
                    nist_ref="NIST SP 800-131A Rev. 2",
                )
            )

        self.generic_visit(node)

    def _pycrypto(self, node: ast.AST, evidence: str) -> Finding:
        return Finding(
            id="SRC-001",
            category=FindingCategory.SOURCE_IMPORT,
            severity=Severity.HIGH,
            title="PyCrypto / PyCryptodome import",
            description=(
                "Code depends on the `Crypto` package. PyCrypto is unmaintained; "
                "PyCryptodome is fine for legacy use but its RSA/ECC code is "
                "quantum-vulnerable. Use this signal to scope a PQC migration."
            ),
            location=f"{self.path}:{getattr(node, 'lineno', 0)}",
            evidence=evidence,
            remediation=(
                "Migrate to `cryptography` and plan a path to FIPS 203 / 204."
            ),
            nist_ref="FIPS 203 / FIPS 204",
        )


def _call_name(node: ast.Call) -> str:
    """Best-effort dotted name for a Call node, e.g. ``hashlib.md5``."""
    parts: list[str] = []
    cur: ast.AST = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _first_int_arg(node: ast.Call) -> int | None:
    for arg in node.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, int):
            return arg.value
    for kw in node.keywords:
        if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
            return kw.value.value
    return None


def _scan_python_regex_fallback(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if "from Crypto" in line or "import Crypto" in line:
            findings.append(
                Finding(
                    id="SRC-001",
                    category=FindingCategory.SOURCE_IMPORT,
                    severity=Severity.HIGH,
                    title="PyCrypto / PyCryptodome import (regex fallback)",
                    description="File could not be parsed by AST; matched via regex.",
                    location=f"{path}:{i}",
                    evidence=line.strip(),
                    remediation="Migrate to `cryptography` and plan PQC migration.",
                    nist_ref="FIPS 203 / FIPS 204",
                )
            )
    return findings


def _scan_config(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if _CONFIG_RSA.search(line) or _CONFIG_AES_CBC.search(line):
            findings.append(
                Finding(
                    id="SRC-006",
                    category=FindingCategory.SOURCE_USAGE,
                    severity=Severity.LOW,
                    title="Hardcoded weak cipher identifier in config",
                    description=(
                        "Config references RSA or AES-128-CBC. Worth reviewing — "
                        "these may pin code paths that block a future PQC upgrade."
                    ),
                    location=f"{path}:{i}",
                    evidence=line.strip()[:160],
                    remediation=(
                        "Prefer AES-GCM / ChaCha20-Poly1305; document RSA usage in "
                        "your PQC migration plan."
                    ),
                    nist_ref="NIST SP 800-131A Rev. 2",
                )
            )
    return findings


def _scan_open_pem(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), start=1):
        if _OPEN_PEM.search(line):
            findings.append(
                Finding(
                    id="SRC-007",
                    category=FindingCategory.SOURCE_USAGE,
                    severity=Severity.LOW,
                    title="Reference to certificate/key file via open()",
                    description=(
                        "Source code opens a .pem/.crt/.key/.cer file. Inventory "
                        "this key material — it will need rotation when migrating "
                        "to ML-DSA-signed certificates."
                    ),
                    location=f"{path}:{i}",
                    evidence=line.strip()[:160],
                    remediation="Add this file to your key-material inventory.",
                    nist_ref="FIPS 204 (ML-DSA)",
                )
            )
    return findings
