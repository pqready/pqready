"""Certificate-file scanner for PEM / DER / CRT / CER / KEY material."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_pem_private_key,
)

from .models import Finding, FindingCategory, ScanResult, Severity


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def scan_cert_file(path: str) -> ScanResult:
    """Parse and assess a PEM/DER/CRT/CER/KEY file on disk."""

    started = time.monotonic()
    p = Path(path)
    result = ScanResult(target=str(p), scan_type="cert", scanned_at=_now_iso())

    if not p.exists():
        result.error = f"file does not exist: {p}"
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    try:
        data = p.read_bytes()
    except OSError as exc:
        result.error = f"read failed: {exc}"
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    cert = _try_load_certificate(data)
    if cert is not None:
        result.findings.extend(_assess_certificate(cert, str(p)))
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    pubkey = _try_load_public_key_via_private(data)
    if pubkey is not None:
        result.findings.extend(_assess_public_key(pubkey, str(p)))
        result.duration_ms = int((time.monotonic() - started) * 1000)
        return result

    result.error = "could not parse file as certificate or private key"
    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def _try_load_certificate(data: bytes):
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            return loader(data)
        except Exception:
            continue
    return None


def _try_load_public_key_via_private(data: bytes):
    for loader in (load_pem_private_key, load_der_private_key):
        try:
            key = loader(data, password=None)
            return key.public_key()
        except Exception:
            continue
    return None


def _assess_certificate(cert, location: str) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_assess_public_key(cert.public_key(), location))
    findings.extend(_assess_validity(cert, location))
    findings.extend(_assess_signature(cert, location))
    return findings


def _assess_public_key(public_key, location: str) -> list[Finding]:
    findings: list[Finding] = []

    if isinstance(public_key, rsa.RSAPublicKey):
        key_size = public_key.key_size
        if key_size < 3072:
            findings.append(
                Finding(
                    id="CERT-004",
                    category=FindingCategory.CERT_FILE,
                    severity=Severity.CRITICAL,
                    title=f"RSA key {key_size}-bit (below 3072)",
                    description=(
                        "Certificate or key file uses RSA below the 3072-bit floor "
                        "recommended for the transition era."
                    ),
                    location=location,
                    evidence=f"RSA-{key_size}",
                    remediation=(
                        "Re-issue with RSA ≥ 3072 bits; plan migration to ML-DSA."
                    ),
                    nist_ref="FIPS 186-5 / FIPS 204",
                )
            )
        else:
            findings.append(
                Finding(
                    id="CERT-006",
                    category=FindingCategory.CERT_FILE,
                    severity=Severity.MEDIUM,
                    title=f"RSA key {key_size}-bit (acceptable, not PQC)",
                    description=(
                        "RSA at this strength is acceptable today but not "
                        "quantum-safe. Plan rotation to a PQC signature scheme."
                    ),
                    location=location,
                    evidence=f"RSA-{key_size}",
                    remediation="Track CA roadmap for ML-DSA (FIPS 204) issuance.",
                    nist_ref="FIPS 204 (ML-DSA)",
                )
            )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        curve_name = public_key.curve.name
        findings.append(
            Finding(
                id="CERT-005",
                category=FindingCategory.CERT_FILE,
                severity=Severity.HIGH,
                title=f"ECC key on {curve_name}",
                description=(
                    "Elliptic-curve keys are quantum-vulnerable. Plan migration "
                    "to ML-DSA for signatures and ML-KEM for KEX."
                ),
                location=location,
                evidence=f"ECC {curve_name}",
                remediation="Schedule migration to ML-DSA (FIPS 204).",
                nist_ref="FIPS 204 (ML-DSA)",
            )
        )
    return findings


def _assess_validity(cert, location: str) -> list[Finding]:
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is None:
        not_after = cert.not_valid_after
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=UTC)

    days_left = (not_after - datetime.now(UTC)).days
    if days_left < 30:
        return [
            Finding(
                id="CERT-008",
                category=FindingCategory.CERT_FILE,
                severity=Severity.HIGH,
                title=f"Certificate expires in {days_left} day(s)",
                description=(
                    "Short-dated certificate. Renew before expiry; also a good "
                    "opportunity to upgrade key parameters."
                ),
                location=location,
                evidence=f"not_after={not_after.isoformat()}",
                remediation="Renew; consider stronger key params during rotation.",
                nist_ref="CA/B Forum BR §6.3.2",
            )
        ]
    return []


def _assess_signature(cert, location: str) -> list[Finding]:
    sig_algo = ""
    hash_obj = getattr(cert, "signature_hash_algorithm", None)
    if hash_obj is not None:
        sig_algo = getattr(hash_obj, "name", "") or ""

    sig_lower = sig_algo.lower()
    if "md5" in sig_lower or "sha1" in sig_lower:
        return [
            Finding(
                id="CERT-009",
                category=FindingCategory.CERT_FILE,
                severity=Severity.CRITICAL,
                title=f"Certificate signed with {sig_algo}",
                description=(
                    "Certificate uses a broken hash for its signature. Trivially "
                    "forgeable; replace immediately."
                ),
                location=location,
                evidence=f"signature_hash={sig_algo}",
                remediation="Re-issue with SHA-256 or stronger.",
                nist_ref="NIST SP 800-131A Rev. 2",
            )
        ]
    return []
