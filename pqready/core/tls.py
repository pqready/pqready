"""TLS endpoint scanner backed by sslyze."""

from __future__ import annotations

import time
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa

from .models import Finding, FindingCategory, ScanResult, Severity

# Weak / quantum-relevant cipher fragments. Matched case-insensitively against
# the cipher suite name.
_WEAK_CIPHER_FRAGMENTS = ("RC4", "3DES", "DES_", "_DES_", "NULL", "EXPORT")

# OpenSSL-style names for the hybrid PQC KEX groups currently being standardised.
_PQC_KEX_NAMES = {
    "x25519mlkem768",
    "x25519kyber768",        # pre-standard name still seen in older deployments
    "secp256r1mlkem768",
    "secp384r1mlkem1024",
}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _error_result(target: str, started: float, message: str) -> ScanResult:
    return ScanResult(
        target=target,
        scan_type="tls",
        findings=[],
        scanned_at=_now_iso(),
        duration_ms=int((time.monotonic() - started) * 1000),
        error=message,
    )


def scan_tls(hostname: str, port: int = 443) -> ScanResult:
    """Scan a single HTTPS endpoint for PQC-relevant TLS weaknesses."""

    started = time.monotonic()
    target = f"{hostname}:{port}"

    try:
        from sslyze import (
            ScanCommand,
            Scanner,
            ServerNetworkLocation,
            ServerScanRequest,
            ServerScanStatusEnum,
        )
    except ImportError as exc:  # pragma: no cover - import guard
        return _error_result(target, started, f"sslyze not installed: {exc}")

    try:
        location = ServerNetworkLocation(hostname=hostname, port=port)
    except Exception as exc:
        return _error_result(target, started, f"invalid target: {exc}")

    scan_commands = {
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.ELLIPTIC_CURVES,
    }

    request = ServerScanRequest(server_location=location, scan_commands=scan_commands)
    scanner = Scanner()

    try:
        scanner.queue_scans([request])
        result = next(iter(scanner.get_results()), None)
    except Exception as exc:
        return _error_result(target, started, f"scan failed: {exc}")

    if result is None:
        return _error_result(target, started, "no scan result returned")

    if result.scan_status != ServerScanStatusEnum.COMPLETED:
        reason = getattr(result, "connectivity_error_trace", None) or "connectivity error"
        return _error_result(target, started, str(reason))

    findings: list[Finding] = []
    findings.extend(_check_legacy_protocols(result, target))
    findings.extend(_check_cipher_weaknesses(result, target))
    findings.extend(_check_certificate(result, target))
    findings.extend(_check_pqc_groups(result, target))

    return ScanResult(
        target=target,
        scan_type="tls",
        findings=findings,
        scanned_at=_now_iso(),
        duration_ms=int((time.monotonic() - started) * 1000),
        error=None,
    )


def _attempted(attempt):
    """Return the inner result of an sslyze ScanCommandAttempt, or None."""
    if attempt is None:
        return None
    return getattr(attempt, "result", None)


def _check_legacy_protocols(scan, target: str) -> list[Finding]:
    findings: list[Finding] = []
    sr = scan.scan_result

    legacy_attempts = {
        "TLS 1.0": _attempted(getattr(sr, "tls_1_0_cipher_suites", None)),
        "TLS 1.1": _attempted(getattr(sr, "tls_1_1_cipher_suites", None)),
    }

    for label, result in legacy_attempts.items():
        if result is None:
            continue
        accepted = getattr(result, "accepted_cipher_suites", []) or []
        if not accepted:
            continue
        findings.append(
            Finding(
                id="TLS-001",
                category=FindingCategory.TLS_VERSION,
                severity=Severity.HIGH,
                title=f"Legacy protocol {label} supported",
                description=(
                    f"The endpoint accepts {label} cipher suites. These protocols are "
                    "deprecated and lack modern key-exchange agility, which blocks any "
                    "future PQC hybrid handshake."
                ),
                location=target,
                evidence=f"{len(accepted)} {label} cipher suite(s) accepted",
                remediation="Disable TLS 1.0/1.1 and require TLS 1.2 or 1.3.",
                nist_ref="NIST SP 800-52 Rev. 2",
            )
        )
    return findings


def _check_cipher_weaknesses(scan, target: str) -> list[Finding]:
    findings: list[Finding] = []
    sr = scan.scan_result

    cipher_attempts = [
        getattr(sr, "tls_1_2_cipher_suites", None),
        getattr(sr, "tls_1_3_cipher_suites", None),
        getattr(sr, "tls_1_1_cipher_suites", None),
        getattr(sr, "tls_1_0_cipher_suites", None),
    ]

    rsa_kex_found: list[str] = []
    weak_cipher_found: list[str] = []

    for attempt in cipher_attempts:
        result = _attempted(attempt)
        if result is None:
            continue
        for accepted in getattr(result, "accepted_cipher_suites", []) or []:
            suite = getattr(accepted, "cipher_suite", None)
            name = (getattr(suite, "name", "") or "").upper()
            if not name:
                continue

            # TLS-002: RSA key exchange (no PFS). TLS 1.3 ciphers don't encode KEX
            # in the name; only the RSA-keyed TLS_RSA_WITH_* ciphers do.
            if name.startswith("TLS_RSA_WITH_"):
                rsa_kex_found.append(name)

            # TLS-003: RC4 / 3DES / NULL / EXPORT.
            if any(frag in name for frag in _WEAK_CIPHER_FRAGMENTS):
                weak_cipher_found.append(name)

    if rsa_kex_found:
        findings.append(
            Finding(
                id="TLS-002",
                category=FindingCategory.TLS_CIPHER,
                severity=Severity.CRITICAL,
                title="RSA key exchange offered (no perfect forward secrecy)",
                description=(
                    "Cipher suites using RSA key transport were accepted. RSA key "
                    "exchange has no forward secrecy and is fully breakable by a "
                    "future quantum adversary holding a recorded handshake."
                ),
                location=target,
                evidence=", ".join(sorted(set(rsa_kex_found))[:5]),
                remediation=(
                    "Disable TLS_RSA_* cipher suites; require (EC)DHE-based suites "
                    "and plan migration to hybrid X25519MLKEM768."
                ),
                nist_ref="NIST SP 800-52 Rev. 2 §3.3.1",
            )
        )

    if weak_cipher_found:
        findings.append(
            Finding(
                id="TLS-003",
                category=FindingCategory.TLS_CIPHER,
                severity=Severity.CRITICAL,
                title="Weak symmetric cipher accepted (RC4 / 3DES / NULL / EXPORT)",
                description=(
                    "The endpoint accepts cipher suites with broken or export-grade "
                    "symmetric algorithms. These are insecure today, regardless of PQC."
                ),
                location=target,
                evidence=", ".join(sorted(set(weak_cipher_found))[:5]),
                remediation="Restrict ciphers to AES-GCM or ChaCha20-Poly1305 suites.",
                nist_ref="NIST SP 800-131A Rev. 2",
            )
        )

    return findings


def _check_certificate(scan, target: str) -> list[Finding]:
    findings: list[Finding] = []
    cert_attempt = getattr(scan.scan_result, "certificate_info", None)
    cert_result = _attempted(cert_attempt)
    if cert_result is None:
        return findings

    for deployment in getattr(cert_result, "certificate_deployments", []) or []:
        chain = getattr(deployment, "received_certificate_chain", []) or []
        if not chain:
            continue
        leaf = chain[0]

        public_key = leaf.public_key()

        # TLS-004 / TLS-006: RSA size bucket
        if isinstance(public_key, _rsa.RSAPublicKey):
            key_size = getattr(public_key, "key_size", 0)
            if key_size and key_size < 3072:
                findings.append(
                    Finding(
                        id="TLS-004",
                        category=FindingCategory.TLS_CERT,
                        severity=Severity.CRITICAL,
                        title=f"RSA certificate with {key_size}-bit key",
                        description=(
                            "The server certificate uses an RSA public key below the "
                            "3072-bit floor recommended for the transition era. RSA at "
                            "this size is the highest-priority migration target."
                        ),
                        location=target,
                        evidence=f"RSA-{key_size}",
                        remediation=(
                            "Re-issue with RSA ≥ 3072 bits as an interim step; plan "
                            "migration to ML-DSA (FIPS 204) once your CA supports it."
                        ),
                        nist_ref="FIPS 186-5 / FIPS 204 (ML-DSA)",
                    )
                )
            elif key_size:
                findings.append(
                    Finding(
                        id="TLS-006",
                        category=FindingCategory.TLS_CERT,
                        severity=Severity.MEDIUM,
                        title=f"RSA certificate with {key_size}-bit key",
                        description=(
                            "RSA at this strength is acceptable today but is not "
                            "quantum-safe. Plan rotation to a post-quantum signature."
                        ),
                        location=target,
                        evidence=f"RSA-{key_size}",
                        remediation="Track CA roadmap for ML-DSA (FIPS 204) issuance.",
                        nist_ref="FIPS 204 (ML-DSA)",
                    )
                )

        # TLS-005: ECC certificate
        elif isinstance(public_key, _ec.EllipticCurvePublicKey):
            curve = getattr(getattr(public_key, "curve", None), "name", "unknown")
            findings.append(
                Finding(
                    id="TLS-005",
                    category=FindingCategory.TLS_CERT,
                    severity=Severity.HIGH,
                    title=f"ECC certificate ({curve})",
                    description=(
                        "Elliptic-curve certificates are quantum-vulnerable. Plan "
                        "migration to ML-DSA once issuance is available."
                    ),
                    location=target,
                    evidence=f"ECC {curve}",
                    remediation="Schedule migration from ECDSA to ML-DSA (FIPS 204).",
                    nist_ref="FIPS 204 (ML-DSA)",
                )
            )

        # TLS-008: expiry < 30 days
        not_after = getattr(leaf, "not_valid_after_utc", None) or getattr(
            leaf, "not_valid_after", None
        )
        if not_after is not None:
            if not_after.tzinfo is None:
                not_after = not_after.replace(tzinfo=UTC)
            days_left = (not_after - datetime.now(UTC)).days
            if days_left < 30:
                findings.append(
                    Finding(
                        id="TLS-008",
                        category=FindingCategory.TLS_CERT,
                        severity=Severity.HIGH,
                        title=f"Certificate expires in {days_left} day(s)",
                        description=(
                            "Short-dated certificate. Replace before expiry; this is "
                            "also a good opportunity to upgrade key parameters."
                        ),
                        location=target,
                        evidence=f"not_after={not_after.isoformat()}",
                        remediation="Renew before expiry; consider stronger key params.",
                        nist_ref="CA/B Forum BR §6.3.2",
                    )
                )

        # TLS-009: MD5 or SHA-1 signature
        sig_algo = ""
        oid_attr = getattr(leaf, "signature_hash_algorithm", None)
        if oid_attr is not None:
            sig_algo = getattr(oid_attr, "name", "") or ""
        sig_lower = sig_algo.lower()
        if "md5" in sig_lower or "sha1" in sig_lower:
            findings.append(
                Finding(
                    id="TLS-009",
                    category=FindingCategory.TLS_CERT,
                    severity=Severity.CRITICAL,
                    title=f"Certificate signed with {sig_algo}",
                    description=(
                        "Certificate uses a broken hash for its signature. This is "
                        "trivially forgeable and must be replaced."
                    ),
                    location=target,
                    evidence=f"signature_hash={sig_algo}",
                    remediation="Re-issue with SHA-256 or stronger; prefer SHA-384.",
                    nist_ref="NIST SP 800-131A Rev. 2",
                )
            )

    return findings


def _check_pqc_groups(scan, target: str) -> list[Finding]:
    ec_attempt = getattr(scan.scan_result, "elliptic_curves", None)
    ec_result = _attempted(ec_attempt)
    if ec_result is None:
        return []

    supported = getattr(ec_result, "supported_curves", []) or []
    names = {(getattr(c, "name", "") or "").lower() for c in supported}
    pqc_hits = sorted(names & _PQC_KEX_NAMES)

    if pqc_hits:
        return [
            Finding(
                id="TLS-007",
                category=FindingCategory.TLS_PQC,
                severity=Severity.INFO,
                title="Hybrid PQC key exchange offered",
                description=(
                    "Endpoint negotiates at least one hybrid post-quantum KEM group. "
                    "Recorded handshakes are protected against a future quantum adversary."
                ),
                location=target,
                evidence=", ".join(pqc_hits),
                remediation="Maintain the hybrid suite; monitor for ML-KEM-only support.",
                nist_ref="FIPS 203 (ML-KEM)",
                pqc_ready=True,
            )
        ]

    return [
        Finding(
            id="TLS-007",
            category=FindingCategory.TLS_PQC,
            severity=Severity.INFO,
            title="No hybrid PQC key exchange offered",
            description=(
                "Endpoint does not yet advertise X25519MLKEM768 or another hybrid "
                "post-quantum group. Recorded handshakes are vulnerable to "
                "harvest-now-decrypt-later."
            ),
            location=target,
            evidence="x25519mlkem768 not in supported_groups",
            remediation=(
                "Upgrade the TLS terminator (e.g. Cloudflare, recent OpenSSL/BoringSSL, "
                "nginx with quictls) and enable X25519MLKEM768."
            ),
            nist_ref="FIPS 203 (ML-KEM)",
            pqc_ready=False,
        )
    ]
