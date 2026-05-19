"""Tests for the TLS scanner's finding rules.

The full ``scan_tls`` entry point talks to the network through ``sslyze``,
so these tests exercise the rule helpers directly against minimal fake
scan-result objects. Each helper accepts a duck-typed ``scan`` value, so we
build the shape with ``SimpleNamespace``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from pqready.core.models import Severity
from pqready.core.tls import (
    _check_certificate,
    _check_cipher_weaknesses,
    _check_legacy_protocols,
    _check_pqc_groups,
)


def _suite(name: str):
    return SimpleNamespace(cipher_suite=SimpleNamespace(name=name))


def _attempt(accepted=None, curves=None):
    if accepted is not None:
        return SimpleNamespace(result=SimpleNamespace(accepted_cipher_suites=accepted))
    if curves is not None:
        return SimpleNamespace(result=SimpleNamespace(supported_curves=curves))
    return None


def _scan(**kwargs):
    sr = SimpleNamespace(**kwargs)
    return SimpleNamespace(scan_result=sr)


def _build_cert(public_key, *, hash_algo=None, days_valid=365):
    if hash_algo is None:
        hash_algo = hashes.SHA256()
    issuer = subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "pqready-test")]
    )
    not_before = datetime.now(UTC) - timedelta(days=1)
    not_after = datetime.now(UTC) + timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    # Self-sign with an RSA key so we can choose an arbitrary signature hash.
    signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return builder.sign(private_key=signing_key, algorithm=hash_algo)


def _fake_cert_with_sig(public_key, sig_name: str, *, days_valid: int = 365):
    """Build a duck-typed cert-like object for tests that need an unsigned hash.

    The real `cryptography` builder refuses to sign with SHA-1 / MD5, so we
    construct a stand-in with just the attributes the rule helpers read.
    """
    not_after = datetime.now(UTC) + timedelta(days=days_valid)
    return SimpleNamespace(
        public_key=lambda: public_key,
        not_valid_after_utc=not_after,
        signature_hash_algorithm=SimpleNamespace(name=sig_name),
    )


def _cert_scan(cert):
    return _scan(
        certificate_info=SimpleNamespace(
            result=SimpleNamespace(
                certificate_deployments=[
                    SimpleNamespace(received_certificate_chain=[cert])
                ]
            )
        )
    )


# ---------- TLS-001: legacy protocols ----------

def test_legacy_tls_10_flagged():
    scan = _scan(
        tls_1_0_cipher_suites=_attempt(accepted=[_suite("TLS_RSA_WITH_AES_128_CBC_SHA")]),
        tls_1_1_cipher_suites=_attempt(accepted=[]),
    )
    findings = _check_legacy_protocols(scan, "h:443")
    assert any(f.id == "TLS-001" and "TLS 1.0" in f.title for f in findings)


def test_legacy_tls_not_flagged_when_unsupported():
    scan = _scan(
        tls_1_0_cipher_suites=_attempt(accepted=[]),
        tls_1_1_cipher_suites=_attempt(accepted=[]),
    )
    assert _check_legacy_protocols(scan, "h:443") == []


# ---------- TLS-002: RSA KEX ----------

def test_rsa_kex_flagged_critical():
    scan = _scan(
        tls_1_2_cipher_suites=_attempt(
            accepted=[_suite("TLS_RSA_WITH_AES_256_GCM_SHA384")]
        ),
        tls_1_3_cipher_suites=_attempt(accepted=[]),
        tls_1_1_cipher_suites=_attempt(accepted=[]),
        tls_1_0_cipher_suites=_attempt(accepted=[]),
    )
    findings = _check_cipher_weaknesses(scan, "h:443")
    rsa_findings = [f for f in findings if f.id == "TLS-002"]
    assert len(rsa_findings) == 1
    assert rsa_findings[0].severity is Severity.CRITICAL


def test_ecdhe_only_no_rsa_kex_finding():
    scan = _scan(
        tls_1_2_cipher_suites=_attempt(
            accepted=[_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")]
        ),
        tls_1_3_cipher_suites=_attempt(accepted=[]),
        tls_1_1_cipher_suites=_attempt(accepted=[]),
        tls_1_0_cipher_suites=_attempt(accepted=[]),
    )
    assert not any(f.id == "TLS-002" for f in _check_cipher_weaknesses(scan, "h:443"))


# ---------- TLS-003: weak ciphers ----------

def test_rc4_cipher_flagged():
    scan = _scan(
        tls_1_2_cipher_suites=_attempt(
            accepted=[_suite("TLS_RSA_WITH_RC4_128_SHA")]
        ),
        tls_1_3_cipher_suites=_attempt(accepted=[]),
        tls_1_1_cipher_suites=_attempt(accepted=[]),
        tls_1_0_cipher_suites=_attempt(accepted=[]),
    )
    findings = _check_cipher_weaknesses(scan, "h:443")
    assert any(f.id == "TLS-003" for f in findings)


def test_3des_cipher_flagged():
    scan = _scan(
        tls_1_2_cipher_suites=_attempt(
            accepted=[_suite("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA")]
        ),
        tls_1_3_cipher_suites=_attempt(accepted=[]),
        tls_1_1_cipher_suites=_attempt(accepted=[]),
        tls_1_0_cipher_suites=_attempt(accepted=[]),
    )
    assert any(f.id == "TLS-003" for f in _check_cipher_weaknesses(scan, "h:443"))


# ---------- TLS-004 / TLS-006: RSA cert ----------

def test_rsa_cert_small_key_critical():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = _build_cert(key.public_key())
    findings = _check_certificate(_cert_scan(cert), "h:443")
    rsa_findings = [f for f in findings if f.id == "TLS-004"]
    assert len(rsa_findings) == 1
    assert rsa_findings[0].severity is Severity.CRITICAL


def test_rsa_cert_strong_key_medium():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cert = _build_cert(key.public_key())
    findings = _check_certificate(_cert_scan(cert), "h:443")
    medium = [f for f in findings if f.id == "TLS-006"]
    assert len(medium) == 1
    assert medium[0].severity is Severity.MEDIUM


# ---------- TLS-005: ECC cert ----------

def test_ecc_cert_flagged_high():
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _build_cert(key.public_key())
    findings = _check_certificate(_cert_scan(cert), "h:443")
    ecc = [f for f in findings if f.id == "TLS-005"]
    assert len(ecc) == 1
    assert ecc[0].severity is Severity.HIGH


# ---------- TLS-008: short expiry ----------

def test_short_expiry_flagged():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cert = _build_cert(key.public_key(), days_valid=5)
    findings = _check_certificate(_cert_scan(cert), "h:443")
    assert any(f.id == "TLS-008" for f in findings)


# ---------- TLS-009: weak signature ----------

def test_sha1_signature_flagged():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cert = _fake_cert_with_sig(key.public_key(), "sha1")
    findings = _check_certificate(_cert_scan(cert), "h:443")
    weak_sig = [f for f in findings if f.id == "TLS-009"]
    assert len(weak_sig) == 1
    assert weak_sig[0].severity is Severity.CRITICAL


def test_md5_signature_flagged():
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cert = _fake_cert_with_sig(key.public_key(), "md5")
    findings = _check_certificate(_cert_scan(cert), "h:443")
    assert any(f.id == "TLS-009" for f in findings)


# ---------- TLS-007: PQC KEX ----------

def test_pqc_kex_present_marks_pqc_ready():
    scan = _scan(
        elliptic_curves=_attempt(
            curves=[SimpleNamespace(name="X25519MLKEM768")]
        )
    )
    [finding] = _check_pqc_groups(scan, "h:443")
    assert finding.id == "TLS-007"
    assert finding.pqc_ready is True
    assert finding.severity is Severity.INFO


def test_pqc_kex_absent_marks_not_ready():
    scan = _scan(
        elliptic_curves=_attempt(
            curves=[SimpleNamespace(name="X25519"), SimpleNamespace(name="secp256r1")]
        )
    )
    [finding] = _check_pqc_groups(scan, "h:443")
    assert finding.id == "TLS-007"
    assert finding.pqc_ready is False


def test_no_elliptic_curves_result_means_no_pqc_finding():
    scan = _scan(elliptic_curves=None)
    assert _check_pqc_groups(scan, "h:443") == []
