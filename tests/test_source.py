"""Tests for the source-code scanner. No network or external IO required."""

from __future__ import annotations

from pathlib import Path

from pqready.core.models import Severity
from pqready.core.source import scan_source


def _ids(result) -> set[str]:
    return {f.id for f in result.findings}


def _write(tmp_path: Path, name: str, body: str) -> Path:
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_pycrypto_import_flagged(tmp_path):
    f = _write(tmp_path, "bad_pycrypto.py", "from Crypto.Cipher import AES\n")
    [result] = scan_source(str(f))
    assert "SRC-001" in _ids(result)


def test_cryptography_rsa_import_flagged(tmp_path):
    f = _write(
        tmp_path,
        "rsa_import.py",
        "from cryptography.hazmat.primitives.asymmetric import rsa\n",
    )
    [result] = scan_source(str(f))
    assert "SRC-002" in _ids(result)


def test_rsa_generate_small_key_critical(tmp_path):
    f = _write(
        tmp_path,
        "rsa_gen.py",
        "from Crypto.PublicKey import RSA\n"
        "k = RSA.generate(2048)\n",
    )
    [result] = scan_source(str(f))
    findings = {f.id: f for f in result.findings}
    assert "SRC-003" in findings
    assert findings["SRC-003"].severity is Severity.CRITICAL


def test_rsa_generate_large_key_not_flagged(tmp_path):
    f = _write(
        tmp_path,
        "rsa_gen_ok.py",
        "from Crypto.PublicKey import RSA\n"
        "k = RSA.generate(4096)\n",
    )
    [result] = scan_source(str(f))
    # SRC-001 (PyCrypto import) still flagged; SRC-003 must NOT be.
    assert "SRC-003" not in _ids(result)
    assert "SRC-001" in _ids(result)


def test_ec_generate_private_key_flagged(tmp_path):
    f = _write(
        tmp_path,
        "ec.py",
        "from cryptography.hazmat.primitives.asymmetric import ec\n"
        "k = ec.generate_private_key(ec.SECP256R1())\n",
    )
    [result] = scan_source(str(f))
    assert "SRC-004" in _ids(result)


def test_md5_and_sha1_flagged(tmp_path):
    f = _write(
        tmp_path,
        "hash.py",
        "import hashlib\n"
        "hashlib.md5(b'x')\n"
        "hashlib.sha1(b'y')\n",
    )
    [result] = scan_source(str(f))
    assert "SRC-005" in _ids(result)
    md5_or_sha1 = [
        f for f in result.findings if f.id == "SRC-005"
    ]
    assert len(md5_or_sha1) == 2


def test_config_yaml_rsa_low_severity(tmp_path):
    f = _write(tmp_path, "app.yml", "tls:\n  key_algo: RSA\n")
    [result] = scan_source(str(f))
    assert "SRC-006" in _ids(result)


def test_open_pem_reference_flagged(tmp_path):
    f = _write(tmp_path, "loader.py", "open('/etc/ssl/private/server.key', 'rb')\n")
    [result] = scan_source(str(f))
    assert "SRC-007" in _ids(result)


def test_clean_file_has_no_findings(tmp_path):
    f = _write(tmp_path, "clean.py", "def add(a, b):\n    return a + b\n")
    [result] = scan_source(str(f))
    assert result.findings == []
    assert result.error is None


def test_directory_scan_visits_multiple_files(tmp_path):
    _write(tmp_path, "a.py", "from Crypto.Cipher import AES\n")
    _write(tmp_path, "b.py", "import hashlib; hashlib.md5(b'x')\n")
    (tmp_path / "node_modules").mkdir()
    _write(tmp_path / "node_modules", "ignored.py", "from Crypto.Cipher import AES\n")

    results = scan_source(str(tmp_path))
    # node_modules should be pruned — exactly 2 files scanned.
    scanned_names = sorted(Path(r.target).name for r in results)
    assert scanned_names == ["a.py", "b.py"]


def test_nonexistent_path_returns_error_result():
    [result] = scan_source("/no/such/path/anywhere.py")
    assert result.error is not None
    assert result.findings == []


def test_large_file_is_skipped_with_error(tmp_path):
    big = tmp_path / "huge.py"
    big.write_bytes(b"x = 1\n" * 200_000)  # > 1 MB
    [result] = scan_source(str(big))
    assert result.error is not None
    assert "too large" in result.error
