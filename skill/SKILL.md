# pqready — PQC Readiness Scanner

## What this tool does

`pqready` audits a system for post-quantum cryptography (PQC) readiness across
three dimensions:

1. **TLS endpoints** — Detects legacy protocol versions, RSA key exchange,
   weak ciphers, quantum-vulnerable certificates, and whether the server
   advertises a hybrid PQC key-exchange group (X25519MLKEM768).
2. **Source code** — Flags imports and call sites that use RSA, elliptic-curve
   crypto, or broken hashes (MD5/SHA-1). Uses Python AST for Python files and
   regex for config formats (`.yml`, `.toml`, `.env`, `.conf`).
3. **Certificate files** — Parses `.pem`, `.crt`, `.cer`, `.key` files and
   reports key algorithm, key size, expiry, and signature algorithm.

It produces structured `ScanResult` objects, a color-coded terminal summary,
and an optional self-contained HTML report.

## When to invoke it

Use `pqready` whenever the user (or an upstream agent) needs to:

- Triage exposure to "harvest-now-decrypt-later" attacks for a public endpoint.
- Inventory quantum-vulnerable crypto inside a codebase before scoping a PQC
  migration.
- Inspect a single certificate file to decide whether a rotation is urgent.
- Generate an audit-friendly HTML report for a stakeholder.

**Decision tree:**

| Target type                                    | Use this tool          |
| ---------------------------------------------- | ---------------------- |
| Hostname (with or without port), URL           | `scan_tls_endpoint`    |
| Path to a directory or `.py` / `.yml` / etc.   | `scan_source_code`     |
| Path to a `.pem` / `.crt` / `.cer` / `.key`    | `scan_cert_file`       |
| Mixed input or unsure                          | CLI `pqready scan`     |

## Installation

```bash
pip install pqready
```

After install you have two console scripts:

- `pqready`     — the CLI
- `pqready-mcp` — the MCP server (stdio transport)

Requires Python 3.11+.

## CLI usage

```bash
# TLS endpoint
pqready tls api.example.com
pqready tls api.example.com --port 8443 --output tls-report.html

# Source tree
pqready source ./my-service
pqready source ./my-service --output src-report.html

# Single cert file
pqready cert /etc/ssl/certs/api.example.com.pem --output cert-report.html

# Auto-detect
pqready scan api.example.com
pqready scan ./my-service
pqready scan ./api.example.com.pem
```

Exit codes:

- `0` — no CRITICAL or HIGH findings
- `1` — at least one CRITICAL or HIGH
- `2` — scan error

## MCP tool usage

Run the server locally (stdio):

```bash
pqready-mcp
```

Or wire it into Claude Code / Cursor / Cline as an MCP server. Each tool
returns a JSON-serialised `ScanResult`.

### `scan_tls_endpoint`

```json
// input
{ "hostname": "api.example.com", "port": 443 }

// output (abridged)
{
  "target": "api.example.com:443",
  "scan_type": "tls",
  "findings": [
    {
      "id": "TLS-005",
      "category": "tls_cert",
      "severity": "high",
      "title": "ECC certificate (secp256r1)",
      "description": "...",
      "location": "api.example.com:443",
      "evidence": "ECC secp256r1",
      "remediation": "Schedule migration from ECDSA to ML-DSA (FIPS 204).",
      "nist_ref": "FIPS 204 (ML-DSA)",
      "pqc_ready": false
    }
  ],
  "scanned_at": "2026-05-18T20:00:00+00:00",
  "duration_ms": 2150,
  "error": null
}
```

### `scan_source_code`

```json
// input
{ "path": "./services/payments" }

// output
{
  "results": [
    {
      "target": "services/payments/keys.py",
      "scan_type": "source",
      "findings": [ /* Finding objects */ ],
      "scanned_at": "...",
      "duration_ms": 4,
      "error": null
    }
  ]
}
```

### `scan_cert_file`

```json
// input
{ "path": "/etc/ssl/certs/api.example.com.pem" }

// output: a single ScanResult, same shape as scan_tls_endpoint
```

### `generate_html_report`

Accepts either a single `ScanResult` dict, a list, or a `{"results": [...]}`
wrapper from `scan_source_code`. If `output_path` is empty, a temp file is
created and its path is returned.

```json
// input
{
  "results_json": "{\"results\": [...]}",
  "output_path": "/tmp/pqready-report.html"
}

// output
{ "output_path": "/tmp/pqready-report.html", "targets": 12 }
```

## Output schema

```python
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

class FindingCategory(str, Enum):
    TLS_CIPHER    = "tls_cipher"
    TLS_VERSION   = "tls_version"
    TLS_CERT      = "tls_cert"
    TLS_PQC       = "tls_pqc"
    SOURCE_IMPORT = "source_import"
    SOURCE_USAGE  = "source_usage"
    CERT_FILE     = "cert_file"

class Finding:
    id: str               # e.g. "TLS-002"
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    location: str         # endpoint URL, file path, or "file:line"
    evidence: str         # raw value that triggered the finding
    remediation: str
    nist_ref: str         # e.g. "FIPS 203 (ML-KEM)"
    pqc_ready: bool       # only True for TLS-007 positive

class ScanResult:
    target: str
    scan_type: str        # "tls" | "source" | "cert"
    findings: list[Finding]
    scanned_at: str       # ISO 8601, UTC
    duration_ms: int
    error: str | None
    # computed properties
    risk_score: int       # 0-100 (CRITICAL=40, HIGH=20, MEDIUM=10, LOW=5)
    pqc_ready: bool       # False if any CRITICAL/HIGH present
```

## Interpreting findings

`risk_score` is a coarse summary, **not** a substitute for reading the
findings. Two endpoints can hit 100 for very different reasons. Always
report the top CRITICAL/HIGH titles, not just the number.

`pqc_ready` is intentionally conservative: it returns `False` whenever any
CRITICAL or HIGH finding exists. It is **not** a certification — even a fully
green run only means we did not find any of the patterns we know to look for.

## Remediation guidance by finding ID

| ID       | Action                                                                 |
| -------- | ---------------------------------------------------------------------- |
| TLS-001  | Disable TLS 1.0/1.1; require TLS 1.2 minimum (1.3 preferred).          |
| TLS-002  | Remove `TLS_RSA_*` cipher suites; require (EC)DHE.                     |
| TLS-003  | Restrict to AES-GCM and ChaCha20-Poly1305.                             |
| TLS-004  | Re-issue with RSA ≥ 3072 bits; plan ML-DSA migration.                  |
| TLS-005  | Plan ECDSA → ML-DSA migration once CA supports it.                     |
| TLS-006  | Acceptable today; track CA roadmap for ML-DSA issuance.                |
| TLS-007  | (Info) Hybrid PQC KEX present — keep monitoring.                       |
| TLS-008  | Renew before expiry; upgrade key params while you're at it.            |
| TLS-009  | Re-issue immediately with SHA-256 or stronger.                         |
| SRC-001  | Migrate off PyCrypto; use `cryptography` and plan PQC path.            |
| SRC-002  | Audit RSA call sites; scope migration to FIPS 203 / 204.               |
| SRC-003  | Raise RSA size to ≥ 3072; plan PQC migration.                          |
| SRC-004  | Plan ECDSA/ECDH → ML-DSA/ML-KEM migration.                             |
| SRC-005  | Replace MD5/SHA-1 with SHA-256 or SHA-3.                               |
| SRC-006  | Document RSA/AES-128-CBC usage in your PQC plan.                       |
| SRC-007  | Add referenced key material to your inventory for rotation.            |
| CERT-004 | Re-issue with RSA ≥ 3072.                                              |
| CERT-005 | Plan migration to ML-DSA.                                              |
| CERT-006 | Track CA roadmap for ML-DSA issuance.                                  |
| CERT-008 | Renew before expiry.                                                   |
| CERT-009 | Re-issue immediately.                                                  |

## Integration with CI/CD

Fail the build on any CRITICAL/HIGH finding:

```yaml
- run: pip install pqready
- run: pqready source ./src
- run: pqready tls api.example.com
```

Both commands exit non-zero on findings; the standard exit-code contract
plays cleanly with GitHub Actions, GitLab CI, and CircleCI.

## Limitations

- TLS scans depend on `sslyze`'s view of the handshake; some load balancers
  hide cipher details from external scans.
- The source scanner is pattern-based and will miss findings that hide behind
  dynamic dispatch (e.g. `getattr(crypto_mod, fn_name)`).
- PQC group detection looks for OpenSSL-style names; servers exposing only
  IANA codepoints in custom log formats may report differently.
- `pqready` does not test certificate revocation or CT-log inclusion.
