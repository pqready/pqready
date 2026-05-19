# pqready

[![PyPI version](https://img.shields.io/pypi/v/pqready.svg)](https://pypi.org/project/pqready/)
[![Python versions](https://img.shields.io/pypi/pyversions/pqready.svg)](https://pypi.org/project/pqready/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/pqready/pqready/actions/workflows/test.yml/badge.svg)](https://github.com/pqready/pqready/actions/workflows/test.yml)

**Post-quantum cryptography readiness scanner.** Audits TLS endpoints, source
code, and certificate files for quantum-vulnerable crypto and surfaces a
prioritised migration plan — as a CLI, a library, an MCP server, or a remote
Cloudflare-hosted tool.

---

## Install

```bash
pip install pqready
```

Requires Python 3.11+. Installs two console scripts:

| Command       | What it is                                          |
| ------------- | --------------------------------------------------- |
| `pqready`     | the audit CLI                                       |
| `pqready-mcp` | MCP server over stdio (Claude Code, Cursor, Cline)  |

## Quickstart

```bash
# Scan a TLS endpoint
pqready tls api.example.com

# Scan a source tree
pqready source ./my-service

# Inspect a certificate file
pqready cert /etc/ssl/certs/api.example.com.pem

# Auto-detect target type
pqready scan ./my-service
pqready scan api.example.com

# Generate an HTML report alongside the terminal summary
pqready tls api.example.com --output report.html
```

**Exit codes:** `0` clean · `1` CRITICAL/HIGH findings · `2` scan error.
Plays cleanly with CI: just call `pqready` and let the exit code fail the job.

## What it detects

`pqready` looks for three classes of quantum-relevant weakness.

### TLS endpoints — backed by [`sslyze`](https://pypi.org/project/sslyze/)

| ID       | Detects                                              | Severity |
| -------- | ---------------------------------------------------- | -------- |
| TLS-001  | TLS 1.0 / 1.1 still supported                        | HIGH     |
| TLS-002  | RSA key exchange (no PFS) — harvest-now-decrypt-later| CRITICAL |
| TLS-003  | RC4 / 3DES / NULL / EXPORT cipher accepted           | CRITICAL |
| TLS-004  | Certificate uses RSA < 3072 bits                     | CRITICAL |
| TLS-005  | Certificate uses ECC (P-256 / P-384 / …)             | HIGH     |
| TLS-006  | Certificate uses RSA ≥ 3072 bits (not yet PQC)       | MEDIUM   |
| TLS-007  | X25519MLKEM768 hybrid PQC KEX advertised             | INFO ✓   |
| TLS-008  | Certificate expires in < 30 days                     | HIGH     |
| TLS-009  | Certificate signed with MD5 or SHA-1                 | CRITICAL |

### Source code — AST for Python, regex for config

| ID       | Detects                                                  | Severity |
| -------- | -------------------------------------------------------- | -------- |
| SRC-001  | `import Crypto` / `from Crypto…` (PyCrypto / PyCryptodome)| HIGH     |
| SRC-002  | `from cryptography.hazmat.primitives.asymmetric import rsa` | HIGH  |
| SRC-003  | `RSA.generate(<3072)`                                    | CRITICAL |
| SRC-004  | `ec.generate_private_key` / `EllipticCurvePrivateKey`    | HIGH     |
| SRC-005  | `hashlib.md5(` / `hashlib.sha1(`                         | MEDIUM   |
| SRC-006  | Hardcoded `RSA` / `AES-128-CBC` in config files          | LOW      |
| SRC-007  | `.pem` / `.crt` / `.key` referenced via `open(…)`        | LOW      |

Skips binary files and files > 1 MB. Prunes `.git`, `.venv`, `node_modules`,
`__pycache__`, `dist`, `build` and friends.

### Certificate files — PEM / DER / CRT / CER / KEY

Reuses the cert-level checks above (TLS-004 … TLS-009) and applies them to
files on disk. Useful for offline audits of leaf certs and private keys.

## Sample terminal output

```
pqready · TLS scan · api.example.com:443
────────────────────────────────────────
✗ CRITICAL  TLS-002  RSA key exchange offered (no perfect forward secrecy)
✗ CRITICAL  TLS-004  RSA certificate with 2048-bit key
✗ HIGH      TLS-005  ECC certificate (secp256r1)
✓ INFO      TLS-007  No hybrid PQC key exchange offered
Risk score: 80/100  ·  PQC-ready: NO
────────────────────────────────────────
Run with --output report.html to generate a full report.
```

The HTML report is **self-contained** (no external CSS / JS, no remote
fetches). Open it in a browser or attach it to a ticket as-is.

## Library usage

```python
from pqready.core.tls import scan_tls
from pqready.core.source import scan_source
from pqready.core.certs import scan_cert_file
from pqready.reporters.html import render_html

tls_result   = scan_tls("api.example.com")
src_results  = scan_source("./services")
cert_result  = scan_cert_file("./api.example.com.pem")

render_html([tls_result, *src_results, cert_result], "report.html")
```

Every scanner returns a `ScanResult`:

```python
@dataclass
class Finding:
    id: str               # e.g. "TLS-002"
    category: FindingCategory
    severity: Severity    # critical | high | medium | low | info
    title: str
    description: str
    location: str         # endpoint URL, file path, or "file:line"
    evidence: str
    remediation: str
    nist_ref: str         # e.g. "FIPS 203 (ML-KEM)"
    pqc_ready: bool

@dataclass
class ScanResult:
    target: str
    scan_type: str        # "tls" | "source" | "cert"
    findings: list[Finding]
    scanned_at: str       # ISO 8601
    duration_ms: int
    error: str | None
    risk_score: int       # 0-100, severity-weighted
    pqc_ready: bool       # False if any CRITICAL/HIGH
```

## MCP server

`pqready` ships an MCP server (`pqready-mcp`) over stdio that exposes four
tools any MCP-capable agent (Claude Code, Cursor, Cline, …) can call:

| Tool                  | Input                          | Returns                       |
| --------------------- | ------------------------------ | ----------------------------- |
| `scan_tls_endpoint`   | `hostname`, `port` (=443)      | `ScanResult` dict             |
| `scan_source_code`    | `path`                         | `{"results": [ScanResult]}`   |
| `scan_cert_file`      | `path`                         | `ScanResult` dict             |
| `generate_html_report`| `results_json`, `output_path`  | `{output_path, targets}`      |

Wire it in by adding to your MCP client config:

```json
{
  "mcpServers": {
    "pqready": { "command": "pqready-mcp" }
  }
}
```

Full tool schemas, example payloads, and a decision tree for which tool to
call live in [`skill/SKILL.md`](skill/SKILL.md) — drop that file into any
agent skill loader to teach the agent how to use `pqready` correctly.

## Cloudflare Worker (remote MCP)

A thin proxy Worker lives in [`cf_worker/`](cf_worker/). It handles bearer
auth and streams MCP traffic to a backend running `pqready-mcp` over HTTP/SSE
(Cloud Run, Fly, VPS, etc.). The Python runtime cannot execute directly in a
Worker, so this layer is auth + proxy only.

```bash
cd cf_worker
npm install
wrangler secret put PQREADY_API_TOKEN
npm run deploy
```

See [`cf_worker/README.md`](cf_worker/README.md) for the full setup.

## Interpreting findings

`risk_score` is a coarse summary, **not** a substitute for reading the
findings. Two endpoints can hit 100 for entirely different reasons.

`pqc_ready` is intentionally conservative: it returns `False` whenever any
CRITICAL or HIGH finding exists. A green run only means we did not find any
of the patterns we know to look for — it is not a certification.

Every finding carries:

- **NIST reference** — most often FIPS 203 (ML-KEM), FIPS 204 (ML-DSA),
  SP 800-52, or SP 800-131A.
- **Remediation** — concrete, copy-pasteable next step.

See [`skill/SKILL.md`](skill/SKILL.md) for the full per-ID remediation table.

## Documentation

| Where                                       | What                                             |
| ------------------------------------------- | ------------------------------------------------ |
| [`skill/SKILL.md`](skill/SKILL.md)          | Full MCP tool schemas + agent decision tree      |
| [`cf_worker/README.md`](cf_worker/README.md)| Cloudflare Worker deployment guide               |
| [GitHub repo](https://github.com/pqready/pqready) | Issues, releases, source                   |
| [PyPI project](https://pypi.org/project/pqready/)  | Latest release, install command            |

## Development

```bash
git clone https://github.com/pqready/pqready.git
cd pqready
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
ruff check .
pytest tests/
```

CI runs ruff + pytest on Python 3.11 and 3.12. Releases are cut by pushing a
`v*` tag; [`.github/workflows/publish.yml`](.github/workflows/publish.yml)
publishes to PyPI via OIDC trusted publishing — no API tokens stored in the
repo.

## Contributing

Bug reports and PRs welcome. For non-trivial changes, please open an issue
first so we can align on scope. Run `ruff check .` and `pytest tests/`
before opening a PR.

## Limitations

- TLS scans depend on the handshake `sslyze` observes. Some load balancers
  hide cipher details from external probes.
- The source scanner is pattern-based and will miss findings hidden behind
  dynamic dispatch (e.g. `getattr(crypto_mod, name)`).
- PQC group detection matches OpenSSL-style names. Servers exposing only
  IANA codepoints in custom log formats may report differently.
- `pqready` does not test certificate revocation or CT-log inclusion.

## License

Apache-2.0 — see [LICENSE](LICENSE).
