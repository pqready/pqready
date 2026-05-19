# pqready

[![PyPI version](https://img.shields.io/pypi/v/pqready.svg)](https://pypi.org/project/pqready/)
[![Python versions](https://img.shields.io/pypi/pyversions/pqready.svg)](https://pypi.org/project/pqready/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/shanglai/pqready/actions/workflows/test.yml/badge.svg)](https://github.com/shanglai/pqready/actions/workflows/test.yml)

**Post-quantum cryptography readiness scanner.** Audits TLS endpoints, source
code, and certificate files for quantum-vulnerable crypto and surfaces a
prioritised migration plan.

---

## Install

```bash
pip install pqready
```

Requires Python 3.11+.

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

# Generate an HTML report
pqready tls api.example.com --output report.html
```

Exit codes: `0` clean · `1` CRITICAL/HIGH findings · `2` scan error.

## What it detects

| Surface       | Detects                                                          |
| ------------- | ---------------------------------------------------------------- |
| TLS           | Legacy TLS versions, RSA KEX, weak ciphers, RSA/ECC certs, hybrid PQC group |
| Source code   | PyCrypto imports, RSA/EC primitive usage, MD5/SHA-1, weak config |
| Certificates  | Key algorithm, key size, expiry, signature algorithm             |

Findings are tagged with a finding ID (`TLS-002`, `SRC-001`, …), a severity,
remediation guidance, and the relevant NIST reference (FIPS 203 ML-KEM,
FIPS 204 ML-DSA, SP 800-52, etc.).

## MCP server

`pqready` ships an MCP server (`pqready-mcp`) that exposes four tools:

- `scan_tls_endpoint(hostname, port)`
- `scan_source_code(path)`
- `scan_cert_file(path)`
- `generate_html_report(results_json, output_path)`

Run it locally over stdio:

```bash
pqready-mcp
```

Wire it into Claude Code / Cursor / Cline as an MCP server. See
[`skill/SKILL.md`](skill/SKILL.md) for full tool schemas, return shapes, and a
decision tree for which tool to call.

## Cloudflare Worker (remote MCP)

A thin proxy Worker lives in [`cf_worker/`](cf_worker/) for hosting the MCP
endpoint on Cloudflare with bearer-token auth, forwarding to a backend that
runs `pqready-mcp` (e.g. Cloud Run, Fly, VPS).

```bash
cd cf_worker
npm install
wrangler secret put PQREADY_API_TOKEN
npm run deploy
```

See [`cf_worker/README.md`](cf_worker/README.md) for details.

## Library usage

```python
from pqready.core.tls import scan_tls
from pqready.core.source import scan_source
from pqready.reporters.html import render_html

tls_result = scan_tls("api.example.com")
src_results = scan_source("./services")
render_html([tls_result, *src_results], "report.html")
```

## Development

```bash
git clone https://github.com/shanglai/pqready.git
cd pqready
pip install -e ".[dev]"
ruff check .
pytest tests/
```

## Contributing

Bug reports and PRs welcome. Please open an issue first for non-trivial
changes so we can align on scope.

## License

Apache-2.0. See [LICENSE](LICENSE).
