"""fastmcp server exposing pqready scanners as MCP tools."""

from __future__ import annotations

import json
import tempfile
from dataclasses import asdict

from fastmcp import FastMCP

from .core.certs import scan_cert_file as _scan_cert_file
from .core.source import scan_source
from .core.tls import scan_tls
from .reporters.html import render_html

mcp = FastMCP("pqready")


def _serialize(obj):
    """Dataclass → dict with enum values turned into strings."""
    out = asdict(obj)
    return _normalize(out)


def _normalize(value):
    if isinstance(value, dict):
        return {k: _normalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if hasattr(value, "value") and hasattr(value, "name"):
        return value.value
    return value


@mcp.tool()
def scan_tls_endpoint(hostname: str, port: int = 443) -> dict:
    """Scan a TLS endpoint for PQC readiness. Returns a serialized ScanResult."""
    return _serialize(scan_tls(hostname, port))


@mcp.tool()
def scan_source_code(path: str) -> dict:
    """Scan a directory or file for vulnerable cryptographic patterns.

    Returns {"results": [ScanResult, ...]} — one entry per file scanned.
    """
    results = scan_source(path)
    return {"results": [_serialize(r) for r in results]}


@mcp.tool()
def scan_cert_file(path: str) -> dict:
    """Parse and assess a PEM/CRT/CER/KEY certificate file."""
    return _serialize(_scan_cert_file(path))


@mcp.tool()
def generate_html_report(results_json: str, output_path: str = "") -> dict:
    """Render a self-contained HTML report from a JSON ScanResult payload.

    ``results_json`` accepts either a single ScanResult dict, a list of
    ScanResult dicts, or a ``{"results": [...]}`` wrapper. If ``output_path``
    is empty, a temp file is created and its path returned.
    """
    from .core.models import Finding, FindingCategory, ScanResult, Severity

    try:
        payload = json.loads(results_json)
    except json.JSONDecodeError as exc:
        return {"error": f"invalid JSON: {exc}"}

    if isinstance(payload, dict) and "results" in payload:
        raw_results = payload["results"]
    elif isinstance(payload, dict):
        raw_results = [payload]
    elif isinstance(payload, list):
        raw_results = payload
    else:
        return {"error": "expected dict or list payload"}

    reconstructed: list[ScanResult] = []
    for r in raw_results:
        findings = [
            Finding(
                id=f["id"],
                category=FindingCategory(f["category"]),
                severity=Severity(f["severity"]),
                title=f["title"],
                description=f["description"],
                location=f["location"],
                evidence=f["evidence"],
                remediation=f["remediation"],
                nist_ref=f["nist_ref"],
                pqc_ready=f.get("pqc_ready", False),
            )
            for f in r.get("findings", [])
        ]
        reconstructed.append(
            ScanResult(
                target=r.get("target", ""),
                scan_type=r.get("scan_type", ""),
                findings=findings,
                scanned_at=r.get("scanned_at", ""),
                duration_ms=r.get("duration_ms", 0),
                error=r.get("error"),
            )
        )

    if not output_path:
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".html", delete=False, encoding="utf-8"
        )
        tmp.close()
        output_path = tmp.name

    render_html(reconstructed, output_path)
    return {"output_path": output_path, "targets": len(reconstructed)}


def main() -> None:
    """Entry point for `pqready-mcp` and `python -m pqready.mcp_server`."""
    mcp.run()


if __name__ == "__main__":
    main()
