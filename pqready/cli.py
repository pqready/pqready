"""click-based CLI entry point for pqready."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .core.certs import scan_cert_file
from .core.models import ScanResult, Severity
from .core.source import scan_source
from .core.tls import scan_tls
from .reporters.html import render_html

_SEV_STYLES = {
    Severity.CRITICAL: {"fg": "red", "bold": True, "symbol": "✗"},
    Severity.HIGH: {"fg": "yellow", "bold": True, "symbol": "✗"},
    Severity.MEDIUM: {"fg": "yellow", "bold": False, "symbol": "!"},
    Severity.LOW: {"fg": "blue", "bold": False, "symbol": "·"},
    Severity.INFO: {"fg": "green", "bold": False, "symbol": "✓"},
}

_CERT_SUFFIXES = {".pem", ".crt", ".cer", ".key"}


@click.group()
@click.version_option(package_name="pqready")
def main() -> None:
    """pqready — post-quantum cryptography readiness scanner."""


@main.command("tls")
@click.argument("hostname")
@click.option("--port", default=443, show_default=True, type=int)
@click.option("--output", type=click.Path(dir_okay=False), default=None,
              help="Write a full HTML report to this path.")
def cli_tls(hostname: str, port: int, output: str | None) -> None:
    """Scan a TLS endpoint for PQC readiness."""
    with click.progressbar(length=1, label=f"scanning {hostname}:{port}") as bar:
        result = scan_tls(hostname, port)
        bar.update(1)
    _print_summary(result, header=f"TLS scan · {hostname}:{port}")
    _maybe_write_report([result], output)
    sys.exit(_exit_code([result]))


@main.command("source")
@click.argument("path", type=click.Path(exists=True))
@click.option("--output", type=click.Path(dir_okay=False), default=None,
              help="Write a full HTML report to this path.")
def cli_source(path: str, output: str | None) -> None:
    """Scan a directory or file for vulnerable crypto patterns."""
    with click.progressbar(length=1, label=f"scanning {path}") as bar:
        results = scan_source(path)
        bar.update(1)
    for r in results:
        if r.findings or r.error:
            _print_summary(r, header=f"Source scan · {r.target}")
    _print_aggregate(results)
    _maybe_write_report(results, output)
    sys.exit(_exit_code(results))


@main.command("cert")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option("--output", type=click.Path(dir_okay=False), default=None,
              help="Write a full HTML report to this path.")
def cli_cert(path: str, output: str | None) -> None:
    """Parse and assess a PEM/CRT/KEY file."""
    with click.progressbar(length=1, label=f"parsing {path}") as bar:
        result = scan_cert_file(path)
        bar.update(1)
    _print_summary(result, header=f"Cert scan · {path}")
    _maybe_write_report([result], output)
    sys.exit(_exit_code([result]))


@main.command("scan")
@click.argument("target")
@click.option("--output", type=click.Path(dir_okay=False), default=None,
              help="Write a full HTML report to this path.")
@click.pass_context
def cli_scan(ctx: click.Context, target: str, output: str | None) -> None:
    """Auto-detect target type (host, path, or cert file) and scan."""
    p = Path(target)
    if p.exists():
        if p.is_file() and p.suffix.lower() in _CERT_SUFFIXES:
            ctx.invoke(cli_cert, path=str(p), output=output)
        else:
            ctx.invoke(cli_source, path=str(p), output=output)
    else:
        host, _, port = target.partition(":")
        ctx.invoke(cli_tls, hostname=host, port=int(port) if port else 443, output=output)


def _print_summary(result: ScanResult, header: str) -> None:
    bar = "─" * max(len(header), 40)
    click.echo(click.style(f"pqready · {header}", bold=True))
    click.echo(bar)

    if result.error:
        click.echo(click.style(f"  error: {result.error}", fg="red"))
        click.echo(bar)
        click.echo("")
        return

    if not result.findings:
        click.echo(click.style("  no findings", fg="green"))
    else:
        for f in _sorted_findings(result):
            style = _SEV_STYLES[f.severity]
            label = click.style(
                f"{style['symbol']} {f.severity.value.upper():<8} {f.id:<7}",
                fg=style["fg"],
                bold=style["bold"],
            )
            click.echo(f"{label} {f.title}")

    score = result.risk_score
    pqc = "YES" if result.pqc_ready else "NO"
    pqc_color = "green" if result.pqc_ready else "red"
    click.echo(
        f"Risk score: {score}/100  ·  PQC-ready: "
        + click.style(pqc, fg=pqc_color, bold=True)
    )
    click.echo(bar)
    click.echo("")


def _print_aggregate(results: list[ScanResult]) -> None:
    if len(results) <= 1:
        return
    total_findings = sum(len(r.findings) for r in results)
    total_score = min(sum(r.risk_score for r in results), 100)
    pqc_ready = all(r.pqc_ready for r in results)
    pqc_color = "green" if pqc_ready else "red"
    click.echo(click.style("Aggregate", bold=True))
    click.echo("─" * 40)
    click.echo(f"Files scanned : {len(results)}")
    click.echo(f"Total findings: {total_findings}")
    click.echo(f"Risk score    : {total_score}/100")
    click.echo("PQC-ready     : " + click.style("YES" if pqc_ready else "NO", fg=pqc_color, bold=True))
    click.echo("─" * 40)
    click.echo("")


def _sorted_findings(result: ScanResult):
    order = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }
    return sorted(result.findings, key=lambda f: (order[f.severity], f.id))


def _maybe_write_report(results: list[ScanResult], output: str | None) -> None:
    if output:
        render_html(results, output)
        click.echo(click.style(f"Wrote HTML report → {output}", fg="cyan"))
    else:
        click.echo("Run with --output report.html to generate a full report.")


def _exit_code(results: list[ScanResult]) -> int:
    if any(r.error for r in results):
        return 2
    for r in results:
        for f in r.findings:
            if f.severity in (Severity.CRITICAL, Severity.HIGH):
                return 1
    return 0


if __name__ == "__main__":
    main()
