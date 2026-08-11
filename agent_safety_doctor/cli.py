from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import load_config
from .models import ScanResult
from .report import render_html, render_json, render_markdown, write_report
from .scanner import scan_workspace

# Backward-compatible aliases for early tests/imports.
def safety_score(findings_or_result) -> int:
    if isinstance(findings_or_result, ScanResult):
        return findings_or_result.score
    from .models import ScanMetadata

    metadata = ScanMetadata(root=".", started_at="", completed_at="", files_scanned=0, files_skipped=0, bytes_scanned=0)
    return ScanResult(metadata=metadata, findings=list(findings_or_result)).score


def render_report(root: Path, findings_or_result) -> str:
    if isinstance(findings_or_result, ScanResult):
        return render_markdown(findings_or_result)
    from .models import ScanMetadata

    metadata = ScanMetadata(root=str(root), started_at="", completed_at="", files_scanned=0, files_skipped=0, bytes_scanned=0)
    return render_markdown(ScanResult(metadata=metadata, findings=list(findings_or_result)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-safety-doctor",
        description="Scan an AI-agent-accessible workspace for runtime safety risks.",
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit.")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Scan a workspace and write a report.")
    scan.add_argument("path", nargs="?", default=".", help="Workspace path to scan.")
    scan.add_argument("--output", "-o", default="agent-safety-report.md", help="Report output path. Use '-' for stdout.")
    scan.add_argument("--format", "-f", choices=["markdown", "json", "html"], default=None, help="Report format. Defaults from output extension, otherwise markdown.")
    scan.add_argument("--config", help="Path to .agent-safety-doctor.toml config.")
    scan.add_argument("--fail-under", type=int, help="Exit non-zero if safety score is below this threshold.")
    scan.add_argument("--summary", action="store_true", help="Print a compact scan summary to stderr/stdout in addition to writing the report.")
    scan.add_argument("--display-root", help="Override the root path shown in reports; useful for sanitized demos.")
    return parser


def infer_format(output: str, explicit_format: str | None) -> str:
    if explicit_format:
        return explicit_format
    if output == "-":
        return "markdown"
    if Path(output).suffix.lower() == ".json":
        return "json"
    if Path(output).suffix.lower() in {".html", ".htm"}:
        return "html"
    return "markdown"


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        from . import __version__

        print(__version__)
        return 0

    if not args.command:
        parser.print_help()
        return 2

    if args.command == "scan":
        try:
            root = Path(args.path).resolve()
            config = load_config(root, Path(args.config).resolve() if args.config else None)
            result = scan_workspace(root, config, display_root=args.display_root)
            fmt = infer_format(args.output, args.format)
            if args.output == "-":
                if fmt == "json":
                    sys.stdout.write(render_json(result))
                elif fmt == "html":
                    sys.stdout.write(render_html(result))
                else:
                    sys.stdout.write(render_markdown(result))
            else:
                output = Path(args.output)
                write_report(result, output, fmt)
                print(f"Wrote {output} with score {result.score}/100 and {result.counts['total']} findings")
            if args.summary:
                stream = sys.stderr if args.output == "-" else sys.stdout
                print(f"score={result.score} findings={result.counts['total']} high={result.counts['high']} medium={result.counts['medium']}", file=stream)
            if args.fail_under is not None and result.score < args.fail_under:
                print(f"Safety score {result.score}/100 is below fail-under threshold {args.fail_under}", file=sys.stderr)
                return 3
            return 0
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
