from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Sequence

from .discovery import (
    DiscoveryError,
    discover_from_config,
    discover_from_server_url,
    discover_from_stdio_command,
    load_tools_file,
)
from .lint import lint_sources
from .models import LintConfig, SourceResult
from .reporting import (
    ReportError,
    baseline_fingerprints_from_payload,
    exit_code_for_report,
    optimize_from_report,
    report_to_json,
    report_to_markdown,
    write_json_report,
    write_markdown_report,
    write_optimization_report,
)
from .security import (
    MAX_HTTP_RESPONSE_BYTES,
    InputValidationError,
    load_json_file,
    safe_log_text,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "lint":
            return _run_lint(args)
        if args.command == "optimize":
            return _run_optimize(args)
        parser.print_help(sys.stderr)
        return 2
    except (DiscoveryError, ReportError, InputValidationError) as exc:
        print(f"error: {safe_log_text(exc)}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"io error: {safe_log_text(exc)}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-tool-card-linter",
        description="Lint MCP tool metadata for schema quality, description clarity, side effects, and tool-poisoning risks.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    lint_parser = subparsers.add_parser("lint", help="Discover and lint MCP tools")
    source = lint_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--tools-file", help="JSON file containing tools or result.tools")
    source.add_argument("--config", help="MCP config file containing mcpServers")
    source.add_argument("--stdio", help="Command line for a stdio MCP server")
    source.add_argument("--server-url", help="Streamable HTTP MCP endpoint URL")
    lint_parser.add_argument("--server", help="Server name for config filtering or report labeling")
    lint_parser.add_argument("--json-report", help="Write machine-readable JSON report")
    lint_parser.add_argument("--markdown-report", help="Write human-readable Markdown report")
    lint_parser.add_argument(
        "--baseline-report",
        help="Compare tool-card SHA-256 fingerprints with a previous JSON report",
    )
    lint_parser.add_argument(
        "--fail-on",
        choices=["critical", "error", "warning", "info", "never"],
        default="error",
        help="Exit with code 1 when findings at this severity or higher are present; source failures return code 2.",
    )
    lint_parser.add_argument("--timeout", type=_timeout_seconds, default=10.0, help="Total MCP request timeout in seconds (0.05..300)")
    lint_parser.add_argument("--max-tools", type=lambda value: _bounded_int(value, 100_000), default=1000, help="Maximum tools to lint per source")
    lint_parser.add_argument("--concurrency", type=lambda value: _bounded_int(value, 32), default=4, help="Concurrent servers for config discovery (max 32)")
    lint_parser.add_argument("--max-pages", type=lambda value: _bounded_int(value, 10_000), default=100, help="Maximum tools/list pages per source")
    lint_parser.add_argument("--max-response-bytes", type=lambda value: _bounded_int(value, 16 * 1024 * 1024), default=MAX_HTTP_RESPONSE_BYTES, help="Maximum HTTP response bytes")
    lint_parser.add_argument("--max-schema-depth", type=lambda value: _bounded_int(value, 64), default=8)
    lint_parser.add_argument("--max-schema-properties", type=lambda value: _bounded_int(value, 100_000), default=2000)
    lint_parser.add_argument("--max-card-chars", type=lambda value: _bounded_int(value, 1_000_000), default=2800)
    lint_parser.add_argument("--max-description-chars", type=lambda value: _bounded_int(value, 100_000), default=1200)
    lint_parser.add_argument(
        "--allow-config-execution",
        action="store_true",
        help="Execute local commands found in a reviewed config file",
    )
    lint_parser.add_argument(
        "--inherit-env",
        action="store_true",
        help="Pass the full parent environment to stdio servers (may expose secrets)",
    )
    lint_parser.add_argument(
        "--allow-private-network",
        action="store_true",
        help="Allow private/reserved destinations and config-sourced loopback URLs",
    )
    lint_parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="Allow plain HTTP for non-loopback destinations",
    )
    lint_parser.add_argument(
        "--format",
        choices=["markdown", "json", "none"],
        default="markdown",
        help="Stdout format. Use none when only report files are desired.",
    )

    optimize_parser = subparsers.add_parser(
        "optimize",
        help="Generate allowlist/approval/block decisions from a JSON lint report",
    )
    optimize_parser.add_argument("--input-report", required=True, help="JSON report generated by lint")
    optimize_parser.add_argument("--output", help="Write optimization JSON to this path")
    return parser


def _run_lint(args: argparse.Namespace) -> int:
    _validate_lint_paths(args)
    baseline_fingerprints = None
    if args.baseline_report:
        baseline_payload = load_json_file(args.baseline_report)
        baseline_fingerprints = baseline_fingerprints_from_payload(baseline_payload)
    sources = _discover_sources(args)
    config = LintConfig(
        max_tools=args.max_tools,
        max_schema_depth=args.max_schema_depth,
        max_schema_properties=args.max_schema_properties,
        max_card_chars=args.max_card_chars,
        max_description_chars=args.max_description_chars,
    )
    report = lint_sources(
        sources,
        config,
        baseline_fingerprints=baseline_fingerprints,
    )
    if args.json_report:
        write_json_report(report, args.json_report)
    if args.markdown_report:
        write_markdown_report(report, args.markdown_report)
    if args.format == "markdown":
        print(report_to_markdown(report), end="")
    elif args.format == "json":
        print(report_to_json(report))
    exit_code = exit_code_for_report(report, args.fail_on)
    if exit_code == 2:
        for source in report.sources:
            for error in source.get("errors", []):
                print(
                    f"source error [{safe_log_text(source.get('server_name', 'unknown'))}]: "
                    f"{safe_log_text(error)}",
                    file=sys.stderr,
                )
    return exit_code


def _discover_sources(args: argparse.Namespace) -> list[SourceResult]:
    if args.tools_file:
        server_name = args.server or "static"
        return [load_tools_file(args.tools_file, server_name=server_name)]
    if args.config:
        return discover_from_config(
            args.config,
            server_filter=args.server,
            timeout=args.timeout,
            max_tools=args.max_tools,
            concurrency=args.concurrency,
            max_pages=args.max_pages,
            max_response_bytes=args.max_response_bytes,
            allow_private_network=args.allow_private_network,
            allow_insecure_http=args.allow_insecure_http,
            allow_command_execution=args.allow_config_execution,
            inherit_env=args.inherit_env,
        )
    if args.stdio:
        return [
            discover_from_stdio_command(
                args.stdio,
                server_name=args.server or "stdio",
                timeout=args.timeout,
                max_tools=args.max_tools,
                max_pages=args.max_pages,
                inherit_env=args.inherit_env,
            )
        ]
    if args.server_url:
        return [
            discover_from_server_url(
                args.server_url,
                server_name=args.server or "http",
                timeout=args.timeout,
                max_tools=args.max_tools,
                max_pages=args.max_pages,
                max_response_bytes=args.max_response_bytes,
                allow_private_network=args.allow_private_network,
                allow_insecure_http=args.allow_insecure_http,
            )
        ]
    raise DiscoveryError("No source selected")


def _run_optimize(args: argparse.Namespace) -> int:
    if args.output and _resolved_path(args.output) == _resolved_path(args.input_report):
        raise ReportError("Optimization output must not overwrite its input report")
    payload = load_json_file(args.input_report)
    optimized = optimize_from_report(payload)
    text = (
        json.dumps(
            optimized,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    )
    if args.output:
        write_optimization_report(optimized, args.output)
    else:
        print(text, end="")
    return 0


def _bounded_int(value: str, maximum: int) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= number <= maximum:
        raise argparse.ArgumentTypeError(f"must be in 1..{maximum}")
    return number


def _timeout_seconds(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(number) or not 0.05 <= number <= 300:
        raise argparse.ArgumentTypeError("must be finite and in 0.05..300")
    return number


def _validate_lint_paths(args: argparse.Namespace) -> None:
    outputs = [
        _resolved_path(value)
        for value in (args.json_report, args.markdown_report)
        if value
    ]
    if len(outputs) != len(set(outputs)):
        raise ReportError("JSON and Markdown reports must use different paths")
    inputs = [
        _resolved_path(value)
        for value in (args.tools_file, args.config, args.baseline_report)
        if value
    ]
    overlap = set(outputs) & set(inputs)
    if overlap:
        raise ReportError(
            f"Report output must not overwrite an input file: {safe_log_text(next(iter(overlap)))}"
        )


def _resolved_path(value: str) -> Path:
    try:
        return Path(value).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ReportError(f"Invalid path: {safe_log_text(exc)}") from exc
