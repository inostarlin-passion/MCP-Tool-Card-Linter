from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .auth import BearerTokenProvider, CredentialProvider
from .discovery import (
    SUPPORTED_MCP_PROTOCOL_VERSIONS,
    DiscoveryError,
    discover_from_config,
    discover_from_server_url,
    discover_from_stdio_command,
    load_tools_file,
)
from .lint import lint_sources
from .models import LintConfig, SourceResult
from .oauth import (
    callback_url_from_environment,
    callback_url_from_file,
    complete_authorization,
    start_authorization,
)
from .policy import PROFILES, PolicyConfig, load_policy
from .reporting import (
    ReportError,
    baseline_fingerprints_from_payload,
    exit_code_for_report,
    optimize_from_report,
    report_to_json,
    report_to_jsonl,
    report_to_junit,
    report_to_markdown,
    report_to_sarif,
    report_to_github_annotations,
    write_jsonl_report,
    write_json_report,
    write_junit_report,
    write_markdown_report,
    write_optimization_report,
    write_sarif_report,
)
from .rules import KNOWN_RULE_IDS, list_rule_metadata, rule_metadata
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
        if args.command == "list-rules":
            return _run_list_rules(args)
        if args.command == "explain":
            return _run_explain(args)
        if args.command == "authorize":
            return _run_authorize(args)
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
    except Exception as exc:
        if getattr(args, "debug", False):
            raise
        print(
            f"internal error: {safe_log_text(exc)} (rerun with --debug for a traceback)",
            file=sys.stderr,
        )
        return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-tool-card-linter",
        description="Lint MCP tool metadata for schema quality, description clarity, side effects, and tool-poisoning risks.",
    )
    parser.add_argument("--version", action="version", version=__version__)
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
    lint_parser.add_argument("--sarif-report", help="Write SARIF 2.1.0 for GitHub code scanning")
    lint_parser.add_argument("--junit-report", help="Write JUnit XML for CI test reporting")
    lint_parser.add_argument("--jsonl-report", help="Write streaming JSON Lines records")
    lint_parser.add_argument(
        "--baseline-report",
        help="Compare tool-card SHA-256 fingerprints with a previous JSON report",
    )
    lint_parser.add_argument(
        "--fail-on",
        choices=["critical", "error", "warning", "info", "never"],
        default=None,
        help="Exit with code 1 when findings at this severity or higher are present; source failures return code 2.",
    )
    lint_parser.add_argument(
        "--protocol-version",
        choices=SUPPORTED_MCP_PROTOCOL_VERSIONS,
        default=SUPPORTED_MCP_PROTOCOL_VERSIONS[0],
        help="Newest MCP protocol version to request; a supported previous version may be negotiated.",
    )
    lint_parser.add_argument("--timeout", type=_timeout_seconds, default=10.0, help="Total MCP request timeout in seconds (0.05..300)")
    lint_parser.add_argument(
        "--refresh-on-list-changed",
        type=_optional_timeout_seconds,
        default=0.0,
        metavar="SECONDS",
        help="Wait up to 0..300 seconds for tools/list_changed, then re-list once (default: disabled)",
    )
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
        "--compat-stdio-noise",
        action="store_true",
        help="Skip bounded non-JSON stdout from a reviewed legacy stdio server (strict by default)",
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
    credentials = lint_parser.add_mutually_exclusive_group()
    credentials.add_argument(
        "--bearer-token-env",
        help="Read a pre-issued bearer token from this environment variable",
    )
    credentials.add_argument(
        "--bearer-token-file",
        help="Read a pre-issued bearer token from a private file (never accepts token text on CLI)",
    )
    lint_parser.add_argument("--ca-bundle", help="PEM CA bundle for enterprise/private PKI")
    lint_parser.add_argument("--proxy", help="Explicit HTTP(S) proxy URL without embedded credentials")
    lint_parser.add_argument("--client-cert", help="PEM client certificate chain for mTLS")
    lint_parser.add_argument("--client-key", help="PEM private key for mTLS")
    lint_parser.add_argument("--policy", help="Bounded TOML rule policy or pyproject.toml")
    lint_parser.add_argument("--profile", choices=sorted(PROFILES), help="Override policy profile")
    lint_parser.add_argument(
        "--select",
        action="append",
        default=[],
        metavar="RULE[,RULE...]",
        help="Select exact rule IDs or trailing-* prefixes",
    )
    lint_parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="RULE[,RULE...]",
        help="Ignore exact rule IDs or trailing-* prefixes",
    )
    lint_parser.add_argument(
        "--deterministic",
        action="store_true",
        help="Use a content-derived scan ID and fixed timestamp for reproducible output",
    )
    lint_parser.add_argument("--debug", action="store_true", help="Show unexpected tracebacks")
    lint_parser.add_argument(
        "--format",
        choices=["markdown", "json", "sarif", "junit", "jsonl", "github", "none"],
        default="markdown",
        help="Stdout format. Use none when only report files are desired.",
    )

    optimize_parser = subparsers.add_parser(
        "optimize",
        help="Generate allowlist/approval/block decisions from a JSON lint report",
    )
    optimize_parser.add_argument("--input-report", required=True, help="JSON report generated by lint")
    optimize_parser.add_argument("--output", help="Write optimization JSON to this path")
    optimize_parser.add_argument("--debug", action="store_true", help="Show unexpected tracebacks")

    rules_parser = subparsers.add_parser("list-rules", help="List stable rule metadata")
    rules_parser.add_argument("--format", choices=["text", "json"], default="text")
    rules_parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)

    explain_parser = subparsers.add_parser("explain", help="Explain a stable rule ID")
    explain_parser.add_argument("rule_id", choices=KNOWN_RULE_IDS)
    explain_parser.add_argument("--format", choices=["text", "json"], default="text")
    explain_parser.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)

    authorize_parser = subparsers.add_parser(
        "authorize",
        help="Run MCP OAuth Authorization Code + PKCE for a pre-registered public client",
    )
    authorize_actions = authorize_parser.add_subparsers(
        dest="authorize_command",
        required=True,
    )
    authorize_start = authorize_actions.add_parser(
        "start",
        help="Discover metadata, persist private PKCE state, and print the authorization URL",
    )
    authorize_start.add_argument("--server-url", required=True, help="Protected MCP endpoint")
    authorize_start.add_argument("--client-id", required=True, help="Pre-registered public client ID")
    authorize_start.add_argument("--redirect-uri", required=True, help="Registered HTTPS or localhost redirect URI")
    authorize_start.add_argument("--state-file", required=True, help="New private file for single-use PKCE state")
    authorize_start.add_argument(
        "--scope",
        action="append",
        default=[],
        help="Request one OAuth scope token; repeat for multiple scopes",
    )
    authorize_complete = authorize_actions.add_parser(
        "complete",
        help="Validate the callback, exchange the code, and write a private bearer-token file",
    )
    authorize_complete.add_argument("--state-file", required=True, help="Private PKCE state from authorize start")
    authorize_complete.add_argument("--token-file", required=True, help="Private bearer-token output file")
    callback_source = authorize_complete.add_mutually_exclusive_group(required=True)
    callback_source.add_argument(
        "--callback-url-env",
        help="Read the full callback URL from this environment variable",
    )
    callback_source.add_argument(
        "--callback-url-file",
        help="Read the full callback URL from a mode-0600 file",
    )
    for authorize_action in (authorize_start, authorize_complete):
        authorize_action.add_argument(
            "--timeout",
            type=_timeout_seconds,
            default=10.0,
            help="OAuth request timeout in seconds (0.05..300)",
        )
        authorize_action.add_argument(
            "--allow-private-network",
            action="store_true",
            help="Allow private/reserved OAuth metadata and endpoint destinations",
        )
        authorize_action.add_argument(
            "--allow-insecure-http",
            action="store_true",
            help="Allow plain HTTP OAuth endpoints for explicitly trusted local testing",
        )
        authorize_action.add_argument("--ca-bundle", help="PEM CA bundle")
        authorize_action.add_argument("--proxy", help="Explicit HTTP(S) proxy URL")
        authorize_action.add_argument("--client-cert", help="PEM client certificate chain")
        authorize_action.add_argument("--client-key", help="PEM private key for mTLS")
        authorize_action.add_argument("--debug", action="store_true", help=argparse.SUPPRESS)
    return parser


def _run_lint(args: argparse.Namespace) -> int:
    _validate_lint_paths(args)
    policy = load_policy(args.policy) if args.policy else PolicyConfig()
    policy = policy.with_cli_overrides(
        profile=args.profile,
        select=args.select,
        ignore=args.ignore,
    )
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
        policy=policy,
        deterministic=args.deterministic,
    )
    if args.json_report:
        write_json_report(report, args.json_report)
    if args.markdown_report:
        write_markdown_report(report, args.markdown_report)
    if args.sarif_report:
        write_sarif_report(report, args.sarif_report)
    if args.junit_report:
        write_junit_report(report, args.junit_report)
    if args.jsonl_report:
        write_jsonl_report(report, args.jsonl_report)
    if args.format == "markdown":
        print(report_to_markdown(report), end="")
    elif args.format == "json":
        print(report_to_json(report))
    elif args.format == "sarif":
        print(report_to_sarif(report))
    elif args.format == "junit":
        print(report_to_junit(report), end="")
    elif args.format == "jsonl":
        print(report_to_jsonl(report), end="")
    elif args.format == "github":
        print(report_to_github_annotations(report), end="")
    fail_on = args.fail_on or policy.fail_on or "error"
    exit_code = exit_code_for_report(report, fail_on)
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
    credential_provider = _credential_provider(args)
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
            compat_stdio_noise=args.compat_stdio_noise,
            protocol_version=args.protocol_version,
            credential_provider=credential_provider,
            ca_bundle=args.ca_bundle,
            proxy_url=args.proxy,
            client_cert=args.client_cert,
            client_key=args.client_key,
            refresh_on_list_changed=args.refresh_on_list_changed,
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
                compat_stdio_noise=args.compat_stdio_noise,
                protocol_version=args.protocol_version,
                refresh_on_list_changed=args.refresh_on_list_changed,
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
                protocol_version=args.protocol_version,
                credential_provider=credential_provider,
                ca_bundle=args.ca_bundle,
                proxy_url=args.proxy,
                client_cert=args.client_cert,
                client_key=args.client_key,
                refresh_on_list_changed=args.refresh_on_list_changed,
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


def _run_list_rules(args: argparse.Namespace) -> int:
    rules = list_rule_metadata()
    if args.format == "json":
        print(json.dumps(rules, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        for rule in rules:
            print(f"{rule['id']}\t{rule['category']}\t{rule['title']}")
    return 0


def _run_explain(args: argparse.Namespace) -> int:
    rule = rule_metadata(args.rule_id).to_dict()
    if args.format == "json":
        print(json.dumps(rule, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(f"{rule['id']}: {rule['title']}")
        print(f"Category: {rule['category']}")
        print(f"Confidence: {rule['confidence']}")
        print(f"References: {', '.join(rule['references'])}")
    return 0


def _run_authorize(args: argparse.Namespace) -> int:
    network = {
        "timeout": args.timeout,
        "allow_private_network": args.allow_private_network,
        "allow_insecure_http": args.allow_insecure_http,
        "ca_bundle": args.ca_bundle,
        "proxy_url": args.proxy,
        "client_cert": args.client_cert,
        "client_key": args.client_key,
    }
    if args.authorize_command == "start":
        result = start_authorization(
            args.server_url,
            client_id=args.client_id,
            redirect_uri=args.redirect_uri,
            state_file=args.state_file,
            scopes=args.scope,
            **network,
        )
    elif args.authorize_command == "complete":
        callback_url = (
            callback_url_from_environment(args.callback_url_env)
            if args.callback_url_env
            else callback_url_from_file(args.callback_url_file)
        )
        state_path = _resolved_path(args.state_file)
        token_path = _resolved_path(args.token_file)
        if state_path == token_path:
            raise InputValidationError("OAuth token file must differ from the state file")
        if args.callback_url_file and token_path == _resolved_path(args.callback_url_file):
            raise InputValidationError("OAuth token file must not overwrite the callback file")
        for option_name, input_path in (
            ("CA bundle", args.ca_bundle),
            ("client certificate", args.client_cert),
            ("client key", args.client_key),
        ):
            if input_path and token_path == _resolved_path(input_path):
                raise InputValidationError(
                    f"OAuth token file must not overwrite the {option_name}"
                )
        result = complete_authorization(
            state_file=args.state_file,
            callback_url=callback_url,
            token_file=args.token_file,
            **network,
        )
    else:
        raise InputValidationError("Unknown authorize action")
    print(
        json.dumps(
            result,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
    )
    return 0


def _credential_provider(args: argparse.Namespace) -> CredentialProvider | None:
    if args.bearer_token_env:
        return BearerTokenProvider.from_environment(args.bearer_token_env)
    if args.bearer_token_file:
        return BearerTokenProvider.from_file(args.bearer_token_file)
    return None


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


def _optional_timeout_seconds(value: str) -> float:
    try:
        number = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if not math.isfinite(number) or not 0 <= number <= 300:
        raise argparse.ArgumentTypeError("must be finite and in 0..300")
    return number


def _validate_lint_paths(args: argparse.Namespace) -> None:
    outputs = [
        _resolved_path(value)
        for value in (
            args.json_report,
            args.markdown_report,
            args.sarif_report,
            args.junit_report,
            args.jsonl_report,
        )
        if value
    ]
    if len(outputs) != len(set(outputs)):
        raise ReportError("JSON and Markdown reports must use different paths")
    inputs = [
        _resolved_path(value)
        for value in (
            args.tools_file,
            args.config,
            args.baseline_report,
            args.policy,
            args.bearer_token_file,
            args.ca_bundle,
            args.client_cert,
            args.client_key,
        )
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
