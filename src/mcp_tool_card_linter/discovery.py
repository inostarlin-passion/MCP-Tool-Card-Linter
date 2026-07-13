from __future__ import annotations

import json
import math
import os
import queue
import re
import shlex
import signal
import ssl
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import __version__
from .auth import CredentialProvider
from .models import MAX_LINT_TOOLS, SourceResult, ToolCard
from .security import (
    MAX_HTTP_ERROR_BYTES,
    MAX_HTTP_RESPONSE_BYTES,
    InputValidationError,
    load_json_file,
    redact_command,
    redact_url,
    safe_log_text,
    strict_json_loads,
    validate_mcp_url,
)

SUPPORTED_MCP_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")
MCP_PROTOCOL_VERSION = SUPPORTED_MCP_PROTOCOL_VERSIONS[0]
MAX_STDERR_LINES = 100
MAX_STDERR_LINE_BYTES = 4096
MAX_STDIO_MESSAGE_BYTES = 4 * 1024 * 1024
MAX_SKIPPED_STDIO_MESSAGES = 1000
MAX_BUFFERED_STDOUT_MESSAGES = 8
MAX_CONFIG_SERVERS = 128
MAX_COMMAND_ARGS = 256
MAX_COMMAND_ARG_CHARS = 8192
MAX_COMMAND_CHARS = 65_536
MAX_ENV_VARS = 256
MAX_ENV_VALUE_CHARS = 65_536
MAX_ENV_TOTAL_CHARS = 1_048_576
MAX_SERVER_NAME_CHARS = 256
MAX_PAGES_LIMIT = 10_000
MAX_RESPONSE_BYTES_LIMIT = 16 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 300.0
MAX_HTTP_RETRIES = 3
MAX_RETRY_AFTER_SECONDS = 30.0
MAX_SSE_EVENTS = 10_000
MAX_SSE_LINE_BYTES = 64 * 1024
MAX_SSE_RECONNECTS = 3
MAX_SESSION_RECOVERIES = 1
_TRANSIENT_HTTP_CODES = {429, 502, 503, 504}
_TERMINATE_SIGNAL = signal.SIGTERM
_KILL_SIGNAL = getattr(signal, "SIGKILL", signal.SIGTERM)
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_SAFE_INHERITED_ENV = {
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SYSTEMROOT",
    "COMSPEC",
    "PATHEXT",
    "WINDIR",
}


class DiscoveryError(RuntimeError):
    """Raised when a tool source cannot be discovered safely."""


class JsonRpcError(DiscoveryError):
    """Raised for malformed or unsuccessful JSON-RPC messages."""


class UnsupportedFeatureError(DiscoveryError):
    """Raised when negotiated capabilities do not permit an operation."""


class SessionExpiredError(DiscoveryError):
    """Raised when a Streamable HTTP server terminates an MCP session."""


def load_tools_file(
    path: str | Path,
    *,
    server_name: str = "static",
) -> SourceResult:
    _validate_server_name(server_name)
    payload = _load_json_file(path)
    tools = extract_tools(payload)
    return _source_from_raw_tools(
        server_name=server_name,
        source_type="tools-file",
        raw_tools=tools,
        metadata={"path": str(Path(path).expanduser().resolve())},
    )


def discover_from_stdio_command(
    command_text: str,
    *,
    server_name: str = "stdio",
    timeout: float = 10.0,
    max_tools: int = 1000,
    max_pages: int = 100,
    inherit_env: bool = False,
    compat_stdio_noise: bool = False,
    protocol_version: str = MCP_PROTOCOL_VERSION,
    refresh_on_list_changed: float = 0.0,
) -> SourceResult:
    _validate_server_name(server_name)
    _validate_optional_timeout("refresh_on_list_changed", refresh_on_list_changed)
    if not isinstance(command_text, str) or not command_text.strip():
        raise DiscoveryError("--stdio command is empty")
    if len(command_text) > MAX_COMMAND_CHARS or "\x00" in command_text:
        raise DiscoveryError("--stdio command is too long or contains a NUL byte")
    try:
        command = shlex.split(command_text)
    except ValueError as exc:
        raise DiscoveryError(f"Invalid --stdio command quoting: {safe_log_text(exc)}") from exc
    with StdioMcpClient(
        command,
        timeout=timeout,
        inherit_env=inherit_env,
        compat_stdio_noise=compat_stdio_noise,
        protocol_version=protocol_version,
    ) as client:
        raw_tools = client.list_tools(max_tools=max_tools, max_pages=max_pages)
        list_changed = False
        if refresh_on_list_changed > 0:
            list_changed = client.wait_for_tools_list_changed(refresh_on_list_changed)
            if list_changed:
                raw_tools = client.list_tools(max_tools=max_tools, max_pages=max_pages)
        protocol_metadata = client.discovery_metadata()
    return _source_from_raw_tools(
        server_name=server_name,
        source_type="stdio",
        raw_tools=raw_tools,
        metadata={
            "command": redact_command(command),
            "compat_stdio_noise": compat_stdio_noise,
            "list_changed_received": list_changed,
            "refresh_count": int(list_changed),
            **protocol_metadata,
        },
    )


def discover_from_server_url(
    url: str,
    *,
    server_name: str = "http",
    timeout: float = 10.0,
    max_tools: int = 1000,
    max_pages: int = 100,
    max_response_bytes: int = MAX_HTTP_RESPONSE_BYTES,
    allow_private_network: bool = False,
    allow_insecure_http: bool = False,
    allow_loopback: bool = True,
    protocol_version: str = MCP_PROTOCOL_VERSION,
    credential_provider: CredentialProvider | None = None,
    ca_bundle: str | None = None,
    proxy_url: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    refresh_on_list_changed: float = 0.0,
) -> SourceResult:
    _validate_server_name(server_name)
    _validate_optional_timeout("refresh_on_list_changed", refresh_on_list_changed)
    with StreamableHttpMcpClient(
        url,
        timeout=timeout,
        max_response_bytes=max_response_bytes,
        allow_private_network=allow_private_network,
        allow_insecure_http=allow_insecure_http,
        allow_loopback=allow_loopback,
        protocol_version=protocol_version,
        credential_provider=credential_provider,
        ca_bundle=ca_bundle,
        proxy_url=proxy_url,
        client_cert=client_cert,
        client_key=client_key,
    ) as client:
        raw_tools = client.list_tools(max_tools=max_tools, max_pages=max_pages)
        list_changed = False
        if refresh_on_list_changed > 0:
            list_changed = client.wait_for_tools_list_changed(refresh_on_list_changed)
            if list_changed:
                raw_tools = client.list_tools(max_tools=max_tools, max_pages=max_pages)
        protocol_metadata = client.discovery_metadata()
    return _source_from_raw_tools(
        server_name=server_name,
        source_type="streamable-http",
        raw_tools=raw_tools,
        metadata={
            "url": redact_url(url),
            "list_changed_received": list_changed,
            "refresh_count": int(list_changed),
            **protocol_metadata,
        },
    )


def discover_from_config(
    path: str | Path,
    *,
    server_filter: str | None = None,
    timeout: float = 10.0,
    max_tools: int = 1000,
    concurrency: int = 4,
    max_pages: int = 100,
    max_response_bytes: int = MAX_HTTP_RESPONSE_BYTES,
    allow_private_network: bool = False,
    allow_insecure_http: bool = False,
    allow_command_execution: bool = False,
    inherit_env: bool = False,
    compat_stdio_noise: bool = False,
    protocol_version: str = MCP_PROTOCOL_VERSION,
    credential_provider: CredentialProvider | None = None,
    ca_bundle: str | None = None,
    proxy_url: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
    refresh_on_list_changed: float = 0.0,
) -> list[SourceResult]:
    _validate_timeout(timeout)
    _validate_positive_int("max_tools", max_tools, MAX_LINT_TOOLS)
    _validate_positive_int("concurrency", concurrency, 32)
    _validate_positive_int("max_pages", max_pages, MAX_PAGES_LIMIT)
    _validate_positive_int(
        "max_response_bytes", max_response_bytes, MAX_RESPONSE_BYTES_LIMIT
    )
    _validate_protocol_version(protocol_version)
    _validate_optional_timeout("refresh_on_list_changed", refresh_on_list_changed)
    if server_filter is not None:
        _validate_server_name(server_filter)

    payload = _load_json_file(path)
    servers = _extract_servers(payload)
    if server_filter:
        servers = {name: cfg for name, cfg in servers.items() if name == server_filter}
        if not servers:
            raise DiscoveryError(f"Server '{safe_log_text(server_filter)}' not found in config")
    if not servers:
        raise DiscoveryError("No MCP servers found in config")

    workers = min(concurrency, len(servers))
    results: list[SourceResult] = []
    config_path = str(Path(path).expanduser().resolve())
    with ThreadPoolExecutor(
        max_workers=workers,
        thread_name_prefix="mcp-discovery",
    ) as executor:
        futures = {
            executor.submit(
                _discover_config_server,
                name,
                cfg,
                timeout,
                max_tools,
                max_pages,
                max_response_bytes,
                allow_private_network,
                allow_insecure_http,
                allow_command_execution,
                inherit_env,
                compat_stdio_noise,
                protocol_version,
                credential_provider,
                ca_bundle,
                proxy_url,
                client_cert,
                client_key,
                refresh_on_list_changed,
            ): name
            for name, cfg in sorted(servers.items())
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # A failed server must not suppress other results.
                results.append(
                    SourceResult(
                        server_name=name,
                        source_type="config",
                        errors=[safe_log_text(exc)],
                        metadata={"config_path": config_path},
                    )
                )
    return sorted(results, key=lambda item: item.server_name)


class StdioMcpClient:
    def __init__(
        self,
        command: list[str],
        *,
        timeout: float = 10.0,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        inherit_env: bool = False,
        compat_stdio_noise: bool = False,
        protocol_version: str = MCP_PROTOCOL_VERSION,
    ) -> None:
        self.command = _validate_command(command)
        self.timeout = _validate_timeout(timeout)
        self.cwd = _validate_cwd(cwd)
        self.env = _validate_env(env or {})
        self.inherit_env = bool(inherit_env)
        self.compat_stdio_noise = bool(compat_stdio_noise)
        self.requested_protocol_version = _validate_protocol_version(protocol_version)
        self.negotiated_protocol_version: str | None = None
        self.server_capabilities: dict[str, Any] | None = None
        self.server_info: dict[str, Any] | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._request_id = 0
        self._request_lock = threading.Lock()
        self._stdout_messages: queue.Queue[bytes | None] = queue.Queue(
            maxsize=MAX_BUFFERED_STDOUT_MESSAGES
        )
        self._stdout_overflow = threading.Event()
        self._stdout_thread: threading.Thread | None = None
        self._stderr_lines: queue.Queue[str] = queue.Queue(maxsize=MAX_STDERR_LINES)
        self._stderr_thread: threading.Thread | None = None
        self._tools_changed_pending: bool = False

    def __enter__(self) -> "StdioMcpClient":
        self.start()
        try:
            self.initialize()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def start(self) -> None:
        if self._proc is not None:
            return
        self._stdout_messages = queue.Queue(maxsize=MAX_BUFFERED_STDOUT_MESSAGES)
        self._stdout_overflow.clear()
        self._stderr_lines = queue.Queue(maxsize=MAX_STDERR_LINES)
        environment = (
            os.environ.copy()
            if self.inherit_env
            else {key: value for key, value in os.environ.items() if key in _SAFE_INHERITED_ENV}
        )
        environment.update(self.env)
        try:
            self._proc = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                start_new_session=os.name == "posix",
            )
        except OSError as exc:
            raise DiscoveryError(
                f"Failed to start stdio MCP server: {safe_log_text(exc)}"
            ) from exc
        self._stdout_thread = threading.Thread(
            target=self._drain_stdout,
            name="mcp-stdout-drain",
            daemon=True,
        )
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr,
            name="mcp-stderr-drain",
            daemon=True,
        )
        self._stdout_thread.start()
        self._stderr_thread.start()

    def initialize(self) -> None:
        result = self.request(
            "initialize",
            {
                "protocolVersion": self.requested_protocol_version,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-tool-card-linter",
                    "version": __version__,
                },
            },
        )
        (
            self.negotiated_protocol_version,
            self.server_capabilities,
            self.server_info,
        ) = _validate_initialize_result(result)
        self.notify("notifications/initialized", {})

    def list_tools(
        self,
        *,
        max_tools: int = 1000,
        max_pages: int = 100,
    ) -> list[Any]:
        _validate_positive_int("max_tools", max_tools, MAX_LINT_TOOLS)
        _validate_positive_int("max_pages", max_pages, MAX_PAGES_LIMIT)
        _require_tools_capability(self.server_capabilities)
        tools: list[Any] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _page in range(max_pages):
            params = {"cursor": cursor} if cursor else {}
            result = self.request("tools/list", params)
            page_tools, next_cursor = _validate_tools_page(result)
            for tool in page_tools:
                if len(tools) >= max_tools:
                    return tools
                tools.append(tool)
            if next_cursor is None:
                return tools
            if next_cursor in seen_cursors:
                raise JsonRpcError("tools/list pagination cursor repeated")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise DiscoveryError(f"tools/list exceeded the {max_pages} page limit")

    def wait_for_tools_list_changed(self, timeout: float) -> bool:
        _require_list_changed_capability(self.server_capabilities)
        wait_timeout = _validate_optional_timeout("list changed timeout", timeout)
        if wait_timeout == 0:
            return False
        with self._request_lock:
            if self._tools_changed_pending:
                self._tools_changed_pending = False
                return True
            deadline = time.monotonic() + wait_timeout
            skipped = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                try:
                    raw_line = self._stdout_messages.get(timeout=remaining)
                except queue.Empty:
                    return False
                if raw_line is None:
                    raise DiscoveryError(
                        "stdio server exited while waiting for notifications/tools/list_changed"
                    )
                message = _decode_stdio_message(
                    raw_line,
                    compat_stdio_noise=self.compat_stdio_noise,
                )
                if message is None:
                    skipped += 1
                elif _is_tools_list_changed_notification(message):
                    return True
                else:
                    server_response = _server_request_response(message)
                    if server_response is not None:
                        self._write_message(server_response)
                    skipped += 1
                if skipped > MAX_SKIPPED_STDIO_MESSAGES:
                    raise JsonRpcError(
                        "Too many unrelated messages while waiting for tools/list_changed"
                    )

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        with self._request_lock:
            self._request_id += 1
            request_id = self._request_id
            message: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
            }
            if params is not None:
                message["params"] = params
            self._write_message(message)
            return self._read_response(request_id)

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        with self._request_lock:
            self._write_message(message)

    def close(self) -> None:
        with self._request_lock:
            self._close_unlocked()

    def _close_unlocked(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        except OSError:
            pass

        exited_cleanly = False
        try:
            proc.wait(timeout=1.0)
            exited_cleanly = True
        except subprocess.TimeoutExpired:
            _signal_process_tree(proc, _TERMINATE_SIGNAL)
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                _signal_process_tree(proc, _KILL_SIGNAL)
                try:
                    proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if exited_cleanly and os.name == "posix":
                _signal_process_group(proc.pid, _TERMINATE_SIGNAL)
            for thread in (self._stdout_thread, self._stderr_thread):
                if thread is not None:
                    thread.join(timeout=0.5)
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream and not stream.closed:
                        stream.close()
                except OSError:
                    pass
            for thread in (self._stdout_thread, self._stderr_thread):
                if thread is not None and thread.is_alive():
                    thread.join(timeout=0.5)
            self._stdout_thread = None
            self._stderr_thread = None
            self._proc = None

    def _write_message(self, message: dict[str, Any]) -> None:
        proc = self._ensure_running()
        if proc.stdin is None:
            raise DiscoveryError("stdio server stdin is unavailable")
        raw = (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            proc.stdin.write(raw)
            proc.stdin.flush()
        except OSError as exc:
            raise DiscoveryError(
                f"Failed to write JSON-RPC message to stdio server: {safe_log_text(exc)}"
            ) from exc

    def _read_response(self, request_id: int) -> Any:
        proc = self._proc
        if proc is None:
            raise DiscoveryError("stdio MCP server is not running")
        deadline = time.monotonic() + self.timeout
        skipped = 0
        while True:
            if self._stdout_overflow.is_set():
                raise DiscoveryError(
                    f"stdio server produced more than {MAX_BUFFERED_STDOUT_MESSAGES} buffered messages"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DiscoveryError(
                    f"Timed out waiting for JSON-RPC response id={request_id}. "
                    f"stderr_tail={self.stderr_tail()}"
                )
            try:
                raw_line = self._stdout_messages.get(timeout=remaining)
            except queue.Empty:
                continue
            if self._stdout_overflow.is_set():
                raise DiscoveryError(
                    f"stdio server produced more than {MAX_BUFFERED_STDOUT_MESSAGES} buffered messages"
                )
            if raw_line is None:
                raise DiscoveryError(
                    f"stdio server exited before response id={request_id}. "
                    f"returncode={proc.poll()} stderr_tail={self.stderr_tail()}"
                )
            message = _decode_stdio_message(
                raw_line,
                compat_stdio_noise=self.compat_stdio_noise,
            )
            if message is None:
                skipped += 1
                if skipped > MAX_SKIPPED_STDIO_MESSAGES:
                    raise JsonRpcError("Too many invalid messages on stdio stdout")
                continue
            server_response = _server_request_response(message)
            if server_response is not None:
                self._write_message(server_response)
                skipped += 1
                if skipped > MAX_SKIPPED_STDIO_MESSAGES:
                    raise JsonRpcError("Too many unrelated messages on stdio stdout")
                continue
            if message.get("id") != request_id:
                if _is_tools_list_changed_notification(message):
                    self._tools_changed_pending = True
                skipped += 1
                if skipped > MAX_SKIPPED_STDIO_MESSAGES:
                    raise JsonRpcError("Too many unrelated messages on stdio stdout")
                continue
            return _jsonrpc_result(message, request_id)

    def _ensure_running(self) -> subprocess.Popen[bytes]:
        proc = self._proc
        if proc is None:
            raise DiscoveryError("stdio MCP server is not running")
        if proc.poll() is not None:
            raise DiscoveryError(
                f"stdio server has exited with code {proc.returncode}. "
                f"stderr_tail={self.stderr_tail()}"
            )
        return proc

    def _drain_stdout(self) -> None:
        proc = self._proc
        if proc is None or proc.stdout is None:
            self._enqueue_stdout(None)
            return
        while True:
            try:
                raw_line = proc.stdout.readline(MAX_STDIO_MESSAGE_BYTES + 1)
            except (OSError, ValueError):
                self._enqueue_stdout(None)
                return
            if not raw_line:
                self._enqueue_stdout(None)
                return
            self._enqueue_stdout(raw_line)

    def _enqueue_stdout(self, item: bytes | None) -> None:
        try:
            self._stdout_messages.put_nowait(item)
            return
        except queue.Full:
            self._stdout_overflow.set()
        try:
            self._stdout_messages.get_nowait()
        except queue.Empty:
            pass
        try:
            self._stdout_messages.put_nowait(item)
        except queue.Full:
            pass

    def _drain_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        while True:
            try:
                chunk = proc.stderr.readline(MAX_STDERR_LINE_BYTES + 1)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            text = safe_log_text(chunk.decode("utf-8", errors="replace"), limit=MAX_STDERR_LINE_BYTES)
            if self._stderr_lines.full():
                try:
                    self._stderr_lines.get_nowait()
                except queue.Empty:
                    pass
            try:
                self._stderr_lines.put_nowait(text)
            except queue.Full:
                pass

    def stderr_tail(self) -> list[str]:
        with self._stderr_lines.mutex:
            return list(self._stderr_lines.queue)

    def discovery_metadata(self) -> dict[str, Any]:
        return {
            "protocol_requested": self.requested_protocol_version,
            "protocol_negotiated": self.negotiated_protocol_version,
            "capabilities": self.server_capabilities or {},
            "server_info": self.server_info or {},
        }


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _build_http_opener(
    *,
    ca_bundle: str | None,
    proxy_url: str | None,
    client_cert: str | None,
    client_key: str | None,
) -> urllib.request.OpenerDirector:
    if client_key is not None and client_cert is None:
        raise DiscoveryError("--client-key requires --client-cert")
    try:
        context = ssl.create_default_context(cafile=_regular_file(ca_bundle, "CA bundle"))
        if client_cert is not None:
            certfile = _regular_file(client_cert, "client certificate")
            assert certfile is not None
            context.load_cert_chain(
                certfile=certfile,
                keyfile=_regular_file(client_key, "client key") if client_key else None,
            )
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise DiscoveryError(f"Invalid TLS configuration: {safe_log_text(exc)}") from exc
    handlers: list[Any] = [
        _NoRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    ]
    # Do not silently inherit HTTP(S)_PROXY from the scanner environment. Proxy
    # routing is an explicit trust decision and can otherwise change the peer
    # that receives endpoint paths and authorization headers.
    proxies: dict[str, str] = {}
    if proxy_url is not None:
        proxy = _validate_proxy_url(proxy_url)
        proxies = {"http": proxy, "https": proxy}
    handlers.append(urllib.request.ProxyHandler(proxies))
    return urllib.request.build_opener(*handlers)


class StreamableHttpMcpClient:
    def __init__(
        self,
        url: str,
        *,
        timeout: float = 10.0,
        max_response_bytes: int = MAX_HTTP_RESPONSE_BYTES,
        allow_private_network: bool = False,
        allow_insecure_http: bool = False,
        allow_loopback: bool = True,
        retries: int = 2,
        protocol_version: str = MCP_PROTOCOL_VERSION,
        credential_provider: CredentialProvider | None = None,
        ca_bundle: str | None = None,
        proxy_url: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
    ) -> None:
        self.allow_private_network = bool(allow_private_network)
        self.allow_insecure_http = bool(allow_insecure_http)
        self.allow_loopback = bool(allow_loopback)
        try:
            self.url = validate_mcp_url(
                url,
                allow_private_network=self.allow_private_network,
                allow_insecure_http=self.allow_insecure_http,
                allow_loopback=self.allow_loopback,
            )
        except InputValidationError as exc:
            raise DiscoveryError(str(exc)) from exc
        self.timeout = _validate_timeout(timeout)
        self.max_response_bytes = _validate_positive_int(
            "max_response_bytes", max_response_bytes, MAX_RESPONSE_BYTES_LIMIT
        )
        self.retries = _validate_nonnegative_int("retries", retries, MAX_HTTP_RETRIES)
        self.requested_protocol_version = _validate_protocol_version(protocol_version)
        self.negotiated_protocol_version: str | None = None
        self.server_capabilities: dict[str, Any] | None = None
        self.server_info: dict[str, Any] | None = None
        self.credential_provider = credential_provider
        self._request_id = 0
        self._session_id: str | None = None
        self._session_recoveries = 0
        self._request_lock = threading.Lock()
        self._tools_changed_pending: bool = False
        self._opener = _build_http_opener(
            ca_bundle=ca_bundle,
            proxy_url=proxy_url,
            client_cert=client_cert,
            client_key=client_key,
        )

    def __enter__(self) -> "StreamableHttpMcpClient":
        try:
            self.initialize()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def initialize(self) -> None:
        result, headers = self._request(
            "initialize",
            {
                "protocolVersion": self.requested_protocol_version,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-tool-card-linter",
                    "version": __version__,
                },
            },
            capture_headers=True,
            retryable=False,
        )
        (
            self.negotiated_protocol_version,
            self.server_capabilities,
            self.server_info,
        ) = _validate_initialize_result(result)
        session_id = _header_value(headers, "mcp-session-id")
        if session_id:
            self._session_id = _validate_session_id(session_id)
        self._notify("notifications/initialized", {})

    def list_tools(
        self,
        *,
        max_tools: int = 1000,
        max_pages: int = 100,
    ) -> list[Any]:
        _validate_positive_int("max_tools", max_tools, MAX_LINT_TOOLS)
        _validate_positive_int("max_pages", max_pages, MAX_PAGES_LIMIT)
        _require_tools_capability(self.server_capabilities)
        try:
            return self._list_tools_snapshot(max_tools=max_tools, max_pages=max_pages)
        except SessionExpiredError:
            if self._session_recoveries >= MAX_SESSION_RECOVERIES:
                raise DiscoveryError(
                    f"MCP session exceeded the {MAX_SESSION_RECOVERIES} recovery limit"
                )
            self._session_recoveries += 1
            self._session_id = None
            self.initialize()
            _require_tools_capability(self.server_capabilities)
            return self._list_tools_snapshot(max_tools=max_tools, max_pages=max_pages)

    def _list_tools_snapshot(
        self,
        *,
        max_tools: int,
        max_pages: int,
    ) -> list[Any]:
        tools: list[Any] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _page in range(max_pages):
            params = {"cursor": cursor} if cursor else {}
            result = self._request("tools/list", params, retryable=True)
            page_tools, next_cursor = _validate_tools_page(result)
            for tool in page_tools:
                if len(tools) >= max_tools:
                    return tools
                tools.append(tool)
            if next_cursor is None:
                return tools
            if next_cursor in seen_cursors:
                raise JsonRpcError("tools/list pagination cursor repeated")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise DiscoveryError(f"tools/list exceeded the {max_pages} page limit")

    def wait_for_tools_list_changed(self, timeout: float) -> bool:
        _require_list_changed_capability(self.server_capabilities)
        wait_timeout = _validate_optional_timeout("list changed timeout", timeout)
        if wait_timeout == 0:
            return False
        with self._request_lock:
            if self._take_tools_changed_notification():
                return True
            deadline = time.monotonic() + wait_timeout
            last_event_id: str | None = None
            retry_seconds: float | None = None
            for _attempt in range(MAX_SSE_RECONNECTS + 1):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                if retry_seconds is not None:
                    if remaining <= retry_seconds:
                        return False
                    time.sleep(retry_seconds)
                    remaining = deadline - time.monotonic()
                request = self._sse_get_request(last_event_id=last_event_id)
                try:
                    with self._open(request, timeout=remaining) as response:
                        headers = dict(response.headers.items())
                        _require_content_type(headers, "text/event-stream")
                        result = _consume_sse_stream(
                            response,
                            max_bytes=self.max_response_bytes,
                            request_id=None,
                            on_notification=self._handle_server_message,
                        )
                except urllib.error.HTTPError as exc:
                    exc.close()
                    if exc.code == 405:
                        raise UnsupportedFeatureError(
                            "unsupported_feature: server does not offer an HTTP GET SSE listener"
                        ) from exc
                    raise DiscoveryError(
                        f"HTTP SSE listener failed with status {exc.code}"
                    ) from exc
                except urllib.error.URLError as exc:
                    if isinstance(exc.reason, TimeoutError):
                        if self._take_tools_changed_notification():
                            return True
                        return False
                    raise DiscoveryError(
                        f"HTTP SSE listener failed: {safe_log_text(exc.reason)}"
                    ) from exc
                except TimeoutError:
                    if self._take_tools_changed_notification():
                        return True
                    return False
                if self._take_tools_changed_notification():
                    return True
                last_event_id = result.last_event_id
                retry_seconds = result.retry_seconds
            raise DiscoveryError(
                f"SSE listener exceeded the {MAX_SSE_RECONNECTS} reconnect limit"
            )

    def close(self) -> None:
        with self._request_lock:
            self._close_unlocked()

    def _close_unlocked(self) -> None:
        session_id = self._session_id
        self._session_id = None
        if not session_id:
            return
        request = urllib.request.Request(
            self.url,
            method="DELETE",
            headers=self._headers(session_id=session_id),
        )
        try:
            with self._open(request, timeout=min(self.timeout, 2.0)) as response:
                _read_limited(response, min(self.max_response_bytes, 64 * 1024))
        except Exception:
            pass

    def _request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        capture_headers: bool = False,
        retryable: bool = False,
    ) -> Any:
        with self._request_lock:
            self._request_id += 1
            request_id = self._request_id
            payload: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
            }
            if params is not None:
                payload["params"] = params
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            request = urllib.request.Request(
                self.url,
                data=body,
                method="POST",
                headers=self._headers(),
            )
            message, headers = self._open_jsonrpc(
                request,
                request_id,
                retryable=retryable,
            )
            if capture_headers:
                return message["result"], headers
            return message["result"]

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers=self._headers(),
        )
        try:
            with self._open(request, timeout=self.timeout) as response:
                if response.status not in {200, 202, 204}:
                    raise DiscoveryError(
                        f"HTTP notification returned unexpected status {response.status}"
                    )
                _read_limited(response, min(self.max_response_bytes, 64 * 1024))
        except urllib.error.HTTPError as exc:
            exc.close()
            raise DiscoveryError(f"HTTP notification failed: {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise DiscoveryError(
                f"HTTP notification failed: {safe_log_text(exc.reason)}"
            ) from exc

    def _open_jsonrpc(
        self,
        request: urllib.request.Request,
        request_id: int,
        *,
        retryable: bool,
    ) -> tuple[dict[str, Any], dict[str, str]]:
        deadline = time.monotonic() + self.timeout
        attempts = self.retries + 1 if retryable else 1
        last_error: BaseException | None = None
        for attempt in range(attempts):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                with self._open(request, timeout=remaining) as response:
                    headers = dict(response.headers.items())
                    content_type = _content_type(headers)
                    if content_type == "text/event-stream":
                        sse_result = _consume_sse_stream(
                            response,
                            max_bytes=self.max_response_bytes,
                            request_id=request_id,
                            on_notification=self._handle_server_message,
                        )
                    else:
                        raw = _read_limited(response, self.max_response_bytes)
                        message = _parse_http_response(
                            raw,
                            headers,
                            request_id=request_id,
                        )
                        return message, headers
                if sse_result.message is not None:
                    return sse_result.message, headers
                resume_session_id = _header_value(headers, "mcp-session-id") or None
                if resume_session_id is not None:
                    resume_session_id = _validate_session_id(resume_session_id)
                message = self._resume_sse_response(
                    request_id=request_id,
                    last_event_id=sse_result.last_event_id,
                    retry_seconds=sse_result.retry_seconds,
                    deadline=deadline,
                    session_id=resume_session_id,
                )
                return message, headers
            except urllib.error.HTTPError as exc:
                last_error = exc
                retry_after = _retry_after_seconds(exc.headers.get("Retry-After"))
                error_body = _read_http_error(exc)
                if exc.code == 404 and self._session_id is not None:
                    raise SessionExpiredError(
                        "Streamable HTTP session expired; reinitialization is required"
                    ) from exc
                if (
                    exc.code in _TRANSIENT_HTTP_CODES
                    and attempt + 1 < attempts
                    and self._retry_delay(attempt, deadline, retry_after=retry_after)
                ):
                    continue
                if 300 <= exc.code < 400:
                    raise DiscoveryError(
                        f"HTTP redirect {exc.code} was refused; redirects are disabled to reduce SSRF risk"
                    ) from exc
                raise DiscoveryError(
                    f"HTTP MCP server returned {exc.code}: {error_body}"
                ) from exc
            except urllib.error.URLError as exc:
                last_error = exc
                if attempt + 1 < attempts and self._retry_delay(attempt, deadline):
                    continue
                raise DiscoveryError(
                    f"HTTP MCP request failed: {safe_log_text(exc.reason)}"
                ) from exc
            except TimeoutError as exc:
                last_error = exc
                if attempt + 1 < attempts and self._retry_delay(attempt, deadline):
                    continue
                raise DiscoveryError("HTTP MCP request timed out") from exc
        raise DiscoveryError(
            f"HTTP MCP request timed out after {self.timeout:g} seconds: {safe_log_text(last_error)}"
        )

    def _resume_sse_response(
        self,
        *,
        request_id: int,
        last_event_id: str | None,
        retry_seconds: float | None,
        deadline: float,
        session_id: str | None,
    ) -> dict[str, Any]:
        if not last_event_id:
            raise JsonRpcError(
                f"SSE stream ended before JSON-RPC response id={request_id} and supplied no event id"
            )
        cursor = last_event_id
        delay = retry_seconds
        for _attempt in range(MAX_SSE_RECONNECTS):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if delay is not None:
                if remaining <= delay:
                    break
                time.sleep(delay)
                remaining = deadline - time.monotonic()
            request = self._sse_get_request(
                last_event_id=cursor,
                session_id=session_id,
            )
            try:
                with self._open(request, timeout=remaining) as response:
                    headers = dict(response.headers.items())
                    _require_content_type(headers, "text/event-stream")
                    result = _consume_sse_stream(
                        response,
                        max_bytes=self.max_response_bytes,
                        request_id=request_id,
                        on_notification=self._handle_server_message,
                    )
            except urllib.error.HTTPError as exc:
                exc.close()
                raise DiscoveryError(
                    f"SSE resumption failed with HTTP status {exc.code}"
                ) from exc
            except urllib.error.URLError as exc:
                raise DiscoveryError(
                    f"SSE resumption failed: {safe_log_text(exc.reason)}"
                ) from exc
            if result.message is not None:
                return result.message
            if result.last_event_id is None:
                break
            cursor = result.last_event_id
            delay = result.retry_seconds
        raise DiscoveryError(
            f"SSE stream exceeded the {MAX_SSE_RECONNECTS} reconnect limit before response id={request_id}"
        )

    def _sse_get_request(
        self,
        *,
        last_event_id: str | None,
        session_id: str | None = None,
    ) -> urllib.request.Request:
        headers = self._headers(session_id=session_id)
        headers["Accept"] = "text/event-stream"
        headers.pop("Content-Type", None)
        if last_event_id is not None:
            headers["Last-Event-ID"] = last_event_id
        return urllib.request.Request(self.url, method="GET", headers=headers)

    def _handle_server_message(self, message: dict[str, Any]) -> None:
        if _is_tools_list_changed_notification(message):
            self._tools_changed_pending = True
        server_response = _server_request_response(message)
        if server_response is not None:
            self._post_jsonrpc_message(server_response)

    def _post_jsonrpc_message(self, payload: dict[str, Any]) -> None:
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            method="POST",
            headers=self._headers(),
        )
        try:
            with self._open(request, timeout=self.timeout) as response:
                if response.status not in {200, 202, 204}:
                    raise DiscoveryError(
                        f"HTTP JSON-RPC response returned unexpected status {response.status}"
                    )
                _read_limited(response, min(self.max_response_bytes, 64 * 1024))
        except urllib.error.HTTPError as exc:
            exc.close()
            raise DiscoveryError(
                f"HTTP JSON-RPC response failed: {exc.code}"
            ) from exc
        except urllib.error.URLError as exc:
            raise DiscoveryError(
                f"HTTP JSON-RPC response failed: {safe_log_text(exc.reason)}"
            ) from exc

    def _take_tools_changed_notification(self) -> bool:
        if not self._tools_changed_pending:
            return False
        self._tools_changed_pending = False
        return True

    def _open(self, request: urllib.request.Request, *, timeout: float) -> Any:
        try:
            validate_mcp_url(
                self.url,
                allow_private_network=self.allow_private_network,
                allow_insecure_http=self.allow_insecure_http,
                allow_loopback=self.allow_loopback,
            )
        except InputValidationError as exc:
            raise DiscoveryError(str(exc)) from exc
        return self._opener.open(request, timeout=max(0.001, timeout))

    def _retry_delay(
        self,
        attempt: int,
        deadline: float,
        *,
        retry_after: float | None = None,
    ) -> bool:
        delay = retry_after if retry_after is not None else min(0.1 * (2**attempt), 1.0)
        remaining = deadline - time.monotonic()
        if remaining <= delay:
            return False
        time.sleep(delay)
        return True

    def _headers(self, *, session_id: str | None = None) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": (
                self.negotiated_protocol_version or self.requested_protocol_version
            ),
            "User-Agent": f"mcp-tool-card-linter/{__version__}",
        }
        if self.credential_provider is not None:
            headers.update(
                _validate_credential_headers(
                    self.credential_provider.authorization_headers(self.url, ())
                )
            )
        effective_session = session_id if session_id is not None else self._session_id
        if effective_session:
            headers["Mcp-Session-Id"] = effective_session
        return headers

    def discovery_metadata(self) -> dict[str, Any]:
        return {
            "protocol_requested": self.requested_protocol_version,
            "protocol_negotiated": self.negotiated_protocol_version,
            "capabilities": self.server_capabilities or {},
            "server_info": self.server_info or {},
            "authenticated": self.credential_provider is not None,
            "session_recoveries": self._session_recoveries,
        }


def extract_tools(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise DiscoveryError("Tool file must be a JSON object or array")
    if "tools" in payload:
        tools = payload["tools"]
        if not isinstance(tools, list):
            raise DiscoveryError("tools must be an array")
        return tools
    result = payload.get("result")
    if isinstance(result, dict) and "tools" in result:
        tools = result["tools"]
        if not isinstance(tools, list):
            raise DiscoveryError("result.tools must be an array")
        return tools
    raise DiscoveryError("No tools array found; expected tools or result.tools")


def _discover_config_server(
    name: str,
    cfg: Any,
    timeout: float,
    max_tools: int,
    max_pages: int,
    max_response_bytes: int,
    allow_private_network: bool,
    allow_insecure_http: bool,
    allow_command_execution: bool,
    inherit_env: bool,
    compat_stdio_noise: bool,
    protocol_version: str,
    credential_provider: CredentialProvider | None,
    ca_bundle: str | None,
    proxy_url: str | None,
    client_cert: str | None,
    client_key: str | None,
    refresh_on_list_changed: float,
) -> SourceResult:
    if not isinstance(cfg, dict):
        raise DiscoveryError(f"Config for server '{safe_log_text(name)}' must be an object")
    if "disabled" in cfg and not isinstance(cfg["disabled"], bool):
        raise DiscoveryError(f"Config server '{safe_log_text(name)}' disabled must be boolean")
    if cfg.get("disabled") is True:
        return SourceResult(
            server_name=name,
            source_type="config",
            metadata={"disabled": True},
        )

    has_tools = "tools" in cfg
    url_keys = [key for key in ("url", "serverUrl", "server_url") if key in cfg]
    has_command = "command" in cfg
    source_count = int(has_tools) + int(bool(url_keys)) + int(has_command)
    if source_count != 1:
        raise DiscoveryError(
            f"Config server '{safe_log_text(name)}' must define exactly one of tools, URL, or command"
        )

    if has_tools:
        if not isinstance(cfg["tools"], list):
            raise DiscoveryError(f"Config server '{safe_log_text(name)}' tools must be an array")
        return _source_from_raw_tools(
            server_name=name,
            source_type="config-tools",
            raw_tools=cfg["tools"][:max_tools],
            metadata={"truncated": len(cfg["tools"]) > max_tools},
            discovered_tools=len(cfg["tools"]),
        )

    if url_keys:
        if len(url_keys) > 1:
            raise DiscoveryError(
                f"Config server '{safe_log_text(name)}' defines multiple URL aliases"
            )
        url = cfg[url_keys[0]]
        if not isinstance(url, str):
            raise DiscoveryError(f"Config server '{safe_log_text(name)}' URL must be a string")
        return discover_from_server_url(
            url,
            server_name=name,
            timeout=timeout,
            max_tools=max_tools,
            max_pages=max_pages,
            max_response_bytes=max_response_bytes,
            allow_private_network=allow_private_network,
            allow_insecure_http=allow_insecure_http,
            allow_loopback=allow_private_network,
            protocol_version=protocol_version,
            credential_provider=credential_provider,
            ca_bundle=ca_bundle,
            proxy_url=proxy_url,
            client_cert=client_cert,
            client_key=client_key,
            refresh_on_list_changed=refresh_on_list_changed,
        )

    if not allow_command_execution:
        raise DiscoveryError(
            "Config contains a local command; review it and pass --allow-config-execution to run it"
        )
    command_value = cfg["command"]
    if not isinstance(command_value, str) or not command_value.strip():
        raise DiscoveryError(f"Config server '{safe_log_text(name)}' command must be a non-empty string")
    args = cfg.get("args", [])
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        raise DiscoveryError(f"Config server '{safe_log_text(name)}' args must be a string array")
    env = cfg.get("env", {})
    if not isinstance(env, dict):
        raise DiscoveryError(f"Config server '{safe_log_text(name)}' env must be an object")
    if not all(isinstance(key, str) and isinstance(value, str) for key, value in env.items()):
        raise DiscoveryError(f"Config server '{safe_log_text(name)}' env values must be strings")
    cwd = cfg.get("cwd")
    if cwd is not None and not isinstance(cwd, str):
        raise DiscoveryError(f"Config server '{safe_log_text(name)}' cwd must be a string")
    requested_inheritance = cfg.get("inheritEnv", False)
    if not isinstance(requested_inheritance, bool):
        raise DiscoveryError(f"Config server '{safe_log_text(name)}' inheritEnv must be boolean")
    if requested_inheritance and not inherit_env:
        raise DiscoveryError(
            "Config requests parent environment inheritance; pass --inherit-env only after reviewing secret exposure"
        )

    command = [command_value, *args]
    with StdioMcpClient(
        command,
        timeout=timeout,
        cwd=cwd,
        env=env,
        inherit_env=inherit_env,
        compat_stdio_noise=compat_stdio_noise,
        protocol_version=protocol_version,
    ) as client:
        raw_tools = client.list_tools(max_tools=max_tools, max_pages=max_pages)
        list_changed = False
        if refresh_on_list_changed > 0:
            list_changed = client.wait_for_tools_list_changed(refresh_on_list_changed)
            if list_changed:
                raw_tools = client.list_tools(max_tools=max_tools, max_pages=max_pages)
        protocol_metadata = client.discovery_metadata()
    return _source_from_raw_tools(
        server_name=name,
        source_type="stdio",
        raw_tools=raw_tools,
        metadata={
            "command": redact_command(command),
            "cwd": cwd,
            "compat_stdio_noise": compat_stdio_noise,
            "list_changed_received": list_changed,
            "refresh_count": int(list_changed),
            **protocol_metadata,
        },
    )


def _extract_servers(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DiscoveryError("MCP config must be a JSON object")
    has_mcp_servers = "mcpServers" in payload
    has_servers = "servers" in payload
    if has_mcp_servers and has_servers:
        raise DiscoveryError("MCP config must not define both mcpServers and servers")
    servers = payload.get("mcpServers") if has_mcp_servers else payload.get("servers")
    if not isinstance(servers, dict):
        raise DiscoveryError("MCP config must contain mcpServers or servers object")
    if len(servers) > MAX_CONFIG_SERVERS:
        raise DiscoveryError(
            f"MCP config contains {len(servers)} servers, above the {MAX_CONFIG_SERVERS} limit"
        )
    for name in servers:
        _validate_server_name(name)
    return dict(servers)


def _load_json_file(path: str | Path) -> Any:
    try:
        return load_json_file(path)
    except InputValidationError as exc:
        raise DiscoveryError(str(exc)) from exc


def _source_from_raw_tools(
    *,
    server_name: str,
    source_type: str,
    raw_tools: list[Any],
    metadata: dict[str, Any],
    discovered_tools: int | None = None,
) -> SourceResult:
    return SourceResult(
        server_name=server_name,
        source_type=source_type,
        tools=[
            ToolCard.from_raw(tool, server_name=server_name, index=index)
            for index, tool in enumerate(raw_tools)
        ],
        metadata=metadata,
        discovered_tools=discovered_tools,
    )


@dataclass(frozen=True, slots=True)
class _SseReadResult:
    message: dict[str, Any] | None
    last_event_id: str | None
    retry_seconds: float | None


def _consume_sse_stream(
    response: Any,
    *,
    max_bytes: int,
    request_id: int | None,
    on_notification: Any = None,
) -> _SseReadResult:
    total_bytes = 0
    event_count = 0
    data_lines: list[str] = []
    event_id: str | None = None
    last_event_id: str | None = None
    retry_seconds: float | None = None

    def dispatch() -> dict[str, Any] | None:
        nonlocal event_count, data_lines, event_id, last_event_id
        if event_id is not None:
            last_event_id = event_id
        if not data_lines:
            event_id = None
            return None
        text = "\n".join(data_lines)
        data_lines = []
        event_id = None
        # The transport specification recommends an empty data event to flush
        # HTTP headers before a long-running response. It carries no JSON-RPC
        # message and must not consume the event budget.
        if text == "":
            return None
        event_count += 1
        if event_count > MAX_SSE_EVENTS:
            raise JsonRpcError(f"SSE stream contains more than {MAX_SSE_EVENTS} events")
        try:
            message = strict_json_loads(text)
        except InputValidationError as exc:
            raise JsonRpcError(
                f"SSE data is not valid JSON-RPC JSON: {safe_log_text(exc)}"
            ) from exc
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise JsonRpcError("SSE data must contain a JSON-RPC 2.0 object")
        if "method" in message and on_notification is not None:
            on_notification(message)
            return None
        if request_id is not None and message.get("id") == request_id:
            _jsonrpc_result(message, request_id)
            return message
        return None

    while True:
        raw_line = response.readline(MAX_SSE_LINE_BYTES + 1)
        if not isinstance(raw_line, bytes):
            raise DiscoveryError("SSE response reader returned non-bytes data")
        if len(raw_line) > MAX_SSE_LINE_BYTES:
            raise DiscoveryError(f"SSE line exceeds {MAX_SSE_LINE_BYTES} bytes")
        if not raw_line:
            matched = dispatch()
            return _SseReadResult(matched, last_event_id, retry_seconds)
        total_bytes += len(raw_line)
        if total_bytes > max_bytes:
            raise DiscoveryError(f"SSE stream exceeds the {max_bytes} byte limit")
        try:
            line = raw_line.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError as exc:
            raise JsonRpcError("SSE stream is not valid UTF-8") from exc
        if line == "":
            matched = dispatch()
            if matched is not None:
                return _SseReadResult(matched, last_event_id, retry_seconds)
            continue
        if line.startswith(":"):
            continue
        field, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "data":
            data_lines.append(value)
        elif field == "id":
            if "\x00" in value or len(value) > 4096:
                raise JsonRpcError("SSE event id is invalid")
            event_id = value
        elif field == "retry" and re.fullmatch(r"[0-9]{1,9}", value):
            retry_seconds = min(float(value) / 1000.0, MAX_RETRY_AFTER_SECONDS)


def _parse_http_response(
    raw: bytes,
    headers: dict[str, str],
    *,
    request_id: int | None = None,
) -> dict[str, Any]:
    content_type = _header_value(headers, "content-type").split(";", 1)[0].strip().lower()
    if content_type not in {"application/json", "text/event-stream"}:
        raise JsonRpcError(
            f"Unsupported HTTP Content-Type: {safe_log_text(content_type or '<missing>')}"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JsonRpcError("HTTP MCP response is not valid UTF-8") from exc

    if content_type == "text/event-stream":
        for event_index, block in enumerate(re.split(r"\r?\n\r?\n", text)):
            if event_index >= 10_000:
                raise JsonRpcError("SSE response contains too many events")
            data_lines = []
            for line in block.splitlines():
                if line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
            if not data_lines:
                continue
            try:
                message = strict_json_loads("\n".join(data_lines))
            except InputValidationError:
                continue
            if not isinstance(message, dict):
                continue
            if request_id is None or message.get("id") == request_id:
                if request_id is not None:
                    _jsonrpc_result(message, request_id)
                return message
        raise JsonRpcError("No matching JSON-RPC data event found in SSE response")

    try:
        message = strict_json_loads(text)
    except InputValidationError as exc:
        raise JsonRpcError(f"HTTP response is not valid JSON: {safe_log_text(exc)}") from exc
    if not isinstance(message, dict):
        raise JsonRpcError("HTTP JSON-RPC response must be an object")
    if request_id is not None:
        _jsonrpc_result(message, request_id)
    return message


def _content_type(headers: dict[str, str]) -> str:
    return _header_value(headers, "content-type").split(";", 1)[0].strip().lower()


def _require_content_type(headers: dict[str, str], expected: str) -> None:
    actual = _content_type(headers)
    if actual != expected:
        raise JsonRpcError(
            "Unsupported HTTP Content-Type: "
            f"expected {expected}, received {safe_log_text(actual or '<missing>')}"
        )


def _decode_stdio_message(
    raw_line: bytes,
    *,
    compat_stdio_noise: bool,
) -> dict[str, Any] | None:
    if len(raw_line) > MAX_STDIO_MESSAGE_BYTES:
        raise JsonRpcError(
            f"stdio JSON-RPC message exceeds the {MAX_STDIO_MESSAGE_BYTES} byte limit"
        )
    if not raw_line.endswith(b"\n"):
        raise JsonRpcError("stdio JSON-RPC message is not newline-terminated")
    try:
        text = raw_line.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise JsonRpcError("stdio stdout is not valid UTF-8") from exc
    if not text:
        if compat_stdio_noise:
            return None
        raise JsonRpcError("Non-JSON data received on strict stdio stdout")
    try:
        message = strict_json_loads(text)
    except InputValidationError as exc:
        # A line that appears intended as JSON is always an error. Compatibility
        # mode is deliberately limited to bounded legacy log lines.
        if text.startswith(("{", "[")):
            raise JsonRpcError(
                f"stdio stdout contained malformed JSON: {safe_log_text(exc)}"
            ) from exc
        if not compat_stdio_noise:
            raise JsonRpcError("stdio stdout contained non-JSON data") from exc
        return None
    if not isinstance(message, dict):
        if compat_stdio_noise:
            return None
        raise JsonRpcError("stdio JSON-RPC message must be an object")
    return message


def _is_tools_list_changed_notification(message: dict[str, Any]) -> bool:
    return (
        message.get("jsonrpc") == "2.0"
        and message.get("method") == "notifications/tools/list_changed"
        and "id" not in message
    )


def _server_request_response(message: dict[str, Any]) -> dict[str, Any] | None:
    if "method" not in message or "id" not in message:
        return None
    request_id = message.get("id")
    if (
        message.get("jsonrpc") != "2.0"
        or isinstance(request_id, bool)
        or not isinstance(request_id, (int, float, str))
        or isinstance(request_id, float) and not math.isfinite(request_id)
        or not isinstance(message.get("method"), str)
    ):
        raise JsonRpcError("Server sent a malformed JSON-RPC request")
    if message["method"] == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": "Method not found"},
    }


def _jsonrpc_result(message: dict[str, Any], request_id: int) -> Any:
    if message.get("jsonrpc") != "2.0":
        raise JsonRpcError(f"JSON-RPC response {request_id} has invalid jsonrpc version")
    if message.get("id") != request_id:
        raise JsonRpcError(f"JSON-RPC response id mismatch for {request_id}")
    if "error" in message and "result" in message:
        raise JsonRpcError(
            f"JSON-RPC response {request_id} contains both result and error"
        )
    if "error" in message:
        error = message["error"]
        if not isinstance(error, dict):
            raise JsonRpcError(f"JSON-RPC error for {request_id} is malformed")
        code = error.get("code")
        error_message = error.get("message")
        if (
            isinstance(code, bool)
            or not isinstance(code, int)
            or not isinstance(error_message, str)
        ):
            raise JsonRpcError(f"JSON-RPC error for {request_id} is malformed")
        detail = safe_log_text(error_message)
        raise JsonRpcError(f"JSON-RPC error for {request_id}: code={code}, message={detail}")
    if "result" not in message:
        raise JsonRpcError(f"JSON-RPC response {request_id} has no result")
    return message["result"]


def _validate_initialize_result(
    result: Any,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    if not isinstance(result, dict):
        raise JsonRpcError("initialize returned a non-object result")
    protocol_version = result.get("protocolVersion")
    if protocol_version not in SUPPORTED_MCP_PROTOCOL_VERSIONS:
        raise JsonRpcError(
            f"Server selected unsupported MCP protocol version: {safe_log_text(protocol_version)}"
        )
    capabilities = result.get("capabilities")
    if not isinstance(capabilities, dict):
        raise JsonRpcError("initialize result.capabilities must be an object")
    server_info = result.get("serverInfo")
    if not isinstance(server_info, dict):
        raise JsonRpcError("initialize result.serverInfo must be an object")
    if not isinstance(server_info.get("name"), str) or not server_info["name"]:
        raise JsonRpcError("initialize result.serverInfo.name must be a non-empty string")
    if not isinstance(server_info.get("version"), str) or not server_info["version"]:
        raise JsonRpcError("initialize result.serverInfo.version must be a non-empty string")
    return protocol_version, capabilities, server_info


def _require_tools_capability(capabilities: dict[str, Any] | None) -> None:
    # None means the low-level client has not been initialized yet. This preserves
    # direct request mocking for embedders while enforcing the negotiated state.
    if capabilities is not None and not isinstance(capabilities.get("tools"), dict):
        raise UnsupportedFeatureError(
            "unsupported_feature: server did not declare the tools capability"
        )


def _require_list_changed_capability(capabilities: dict[str, Any] | None) -> None:
    tools = capabilities.get("tools") if capabilities is not None else None
    if not isinstance(tools, dict) or tools.get("listChanged") is not True:
        raise UnsupportedFeatureError(
            "unsupported_feature: server did not declare tools.listChanged=true"
        )


def _validate_tools_page(result: Any) -> tuple[list[Any], str | None]:
    if not isinstance(result, dict):
        raise JsonRpcError("tools/list returned a non-object result")
    page_tools = result.get("tools")
    if not isinstance(page_tools, list):
        raise JsonRpcError("tools/list result.tools must be an array")
    cursor_value = result.get("nextCursor")
    if cursor_value is None or cursor_value == "":
        return page_tools, None
    if not isinstance(cursor_value, str):
        raise JsonRpcError("tools/list nextCursor must be a string")
    if len(cursor_value) > 4096 or any(ord(char) < 32 for char in cursor_value):
        raise JsonRpcError("tools/list nextCursor is invalid")
    return page_tools, cursor_value


def _validate_session_id(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1024
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise JsonRpcError("Mcp-Session-Id header is invalid")
    return value


def _read_limited(response: Any, limit: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as exc:
            raise DiscoveryError("HTTP Content-Length is invalid") from exc
        if declared < 0 or declared > limit:
            raise DiscoveryError(f"HTTP response exceeds the {limit} byte limit")
    raw = response.read(limit + 1)
    if not isinstance(raw, bytes):
        raise DiscoveryError("HTTP response reader returned non-bytes data")
    if len(raw) > limit:
        raise DiscoveryError(f"HTTP response exceeds the {limit} byte limit")
    return raw


def _read_http_error(exc: urllib.error.HTTPError) -> str:
    try:
        raw = exc.read(MAX_HTTP_ERROR_BYTES + 1)
    except OSError:
        return "<unavailable>"
    finally:
        exc.close()
    suffix = "..." if len(raw) > MAX_HTTP_ERROR_BYTES else ""
    return safe_log_text(raw[:MAX_HTTP_ERROR_BYTES].decode("utf-8", errors="replace")) + suffix


def _retry_after_seconds(value: str | None) -> float | None:
    if value is None:
        return None
    value = value.strip()
    if re.fullmatch(r"[0-9]{1,9}", value):
        return min(float(value), MAX_RETRY_AFTER_SECONDS)
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        delay = max(0.0, (parsed - datetime.now(UTC)).total_seconds())
        return min(delay, MAX_RETRY_AFTER_SECONDS)
    except (TypeError, ValueError, OverflowError):
        return None


def _header_value(headers: dict[str, str], name: str) -> str:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return ""


def _validate_command(command: list[str]) -> list[str]:
    if not isinstance(command, list) or not command:
        raise DiscoveryError("stdio command must not be empty")
    if len(command) > MAX_COMMAND_ARGS:
        raise DiscoveryError(f"stdio command has more than {MAX_COMMAND_ARGS} arguments")
    validated: list[str] = []
    for argument in command:
        if not isinstance(argument, str):
            raise DiscoveryError("stdio command arguments must be strings")
        if not argument or len(argument) > MAX_COMMAND_ARG_CHARS or "\x00" in argument:
            raise DiscoveryError(
                f"stdio command arguments must contain 1..{MAX_COMMAND_ARG_CHARS} characters and no NUL bytes"
            )
        validated.append(argument)
    if sum(len(argument) for argument in validated) > MAX_COMMAND_CHARS:
        raise DiscoveryError(
            f"stdio command exceeds the {MAX_COMMAND_CHARS} total character limit"
        )
    return validated


def _validate_env(env: dict[str, str]) -> dict[str, str]:
    if len(env) > MAX_ENV_VARS:
        raise DiscoveryError(f"stdio environment has more than {MAX_ENV_VARS} entries")
    validated: dict[str, str] = {}
    total_characters = 0
    for key, value in env.items():
        if not isinstance(key, str) or not _ENV_NAME.fullmatch(key):
            raise DiscoveryError(f"Invalid environment variable name: {safe_log_text(key)}")
        if not isinstance(value, str):
            raise DiscoveryError(f"Environment variable {safe_log_text(key)} must be a string")
        if len(value) > MAX_ENV_VALUE_CHARS or "\x00" in value:
            raise DiscoveryError(
                f"Environment variable {safe_log_text(key)} is too long or contains a NUL byte"
            )
        total_characters += len(key) + len(value)
        if total_characters > MAX_ENV_TOTAL_CHARS:
            raise DiscoveryError(
                f"stdio environment exceeds the {MAX_ENV_TOTAL_CHARS} total character limit"
            )
        validated[key] = value
    return validated


def _validate_cwd(cwd: str | None) -> str | None:
    if cwd is None:
        return None
    if not isinstance(cwd, str) or not cwd or "\x00" in cwd:
        raise DiscoveryError("stdio cwd must be a non-empty string without NUL bytes")
    resolved = Path(cwd).expanduser().resolve()
    if not resolved.is_dir():
        raise DiscoveryError(f"stdio cwd is not a directory: {safe_log_text(resolved)}")
    return str(resolved)


def _validate_server_name(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        raise DiscoveryError("Server name must be a non-empty string")
    if len(name) > MAX_SERVER_NAME_CHARS or any(ord(char) < 32 for char in name):
        raise DiscoveryError(
            f"Server name must contain at most {MAX_SERVER_NAME_CHARS} characters and no controls"
        )
    return name


def _validate_protocol_version(value: Any) -> str:
    if not isinstance(value, str) or value not in SUPPORTED_MCP_PROTOCOL_VERSIONS:
        raise DiscoveryError(
            "protocol_version must be one of "
            + ", ".join(SUPPORTED_MCP_PROTOCOL_VERSIONS)
        )
    return value


def _validate_credential_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise DiscoveryError("Credential provider returned a non-mapping header set")
    allowed = {"authorization", "dpop"}
    result: dict[str, str] = {}
    for key, header_value in value.items():
        if not isinstance(key, str) or key.lower() not in allowed:
            raise DiscoveryError("Credential provider returned an unsupported header")
        if (
            not isinstance(header_value, str)
            or not header_value
            or len(header_value) > 128 * 1024
            or any(ord(char) < 32 or ord(char) == 127 for char in header_value)
        ):
            raise DiscoveryError("Credential provider returned an invalid header value")
        canonical = "Authorization" if key.lower() == "authorization" else "DPoP"
        result[canonical] = header_value
    return result


def _validate_proxy_url(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise DiscoveryError("Proxy URL must be a bounded string")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise DiscoveryError("Proxy URL contains control characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise DiscoveryError(f"Invalid proxy URL: {safe_log_text(exc)}") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DiscoveryError("Proxy URL must use http or https and include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise DiscoveryError("Credentials in proxy URLs are not allowed")
    if parsed.query or parsed.fragment:
        raise DiscoveryError("Proxy URL must not include a query or fragment")
    if port is not None and not 1 <= port <= 65535:
        raise DiscoveryError("Proxy URL port must be in 1..65535")
    return value


def _regular_file(value: str | None, label: str) -> str | None:
    if value is None:
        return None
    try:
        resolved = Path(value).expanduser().resolve()
        mode = resolved.stat().st_mode
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise DiscoveryError(f"Invalid {label}: {safe_log_text(exc)}") from exc
    if not stat.S_ISREG(mode):
        raise DiscoveryError(f"{label} is not a regular file: {safe_log_text(resolved)}")
    return str(resolved)


def _validate_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DiscoveryError("timeout must be a number")
    result = float(value)
    if not math.isfinite(result) or not 0.05 <= result <= MAX_TIMEOUT_SECONDS:
        raise DiscoveryError(f"timeout must be finite and in 0.05..{MAX_TIMEOUT_SECONDS:g}")
    return result


def _validate_optional_timeout(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DiscoveryError(f"{name} must be a number")
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= MAX_TIMEOUT_SECONDS:
        raise DiscoveryError(
            f"{name} must be finite and in 0..{MAX_TIMEOUT_SECONDS:g}"
        )
    return result


def _validate_positive_int(name: str, value: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise DiscoveryError(f"{name} must be an integer in 1..{maximum}")
    return value


def _validate_nonnegative_int(name: str, value: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise DiscoveryError(f"{name} must be an integer in 0..{maximum}")
    return value


def _signal_process_tree(proc: subprocess.Popen[bytes], sig: signal.Signals) -> None:
    if os.name == "posix":
        _signal_process_group(proc.pid, sig)
        return
    try:
        if sig == _KILL_SIGNAL:
            proc.kill()
        else:
            proc.terminate()
    except OSError:
        pass


def _signal_process_group(pid: int, sig: signal.Signals) -> None:
    try:
        os.killpg(pid, sig)
    except (OSError, ProcessLookupError):
        pass
