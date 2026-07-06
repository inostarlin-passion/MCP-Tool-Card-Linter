from __future__ import annotations

import json
import os
import queue
import select
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from . import __version__
from .models import SourceResult, ToolCard

MCP_PROTOCOL_VERSION = "2025-11-25"
MAX_INPUT_FILE_BYTES = 10 * 1024 * 1024
MAX_STDERR_LINES = 100


class DiscoveryError(RuntimeError):
    """Raised when a tool source cannot be discovered."""


class JsonRpcError(DiscoveryError):
    """Raised for JSON-RPC protocol errors."""


def load_tools_file(path: str | Path, *, server_name: str = "static") -> SourceResult:
    payload = _load_json_file(path)
    tools = extract_tools(payload)
    return SourceResult(
        server_name=server_name,
        source_type="tools-file",
        tools=[
            ToolCard.from_raw(tool, server_name=server_name, index=index)
            for index, tool in enumerate(tools)
        ],
        metadata={"path": str(Path(path).resolve())},
    )


def discover_from_stdio_command(
    command_text: str,
    *,
    server_name: str = "stdio",
    timeout: float = 10.0,
    max_tools: int = 1000,
) -> SourceResult:
    command = shlex.split(command_text)
    if not command:
        raise DiscoveryError("--stdio command is empty")
    with StdioMcpClient(command, timeout=timeout) as client:
        raw_tools = client.list_tools(max_tools=max_tools)
    return _source_from_raw_tools(
        server_name=server_name,
        source_type="stdio",
        raw_tools=raw_tools,
        metadata={"command": command},
    )


def discover_from_server_url(
    url: str,
    *,
    server_name: str = "http",
    timeout: float = 10.0,
    max_tools: int = 1000,
) -> SourceResult:
    with StreamableHttpMcpClient(url, timeout=timeout) as client:
        raw_tools = client.list_tools(max_tools=max_tools)
    return _source_from_raw_tools(
        server_name=server_name,
        source_type="streamable-http",
        raw_tools=raw_tools,
        metadata={"url": url},
    )


def discover_from_config(
    path: str | Path,
    *,
    server_filter: str | None = None,
    timeout: float = 10.0,
    max_tools: int = 1000,
    concurrency: int = 4,
) -> list[SourceResult]:
    payload = _load_json_file(path)
    servers = _extract_servers(payload)
    if server_filter:
        servers = {name: cfg for name, cfg in servers.items() if name == server_filter}
        if not servers:
            raise DiscoveryError(f"Server '{server_filter}' not found in config")
    if not servers:
        raise DiscoveryError("No MCP servers found in config")

    bounded_workers = max(1, min(concurrency, 32, len(servers)))
    results: list[SourceResult] = []
    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        futures = {
            executor.submit(
                _discover_config_server,
                name,
                cfg,
                timeout,
                max_tools,
            ): name
            for name, cfg in sorted(servers.items())
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:  # Keep other servers lintable.
                results.append(
                    SourceResult(
                        server_name=name,
                        source_type="config",
                        errors=[str(exc)],
                        metadata={"config_path": str(Path(path).resolve())},
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
    ) -> None:
        if not command:
            raise DiscoveryError("stdio command must not be empty")
        if timeout <= 0:
            raise DiscoveryError("timeout must be positive")
        self.command = command
        self.timeout = timeout
        self.cwd = cwd
        self.env = env
        self._proc: subprocess.Popen[str] | None = None
        self._request_id = 0
        self._write_lock = threading.Lock()
        self._stderr_lines: queue.Queue[str] = queue.Queue(maxsize=MAX_STDERR_LINES)
        self._stderr_thread: threading.Thread | None = None

    def __enter__(self) -> "StdioMcpClient":
        self.start()
        self.initialize()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def start(self) -> None:
        if self._proc is not None:
            return
        env = os.environ.copy()
        if self.env:
            env.update({str(key): str(value) for key, value in self.env.items()})
        try:
            self._proc = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,
            )
        except OSError as exc:
            raise DiscoveryError(f"Failed to start stdio MCP server: {exc}") from exc
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, name="mcp-stderr-drain", daemon=True
        )
        self._stderr_thread.start()

    def initialize(self) -> None:
        result = self.request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-tool-card-linter",
                    "version": __version__,
                },
            },
        )
        if not isinstance(result, dict):
            raise JsonRpcError("initialize returned a non-object result")
        self.notify("notifications/initialized", {})

    def list_tools(self, *, max_tools: int = 1000) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            params = {"cursor": cursor} if cursor else {}
            result = self.request("tools/list", params)
            if not isinstance(result, dict):
                raise JsonRpcError("tools/list returned a non-object result")
            page_tools = result.get("tools", [])
            if not isinstance(page_tools, list):
                raise JsonRpcError("tools/list result.tools must be an array")
            for tool in page_tools:
                if len(tools) >= max_tools:
                    return tools
                tools.append(tool)
            cursor_value = result.get("nextCursor")
            if not cursor_value:
                return tools
            if not isinstance(cursor_value, str):
                raise JsonRpcError("tools/list nextCursor must be a string")
            cursor = cursor_value

    def request(self, method: str, params: dict[str, Any] | None = None) -> Any:
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
        message: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params is not None:
            message["params"] = params
        self._write_message(message)

    def close(self) -> None:
        proc = self._proc
        if proc is None:
            return
        try:
            if proc.stdin and not proc.stdin.closed:
                proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1.0)
        finally:
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream and not stream.closed:
                        stream.close()
                except OSError:
                    pass
            self._proc = None

    def _write_message(self, message: dict[str, Any]) -> None:
        proc = self._ensure_running()
        if proc.stdin is None:
            raise DiscoveryError("stdio server stdin is unavailable")
        line = json.dumps(message, separators=(",", ":")) + "\n"
        with self._write_lock:
            try:
                proc.stdin.write(line)
                proc.stdin.flush()
            except OSError as exc:
                raise DiscoveryError(
                    f"Failed to write JSON-RPC message to stdio server: {exc}"
                ) from exc

    def _read_response(self, request_id: int) -> Any:
        proc = self._ensure_running()
        if proc.stdout is None:
            raise DiscoveryError("stdio server stdout is unavailable")
        deadline = time.monotonic() + self.timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DiscoveryError(
                    f"Timed out waiting for JSON-RPC response id={request_id}. "
                    f"stderr_tail={self.stderr_tail()}"
                )
            ready, _, _ = select.select([proc.stdout], [], [], remaining)
            if not ready:
                continue
            line = proc.stdout.readline()
            if line == "":
                raise DiscoveryError(
                    f"stdio server exited before response id={request_id}. "
                    f"returncode={proc.poll()} stderr_tail={self.stderr_tail()}"
                )
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise JsonRpcError(f"JSON-RPC error for {request_id}: {message['error']}")
            if "result" not in message:
                raise JsonRpcError(f"JSON-RPC response {request_id} has no result")
            return message["result"]

    def _ensure_running(self) -> subprocess.Popen[str]:
        proc = self._proc
        if proc is None:
            raise DiscoveryError("stdio MCP server is not running")
        if proc.poll() is not None:
            raise DiscoveryError(
                f"stdio server has exited with code {proc.returncode}. "
                f"stderr_tail={self.stderr_tail()}"
            )
        return proc

    def _drain_stderr(self) -> None:
        proc = self._proc
        if proc is None or proc.stderr is None:
            return
        for line in proc.stderr:
            text = line.rstrip("\n")
            if self._stderr_lines.full():
                try:
                    self._stderr_lines.get_nowait()
                except queue.Empty:
                    pass
            self._stderr_lines.put(text)

    def stderr_tail(self) -> list[str]:
        return list(self._stderr_lines.queue)


class StreamableHttpMcpClient:
    def __init__(self, url: str, *, timeout: float = 10.0) -> None:
        if not url.startswith(("http://", "https://")):
            raise DiscoveryError("MCP server URL must start with http:// or https://")
        if timeout <= 0:
            raise DiscoveryError("timeout must be positive")
        self.url = url
        self.timeout = timeout
        self._request_id = 0
        self._session_id: str | None = None

    def __enter__(self) -> "StreamableHttpMcpClient":
        self.initialize()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def initialize(self) -> None:
        result, headers = self._request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-tool-card-linter",
                    "version": __version__,
                },
            },
            capture_headers=True,
        )
        if not isinstance(result, dict):
            raise JsonRpcError("initialize returned a non-object result")
        session_id = headers.get("Mcp-Session-Id") or headers.get("MCP-Session-Id")
        if session_id:
            self._session_id = session_id
        self._notify("notifications/initialized", {})

    def list_tools(self, *, max_tools: int = 1000) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            params = {"cursor": cursor} if cursor else {}
            result = self._request("tools/list", params)
            if not isinstance(result, dict):
                raise JsonRpcError("tools/list returned a non-object result")
            page_tools = result.get("tools", [])
            if not isinstance(page_tools, list):
                raise JsonRpcError("tools/list result.tools must be an array")
            for tool in page_tools:
                if len(tools) >= max_tools:
                    return tools
                tools.append(tool)
            cursor_value = result.get("nextCursor")
            if not cursor_value:
                return tools
            if not isinstance(cursor_value, str):
                raise JsonRpcError("tools/list nextCursor must be a string")
            cursor = cursor_value

    def close(self) -> None:
        if not self._session_id:
            return
        request = urllib.request.Request(
            self.url,
            method="DELETE",
            headers=self._headers(),
        )
        try:
            urllib.request.urlopen(request, timeout=min(self.timeout, 2.0)).close()
        except Exception:
            pass

    def _request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        capture_headers: bool = False,
    ) -> Any:
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
        message, headers = self._open_jsonrpc(request, request_id)
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
            urllib.request.urlopen(request, timeout=self.timeout).close()
        except urllib.error.HTTPError as exc:
            if exc.code not in (200, 202, 204):
                raise DiscoveryError(f"HTTP notification failed: {exc.code}") from exc

    def _open_jsonrpc(
        self, request: urllib.request.Request, request_id: int
    ) -> tuple[dict[str, Any], dict[str, str]]:
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                headers = dict(response.headers.items())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise DiscoveryError(f"HTTP MCP server returned {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise DiscoveryError(f"HTTP MCP request failed: {exc}") from exc

        message = _parse_http_response(raw, headers)
        if message.get("id") != request_id:
            raise JsonRpcError(f"HTTP JSON-RPC response id mismatch for {request_id}")
        if "error" in message:
            raise JsonRpcError(f"JSON-RPC error for {request_id}: {message['error']}")
        if "result" not in message:
            raise JsonRpcError(f"JSON-RPC response {request_id} has no result")
        return message, headers

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            "User-Agent": f"mcp-tool-card-linter/{__version__}",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers


def extract_tools(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        raise DiscoveryError("Tool file must be a JSON object or array")
    if isinstance(payload.get("tools"), list):
        return payload["tools"]
    result = payload.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return result["tools"]
    raise DiscoveryError("No tools array found; expected tools or result.tools")


def _discover_config_server(
    name: str,
    cfg: Any,
    timeout: float,
    max_tools: int,
) -> SourceResult:
    if not isinstance(cfg, dict):
        raise DiscoveryError(f"Config for server '{name}' must be an object")
    if cfg.get("disabled") is True:
        return SourceResult(
            server_name=name,
            source_type="config",
            errors=["Server is marked disabled in config"],
        )
    if isinstance(cfg.get("tools"), list):
        return _source_from_raw_tools(
            server_name=name,
            source_type="config-tools",
            raw_tools=cfg["tools"],
            metadata={},
        )
    url = cfg.get("url") or cfg.get("serverUrl") or cfg.get("server_url")
    if isinstance(url, str):
        return discover_from_server_url(
            url, server_name=name, timeout=timeout, max_tools=max_tools
        )
    command_value = cfg.get("command")
    if isinstance(command_value, str) and command_value.strip():
        args = cfg.get("args", [])
        if args is None:
            args = []
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise DiscoveryError(f"Config server '{name}' args must be a string array")
        env = cfg.get("env")
        if env is not None and not isinstance(env, dict):
            raise DiscoveryError(f"Config server '{name}' env must be an object")
        cwd = cfg.get("cwd")
        if cwd is not None and not isinstance(cwd, str):
            raise DiscoveryError(f"Config server '{name}' cwd must be a string")
        with StdioMcpClient(
            [command_value, *args],
            timeout=timeout,
            cwd=cwd,
            env={str(k): str(v) for k, v in (env or {}).items()},
        ) as client:
            raw_tools = client.list_tools(max_tools=max_tools)
        return _source_from_raw_tools(
            server_name=name,
            source_type="stdio",
            raw_tools=raw_tools,
            metadata={"command": [command_value, *args], "cwd": cwd},
        )
    raise DiscoveryError(
        f"Config server '{name}' must provide command/args, url, or tools"
    )


def _extract_servers(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise DiscoveryError("MCP config must be a JSON object")
    servers = payload.get("mcpServers") or payload.get("servers")
    if not isinstance(servers, dict):
        raise DiscoveryError("MCP config must contain mcpServers or servers object")
    return {str(name): cfg for name, cfg in servers.items()}


def _load_json_file(path: str | Path) -> Any:
    resolved = Path(path).expanduser().resolve()
    if not resolved.exists():
        raise DiscoveryError(f"File not found: {resolved}")
    if not resolved.is_file():
        raise DiscoveryError(f"Path is not a file: {resolved}")
    size = resolved.stat().st_size
    if size > MAX_INPUT_FILE_BYTES:
        raise DiscoveryError(
            f"Input file is {size} bytes, above {MAX_INPUT_FILE_BYTES} byte limit"
        )
    try:
        return json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise DiscoveryError(f"Invalid JSON in {resolved}: {exc}") from exc
    except OSError as exc:
        raise DiscoveryError(f"Failed to read {resolved}: {exc}") from exc


def _source_from_raw_tools(
    *,
    server_name: str,
    source_type: str,
    raw_tools: list[Any],
    metadata: dict[str, Any],
) -> SourceResult:
    return SourceResult(
        server_name=server_name,
        source_type=source_type,
        tools=[
            ToolCard.from_raw(tool, server_name=server_name, index=index)
            for index, tool in enumerate(raw_tools)
        ],
        metadata=metadata,
    )


def _parse_http_response(raw: bytes, headers: dict[str, str]) -> dict[str, Any]:
    content_type = headers.get("Content-Type", headers.get("content-type", ""))
    text = raw.decode("utf-8", errors="replace").strip()
    if "text/event-stream" in content_type:
        for block in text.split("\n\n"):
            data_lines = [
                line[5:].strip()
                for line in block.splitlines()
                if line.startswith("data:")
            ]
            if not data_lines:
                continue
            try:
                message = json.loads("\n".join(data_lines))
            except json.JSONDecodeError:
                continue
            if isinstance(message, dict):
                return message
        raise JsonRpcError("No JSON-RPC data event found in SSE response")
    try:
        message = json.loads(text)
    except json.JSONDecodeError as exc:
        raise JsonRpcError(f"HTTP response is not valid JSON: {text[:200]}") from exc
    if not isinstance(message, dict):
        raise JsonRpcError("HTTP JSON-RPC response must be an object")
    return message
