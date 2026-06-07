import asyncio
import base64
import hashlib
import json
import os
import secrets
import stat
import time
import webbrowser
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, TypedDict, cast
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from dotenv import load_dotenv
from httpx_sse import aconnect_sse
from rich import print as rprint
from rich.console import Console
from rich.table import Table

load_dotenv()
console = Console()


# ---------------------------------------------------------------------------
# Typed structures
# ---------------------------------------------------------------------------

JSON = dict[str, Any]


class JsonRpcErrorObject(TypedDict, total=False):
    code: int
    message: str
    data: Any


class JsonRpcResponse(TypedDict, total=False):
    jsonrpc: str
    id: int | str | None
    result: Any
    error: JsonRpcErrorObject


class ToolDescriptor(TypedDict, total=False):
    name: str
    description: str
    inputSchema: dict[str, Any]


class UserInfo(TypedDict, total=False):
    sub: str
    preferred_username: str
    email: str
    name: str


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Settings:
    kc_base_url: str
    kc_realm: str
    kc_client_id: str
    kc_client_secret: str | None
    mcp_server_url: str
    redirect_port: int
    auth_timeout_seconds: int
    token_cache_file: str
    auth_mode: str
    mode: str
    open_browser: bool
    enable_sse: bool
    scope: str
    tool_name: str | None
    tool_args_json: str
    permission_test_tool: str
    show_userinfo: bool
    insecure_decode_jwt: bool

    @property
    def redirect_uri(self) -> str:
        return f"http://localhost:{self.redirect_port}/callback"

    @property
    def kc_auth_url(self) -> str:
        return (
            f"{self.kc_base_url}/realms/{self.kc_realm}"
            "/protocol/openid-connect/auth"
        )

    @property
    def kc_token_url(self) -> str:
        return (
            f"{self.kc_base_url}/realms/{self.kc_realm}"
            "/protocol/openid-connect/token"
        )

    @property
    def kc_userinfo_url(self) -> str:
        return (
            f"{self.kc_base_url}/realms/{self.kc_realm}"
            "/protocol/openid-connect/userinfo"
        )

    @property
    def token_cache_path(self) -> Path:
        return Path(self.token_cache_file)

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            kc_base_url=os.getenv("KC_BASE_URL", "http://localhost:8080").rstrip("/"),
            kc_realm=os.getenv("KC_REALM", "mcp-realm"),
            kc_client_id=os.getenv("KC_CLIENT_ID", "mcp-client"),
            kc_client_secret=os.getenv("KC_CLIENT_SECRET"),
            mcp_server_url=os.getenv("MCP_SERVER_URL", "http://localhost:3000").rstrip(
                "/"
            ),
            redirect_port=int(os.getenv("REDIRECT_PORT", "9999")),
            auth_timeout_seconds=int(os.getenv("AUTH_TIMEOUT_SECONDS", "120")),
            token_cache_file=os.getenv("TOKEN_CACHE_FILE", ".mcp_tokens.json"),
            auth_mode=os.getenv("AUTH_MODE", "pkce").strip().lower(),
            mode=os.getenv("MODE", "fulltest").strip().lower(),
            open_browser=os.getenv("OPEN_BROWSER", "true").lower() == "true",
            enable_sse=os.getenv("ENABLE_SSE", "false").lower() == "true",
            scope=os.getenv(
                "KC_SCOPE",
                "openid email profile mcp:tools:read mcp:tools:write",
            ),
            tool_name=os.getenv("TOOL_NAME"),
            tool_args_json=os.getenv("TOOL_ARGS_JSON", "{}"),
            permission_test_tool=os.getenv(
                "PERMISSION_TEST_TOOL",
                "admin_config_tool",
            ),
            show_userinfo=os.getenv("SHOW_USERINFO", "false").lower() == "true",
            insecure_decode_jwt=os.getenv("INSECURE_DECODE_JWT", "true").lower()
            == "true",
        )

    def validate(self) -> None:
        if self.auth_mode not in {"pkce", "refresh", "client_credentials"}:
            raise ValueError(
                "AUTH_MODE must be one of: pkce, refresh, client_credentials"
            )

        if self.mode not in {
            "login",
            "userinfo",
            "list",
            "call",
            "stream",
            "fulltest",
        }:
            raise ValueError(
                "MODE must be one of: login, userinfo, list, call, stream, fulltest"
            )

        if self.auth_mode == "client_credentials" and not self.kc_client_secret:
            raise ValueError(
                "AUTH_MODE=client_credentials requires KC_CLIENT_SECRET"
            )

        if self.mode == "call" and not self.tool_name:
            raise ValueError("MODE=call requires TOOL_NAME")

        if self.redirect_port < 1 or self.redirect_port > 65535:
            raise ValueError("REDIRECT_PORT must be between 1 and 65535")


SETTINGS = Settings.from_env()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class TokenSet:
    access_token: str
    refresh_token: str | None
    id_token: str | None
    expires_in: int
    scope: str
    obtained_at: int = 0
    token_type: str = "Bearer"

    def is_likely_expired(self, skew_seconds: int = 30) -> bool:
        if self.obtained_at <= 0 or self.expires_in <= 0:
            return False
        return int(time.time()) >= (self.obtained_at + self.expires_in - skew_seconds)

    def authorization_header(self) -> str:
        return f"{self.token_type} {self.access_token}"


@dataclass(slots=True)
class McpToolResult:
    tool_name: str
    content: list[dict[str, Any]]
    is_error: bool = False


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ConfigError(ValueError):
    pass


class AuthFlowError(RuntimeError):
    pass


class JsonRpcProtocolError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def parse_json_object(raw: str, label: str) -> dict[str, Any]:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"{label} must decode to a JSON object")
    return cast(dict[str, Any], data)


def redact_token(token: str | None, keep: int = 10) -> str:
    if not token:
        return "<none>"
    if len(token) <= keep:
        return token
    return f"{token[:keep]}...<redacted>"


def save_tokens_secure(settings: Settings, token_set: TokenSet) -> None:
    path = settings.token_cache_path
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(asdict(token_set), indent=2))

    try:
        os.chmod(tmp_path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass

    tmp_path.replace(path)

    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def load_tokens(settings: Settings) -> TokenSet | None:
    path = settings.token_cache_path
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text())
        return TokenSet(**data)
    except Exception:
        return None


def generate_pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def decode_jwt_unverified(token: str) -> dict[str, Any]:
    try:
        import jwt  # pyjwt

        claims = jwt.decode(token, options={"verify_signature": False})
        if isinstance(claims, dict):
            return cast(dict[str, Any], claims)
        return {}
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Local callback server
# ---------------------------------------------------------------------------

_auth_code: str | None = None
_auth_error: str | None = None
_auth_state: str | None = None


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        global _auth_code, _auth_error, _auth_state

        params = parse_qs(urlparse(self.path).query)
        returned_state = params.get("state", [None])[0]

        if "error" in params:
            _auth_error = params.get("error_description", ["Unknown auth error"])[0]
            body = b"<h2>Authentication failed. Check terminal output.</h2>"
        elif _auth_state and returned_state != _auth_state:
            _auth_error = "State mismatch in OAuth callback"
            body = b"<h2>Authentication failed: state mismatch.</h2>"
        elif "code" in params:
            _auth_code = params["code"][0]
            body = b"<h2>Authentication successful. You can close this tab.</h2>"
        else:
            _auth_error = "No auth code received"
            body = b"<h2>Authentication failed. No auth code received.</h2>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def wait_for_callback(redirect_port: int, expected_state: str) -> str:
    global _auth_code, _auth_error, _auth_state

    _auth_code = None
    _auth_error = None
    _auth_state = expected_state

    server = HTTPServer(("localhost", redirect_port), _CallbackHandler)
    server.handle_request()
    server.server_close()

    if _auth_error:
        raise AuthFlowError(_auth_error)
    if not _auth_code:
        raise AuthFlowError("No auth code received")

    return _auth_code


# ---------------------------------------------------------------------------
# Keycloak client
# ---------------------------------------------------------------------------

class KeycloakClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def authenticate_pkce(self) -> TokenSet:
        verifier, challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(24)

        params = {
            "client_id": self.settings.kc_client_id,
            "redirect_uri": self.settings.redirect_uri,
            "response_type": "code",
            "scope": self.settings.scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }

        auth_url = f"{self.settings.kc_auth_url}?{urlencode(params)}"

        console.print("\n[bold cyan]Starting Keycloak PKCE login...[/bold cyan]")
        console.print(f"[dim]Auth URL:[/dim] {auth_url}\n")

        result: list[str] = []
        errors: list[Exception] = []

        def listen() -> None:
            try:
                result.append(wait_for_callback(self.settings.redirect_port, state))
            except Exception as exc:
                errors.append(exc)

        listener = Thread(target=listen, daemon=True)
        listener.start()

        if self.settings.open_browser:
            webbrowser.open(auth_url)
        else:
            console.print("[yellow]OPEN_BROWSER=false, open the URL manually.[/yellow]")

        listener.join(timeout=self.settings.auth_timeout_seconds)

        if errors:
            raise AuthFlowError(str(errors[0]))
        if not result:
            raise AuthFlowError(
                f"Timed out waiting for callback "
                f"({self.settings.auth_timeout_seconds}s)"
            )

        return self.exchange_code(result[0], verifier)

    def exchange_code(self, code: str, verifier: str) -> TokenSet:
        with httpx.Client(timeout=30) as http:
            resp = http.post(
                self.settings.kc_token_url,
                data={
                    "grant_type": "authorization_code",
                    "client_id": self.settings.kc_client_id,
                    "redirect_uri": self.settings.redirect_uri,
                    "code": code,
                    "code_verifier": verifier,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        return TokenSet(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            expires_in=int(data.get("expires_in", 0)),
            scope=str(data.get("scope", "")),
            obtained_at=int(time.time()),
            token_type=str(data.get("token_type", "Bearer")),
        )

    def refresh_tokens(self, token_set: TokenSet) -> TokenSet:
        if not token_set.refresh_token:
            raise AuthFlowError("No refresh token available")

        with httpx.Client(timeout=30) as http:
            resp = http.post(
                self.settings.kc_token_url,
                data={
                    "grant_type": "refresh_token",
                    "client_id": self.settings.kc_client_id,
                    "refresh_token": token_set.refresh_token,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        return TokenSet(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token", token_set.refresh_token),
            id_token=data.get("id_token"),
            expires_in=int(data.get("expires_in", 0)),
            scope=str(data.get("scope", token_set.scope)),
            obtained_at=int(time.time()),
            token_type=str(data.get("token_type", token_set.token_type)),
        )

    def client_credentials(self) -> TokenSet:
        if not self.settings.kc_client_secret:
            raise AuthFlowError("KC_CLIENT_SECRET is required")

        with httpx.Client(timeout=30) as http:
            resp = http.post(
                self.settings.kc_token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.settings.kc_client_id,
                    "client_secret": self.settings.kc_client_secret,
                    "scope": self.settings.scope,
                },
            )
            resp.raise_for_status()
            data = resp.json()

        return TokenSet(
            access_token=data["access_token"],
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            expires_in=int(data.get("expires_in", 0)),
            scope=str(data.get("scope", self.settings.scope)),
            obtained_at=int(time.time()),
            token_type=str(data.get("token_type", "Bearer")),
        )

    def get_userinfo(self, token_set: TokenSet) -> UserInfo:
        with httpx.Client(timeout=30) as http:
            resp = http.get(
                self.settings.kc_userinfo_url,
                headers={"Authorization": token_set.authorization_header()},
            )
            resp.raise_for_status()
            data = resp.json()

        if not isinstance(data, dict):
            raise AuthFlowError("userinfo response was not a JSON object")

        return cast(UserInfo, data)


# ---------------------------------------------------------------------------
# MCP client
# ---------------------------------------------------------------------------

class McpClient:
    def __init__(self, settings: Settings, token_set: TokenSet):
        self.settings = settings
        self.token_set = token_set
        self._request_id = 0

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": self.token_set.authorization_header(),
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    @staticmethod
    def _validate_jsonrpc_response(data: Any) -> JsonRpcResponse:
        if not isinstance(data, dict):
            raise JsonRpcProtocolError("JSON-RPC response was not an object")

        parsed = cast(JsonRpcResponse, data)

        if "error" in parsed:
            err = parsed["error"]
            code = err.get("code", "unknown")
            message = err.get("message", "Unknown JSON-RPC error")
            raise RuntimeError(f"JSON-RPC error {code}: {message}")

        if "result" not in parsed:
            raise JsonRpcProtocolError("JSON-RPC response missing result/error")

        return parsed

    async def _post(
        self,
        client: httpx.AsyncClient,
        method: str,
        params: dict[str, Any] | None = None,
    ) -> JsonRpcResponse:
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        resp = await client.post(
            f"{self.settings.mcp_server_url}/mcp",
            json=payload,
            headers=self._headers(),
        )

        if resp.status_code == 401:
            raise PermissionError("401 Unauthorized — token may be expired")
        if resp.status_code == 403:
            raise PermissionError("403 Forbidden — insufficient scopes/roles")

        resp.raise_for_status()

        try:
            data = resp.json()
        except Exception as exc:
            raise JsonRpcProtocolError(
                f"Server did not return valid JSON: {exc}"
            ) from exc

        return self._validate_jsonrpc_response(data)

    async def initialize(self, client: httpx.AsyncClient) -> dict[str, Any]:
        result = await self._post(
            client,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "clientInfo": {
                    "name": "htb-mcp-keycloak-client",
                    "version": "1.1.0",
                },
                "capabilities": {},
            },
        )
        console.print("[bold green]✓ MCP session initialized[/bold green]")
        return cast(dict[str, Any], result["result"])

    async def list_tools(self, client: httpx.AsyncClient) -> list[ToolDescriptor]:
        result = await self._post(client, "tools/list")
        payload = result["result"]

        if not isinstance(payload, dict):
            raise JsonRpcProtocolError("tools/list result was not an object")

        tools = payload.get("tools", [])
        if not isinstance(tools, list):
            raise JsonRpcProtocolError("tools/list result.tools was not a list")

        validated: list[ToolDescriptor] = []
        for item in tools:
            if isinstance(item, dict):
                validated.append(cast(ToolDescriptor, item))
        return validated

    async def call_tool(
        self,
        client: httpx.AsyncClient,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> McpToolResult:
        result = await self._post(
            client,
            "tools/call",
            {"name": tool_name, "arguments": arguments or {}},
        )
        payload = result["result"]

        if not isinstance(payload, dict):
            raise JsonRpcProtocolError("tools/call result was not an object")

        content = payload.get("content", [])
        is_error = bool(payload.get("isError", False))

        if not isinstance(content, list):
            raise JsonRpcProtocolError("tools/call result.content was not a list")

        normalized_content: list[dict[str, Any]] = []
        for item in content:
            if isinstance(item, dict):
                normalized_content.append(cast(dict[str, Any], item))
            else:
                normalized_content.append({"type": "raw", "value": item})

        return McpToolResult(
            tool_name=tool_name,
            content=normalized_content,
            is_error=is_error,
        )

    async def subscribe_sse(self, client: httpx.AsyncClient) -> None:
        console.print(
            "\n[bold cyan]Subscribing to SSE stream (Ctrl+C to stop)...[/bold cyan]"
        )
        url = f"{self.settings.mcp_server_url}/mcp/sse"

        async with aconnect_sse(client, "GET", url, headers=self._headers()) as source:
            async for event in source.aiter_sse():
                rprint(
                    f"[dim]event:[/dim] [yellow]{event.event}[/yellow]  "
                    f"[dim]data:[/dim] {event.data}"
                )


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def print_token_info(settings: Settings, token_set: TokenSet) -> None:
    claims = (
        decode_jwt_unverified(token_set.access_token)
        if settings.insecure_decode_jwt
        else {}
    )

    table = Table(title="Token Info", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Subject", str(claims.get("sub", "?")))
    table.add_row("Username", str(claims.get("preferred_username", "?")))
    table.add_row("Email", str(claims.get("email", "?")))
    table.add_row("Expires in", f"{token_set.expires_in}s")
    table.add_row("Scopes", token_set.scope)
    table.add_row(
        "Realm roles",
        ", ".join(claims.get("realm_access", {}).get("roles", [])) or "none",
    )
    table.add_row("Access token", redact_token(token_set.access_token))
    table.add_row("Refresh token", redact_token(token_set.refresh_token))
    console.print(table)


def print_userinfo(userinfo: UserInfo) -> None:
    table = Table(title="UserInfo", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    for key in sorted(userinfo.keys()):
        table.add_row(str(key), str(userinfo[key]))

    console.print(table)


def print_tools(tools: list[ToolDescriptor]) -> None:
    table = Table(title="Available MCP Tools")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")

    for tool in tools:
        table.add_row(tool.get("name", "?"), tool.get("description", ""))

    console.print(table)


def print_result(result: McpToolResult) -> None:
    status = (
        "[bold red]ERROR[/bold red]"
        if result.is_error
        else "[bold green]OK[/bold green]"
    )
    console.print(f"\nTool [cyan]{result.tool_name}[/cyan] → {status}")

    for item in result.content:
        if item.get("type") == "text":
            rprint(item.get("text", ""))
        else:
            rprint(item)


# ---------------------------------------------------------------------------
# Auth bootstrap
# ---------------------------------------------------------------------------

def get_tokens(settings: Settings) -> TokenSet:
    kc = KeycloakClient(settings)
    cached = load_tokens(settings)

    if settings.auth_mode == "client_credentials":
        token_set = kc.client_credentials()
        save_tokens_secure(settings, token_set)
        console.print("[bold green]✓ Obtained client_credentials token[/bold green]")
        return token_set

    if settings.auth_mode == "refresh":
        if not cached:
            raise AuthFlowError("AUTH_MODE=refresh but no cached tokens found")
        token_set = kc.refresh_tokens(cached)
        save_tokens_secure(settings, token_set)
        console.print("[bold green]✓ Refreshed cached tokens[/bold green]")
        return token_set

    if cached and not cached.is_likely_expired():
        console.print("[bold green]✓ Using cached token set[/bold green]")
        return cached

    if cached and cached.refresh_token:
        try:
            token_set = kc.refresh_tokens(cached)
            save_tokens_secure(settings, token_set)
            console.print("[bold green]✓ Refreshed cached tokens[/bold green]")
            return token_set
        except Exception as exc:
            console.print(f"[yellow]Refresh failed, falling back to PKCE: {exc}[/yellow]")

    token_set = kc.authenticate_pkce()
    save_tokens_secure(settings, token_set)
    console.print("[bold green]✓ Authenticated successfully[/bold green]")
    return token_set


# ---------------------------------------------------------------------------
# Execution helpers
# ---------------------------------------------------------------------------

async def run_mode_login(settings: Settings, token_set: TokenSet) -> None:
    print_token_info(settings, token_set)


async def run_mode_userinfo(settings: Settings, token_set: TokenSet) -> None:
    kc = KeycloakClient(settings)
    print_token_info(settings, token_set)
    userinfo = kc.get_userinfo(token_set)
    print_userinfo(userinfo)


async def run_mode_list(settings: Settings, token_set: TokenSet) -> None:
    async with httpx.AsyncClient(timeout=30) as client:
        mcp = McpClient(settings, token_set)
        await mcp.initialize(client)
        tools = await mcp.list_tools(client)
        print_tools(tools)


async def run_mode_call(settings: Settings, token_set: TokenSet) -> None:
    if not settings.tool_name:
        raise ConfigError("TOOL_NAME is required for MODE=call")

    tool_args = parse_json_object(settings.tool_args_json, "TOOL_ARGS_JSON")

    async with httpx.AsyncClient(timeout=30) as client:
        mcp = McpClient(settings, token_set)
        await mcp.initialize(client)
        result = await mcp.call_tool(client, settings.tool_name, tool_args)
        print_result(result)


async def run_mode_stream(settings: Settings, token_set: TokenSet) -> None:
    async with httpx.AsyncClient(timeout=None) as client:
        mcp = McpClient(settings, token_set)
        await mcp.subscribe_sse(client)


async def run_mode_fulltest(settings: Settings, token_set: TokenSet) -> None:
    async with httpx.AsyncClient(timeout=30) as client:
        mcp = McpClient(settings, token_set)

        console.rule("[bold]1. Initialize MCP Session")
        await mcp.initialize(client)

        console.rule("[bold]2. List Tools")
        tools = await mcp.list_tools(client)
        print_tools(tools)

        if not tools:
            console.print("[yellow]No tools returned — check auth, scopes, or server[/yellow]")
            return

        console.rule("[bold]3. Smoke Test — Call First Tool")
        first_tool = tools[0]
        first_name = first_tool.get("name", "")
        if first_name:
            console.print(f"Calling [cyan]{first_name}[/cyan] with empty args...")
            result = await mcp.call_tool(client, first_name, {})
            print_result(result)

        if settings.tool_name:
            console.rule("[bold]4. Custom Tool Call")
            custom_args = parse_json_object(settings.tool_args_json, "TOOL_ARGS_JSON")
            console.print(f"Calling [cyan]{settings.tool_name}[/cyan]...")
            result = await mcp.call_tool(client, settings.tool_name, custom_args)
            print_result(result)

        console.rule("[bold]5. Permission Denial Test")
        console.print(
            f"Attempting [cyan]{settings.permission_test_tool}[/cyan] "
            "(expects denial or application error)..."
        )
        try:
            denied = await mcp.call_tool(client, settings.permission_test_tool, {})
            print_result(denied)
        except (PermissionError, RuntimeError) as exc:
            console.print(f"[bold green]✓ Denied as expected:[/bold green] {exc}")

        if settings.show_userinfo:
            console.rule("[bold]6. UserInfo")
            kc = KeycloakClient(settings)
            userinfo = kc.get_userinfo(token_set)
            print_userinfo(userinfo)

        if settings.enable_sse:
            console.rule("[bold]7. SSE Stream")
            try:
                await mcp.subscribe_sse(client)
            except KeyboardInterrupt:
                console.print("\n[dim]SSE stream closed[/dim]")


async def dispatch_mode(settings: Settings, token_set: TokenSet) -> None:
    if settings.mode == "login":
        await run_mode_login(settings, token_set)
    elif settings.mode == "userinfo":
        await run_mode_userinfo(settings, token_set)
    elif settings.mode == "list":
        await run_mode_list(settings, token_set)
    elif settings.mode == "call":
        await run_mode_call(settings, token_set)
    elif settings.mode == "stream":
        await run_mode_stream(settings, token_set)
    elif settings.mode == "fulltest":
        await run_mode_fulltest(settings, token_set)
    else:
        raise ConfigError(f"Unsupported MODE: {settings.mode}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    console.rule("[bold magenta]HTB Lab MCP + Keycloak Client")

    try:
        SETTINGS.validate()
    except Exception as exc:
        raise ConfigError(str(exc)) from exc

    token_set = get_tokens(SETTINGS)

    try:
        asyncio.run(dispatch_mode(SETTINGS, token_set))
    except PermissionError as exc:
        console.print(f"\n[bold red]Authorization error:[/bold red] {exc}")
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
    except Exception as exc:
        console.print(f"\n[bold red]Unexpected error:[/bold red] {exc}")
        raise

    console.rule("[bold magenta]Done")


if __name__ == "__main__":
    main()
