import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
import webbrowser
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
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
# Settings
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Settings:
    kc_base_url: str = os.getenv("KC_BASE_URL", "http://localhost:8080")
    kc_realm: str = os.getenv("KC_REALM", "mcp-realm")
    kc_client_id: str = os.getenv("KC_CLIENT_ID", "mcp-client")
    mcp_server_url: str = os.getenv("MCP_SERVER_URL", "http://localhost:3000")
    redirect_port: int = int(os.getenv("REDIRECT_PORT", "9999"))
    auth_timeout_seconds: int = int(os.getenv("AUTH_TIMEOUT_SECONDS", "120"))
    token_cache_file: str = os.getenv("TOKEN_CACHE_FILE", ".mcp_tokens.json")
    auth_mode: str = os.getenv("AUTH_MODE", "pkce")
    open_browser: bool = os.getenv("OPEN_BROWSER", "true").lower() == "true"
    scope: str = os.getenv(
        "KC_SCOPE",
        "openid email profile mcp:tools:read mcp:tools:write",
    )

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


SETTINGS = Settings()


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

    def is_likely_expired(self, skew_seconds: int = 30) -> bool:
        if not self.obtained_at or not self.expires_in:
            return False
        return int(time.time()) >= (self.obtained_at + self.expires_in - skew_seconds)


@dataclass(slots=True)
class McpToolResult:
    tool_name: str
    content: list[dict]
    is_error: bool = False


# ---------------------------------------------------------------------------
# Token cache
# ---------------------------------------------------------------------------

def save_tokens(settings: Settings, token_set: TokenSet) -> None:
    settings.token_cache_path.write_text(json.dumps(asdict(token_set), indent=2))


def load_tokens(settings: Settings) -> TokenSet | None:
    if not settings.token_cache_path.exists():
        return None
    try:
        data = json.loads(settings.token_cache_path.read_text())
        return TokenSet(**data)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# PKCE
# ---------------------------------------------------------------------------

def generate_pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ---------------------------------------------------------------------------
# Local callback server
# ---------------------------------------------------------------------------

_auth_code: str | None = None
_auth_error: str | None = None


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global _auth_code, _auth_error
        params = parse_qs(urlparse(self.path).query)

        if "code" in params:
            _auth_code = params["code"][0]
            body = b"<h2>Auth successful. You can close this tab.</h2>"
        else:
            _auth_error = params.get("error_description", ["Unknown error"])[0]
            body = b"<h2>Auth failed. Check terminal output.</h2>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


def wait_for_callback(redirect_port: int) -> str:
    global _auth_code, _auth_error
    _auth_code = None
    _auth_error = None

    server = HTTPServer(("localhost", redirect_port), _CallbackHandler)
    server.handle_request()
    server.server_close()

    if _auth_error:
        raise RuntimeError(f"Keycloak auth error: {_auth_error}")
    if not _auth_code:
        raise RuntimeError("No auth code received")

    return _auth_code


# ---------------------------------------------------------------------------
# Keycloak client
# ---------------------------------------------------------------------------

class KeycloakClient:
    def __init__(self, settings: Settings):
        self.settings = settings

    def authenticate_pkce(self) -> TokenSet:
        verifier, challenge = generate_pkce_pair()
        state = secrets.token_urlsafe(16)

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
        console.print(f"[dim]Login URL:[/dim] {auth_url}\n")

        result: list[str] = []
        errors: list[Exception] = []

        def listen():
            try:
                result.append(wait_for_callback(self.settings.redirect_port))
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
            raise errors[0]
        if not result:
            raise TimeoutError(
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
            expires_in=data["expires_in"],
            scope=data.get("scope", ""),
            obtained_at=int(time.time()),
        )

    def refresh_tokens(self, token_set: TokenSet) -> TokenSet:
        if not token_set.refresh_token:
            raise RuntimeError("No refresh token available")

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
            expires_in=data["expires_in"],
            scope=data.get("scope", token_set.scope),
            obtained_at=int(time.time()),
        )

    def get_userinfo(self, access_token: str) -> dict:
        with httpx.Client(timeout=30) as http:
            resp = http.get(
                self.settings.kc_userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            return resp.json()


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
            "Authorization": f"Bearer {self.token_set.access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def _post(
        self,
        client: httpx.AsyncClient,
        method: str,
        params: dict | None = None,
    ) -> dict:
        payload = {
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
        data = resp.json()

        if "error" in data:
            err = data["error"]
            code = err.get("code", "unknown")
            message = err.get("message", "Unknown JSON-RPC error")
            raise RuntimeError(f"JSON-RPC error {code}: {message}")

        return data

    async def initialize(self, client: httpx.AsyncClient) -> dict:
        result = await self._post(
            client,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "clientInfo": {
                    "name": "htb-mcp-keycloak-client",
                    "version": "1.0.0",
                },
                "capabilities": {},
            },
        )
        console.print("[bold green]✓ MCP session initialized[/bold green]")
        return result

    async def list_tools(self, client: httpx.AsyncClient) -> list[dict]:
        result = await self._post(client, "tools/list")
        return result.get("result", {}).get("tools", [])

    async def call_tool(
        self,
        client: httpx.AsyncClient,
        tool_name: str,
        arguments: dict | None = None,
    ) -> McpToolResult:
        result = await self._post(
            client,
            "tools/call",
            {
                "name": tool_name,
                "arguments": arguments or {},
            },
        )
        data = result.get("result", {})
        return McpToolResult(
            tool_name=tool_name,
            content=data.get("content", []),
            is_error=data.get("isError", False),
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
# Pretty printers
# ---------------------------------------------------------------------------

def print_token_info(token_set: TokenSet) -> None:
    try:
        import jwt  # pyjwt

        claims = jwt.decode(
            token_set.access_token,
            options={"verify_signature": False},
        )
    except Exception:
        claims = {}

    table = Table(title="Token Info", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    table.add_row("Subject", claims.get("sub", "?"))
    table.add_row("Username", claims.get("preferred_username", "?"))
    table.add_row("Email", claims.get("email", "?"))
    table.add_row("Expires in", f"{token_set.expires_in}s")
    table.add_row("Scopes", token_set.scope)
    table.add_row(
        "Realm roles",
        ", ".join(claims.get("realm_access", {}).get("roles", [])) or "none",
    )
    console.print(table)


def print_tools(tools: list[dict]) -> None:
    table = Table(title="Available MCP Tools")
    table.add_column("Name", style="cyan")
    table.add_column("Description", style="white")

    for tool in tools:
        table.add_row(tool.get("name", "?"), tool.get("description", ""))

    console.print(table)


def print_result(result: McpToolResult) -> None:
    status = "[bold red]ERROR[/bold red]" if result.is_error else "[bold green]OK[/bold green]"
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

    if settings.auth_mode == "refresh":
        if not cached:
            raise RuntimeError("AUTH_MODE=refresh but no cached tokens found")
        refreshed = kc.refresh_tokens(cached)
        save_tokens(settings, refreshed)
        console.print("[bold green]✓ Refreshed cached tokens[/bold green]")
        return refreshed

    if cached and not cached.is_likely_expired():
        console.print("[bold green]✓ Using cached token set[/bold green]")
        return cached

    if cached and cached.refresh_token:
        try:
            refreshed = kc.refresh_tokens(cached)
            save_tokens(settings, refreshed)
            console.print("[bold green]✓ Refreshed cached tokens[/bold green]")
            return refreshed
        except Exception as exc:
            console.print(f"[yellow]Refresh failed, falling back to PKCE: {exc}[/yellow]")

    token_set = kc.authenticate_pkce()
    save_tokens(settings, token_set)
    console.print("[bold green]✓ Authenticated successfully[/bold green]")
    return token_set


# ---------------------------------------------------------------------------
# Main test runner
# ---------------------------------------------------------------------------

async def run_tests(settings: Settings, token_set: TokenSet) -> None:
    async with httpx.AsyncClient(timeout=30) as client:
        mcp = McpClient(settings, token_set)

        console.rule("[bold]1. Initialize MCP Session")
        await mcp.initialize(client)

        console.rule("[bold]2. List Tools")
        tools = await mcp.list_tools(client)
        print_tools(tools)

        if not tools:
            console.print("[yellow]No tools returned — check server, auth, or scopes[/yellow]")
            return

        console.rule("[bold]3. Smoke Test — Call First Tool")
        first_tool = tools[0]
        first_name = first_tool.get("name", "")
        console.print(f"Calling [cyan]{first_name}[/cyan] with empty args...")
        result = await mcp.call_tool(client, first_name, {})
        print_result(result)

        console.rule("[bold]4. Permission Denial Test")
        console.print(
            "Attempting [cyan]admin_config_tool[/cyan] "
            "(expects 403 or application error)..."
        )
        try:
            denied = await mcp.call_tool(client, "admin_config_tool", {})
            print_result(denied)
        except (PermissionError, RuntimeError) as exc:
            console.print(f"[bold green]✓ Denied as expected:[/bold green] {exc}")

        console.rule("[bold]5. SSE Stream")
        console.print(
            "[dim]Set ENABLE_SSE=true if you want to test event streaming.[/dim]"
        )
        if os.getenv("ENABLE_SSE", "false").lower() == "true":
            try:
                await mcp.subscribe_sse(client)
            except KeyboardInterrupt:
                console.print("\n[dim]SSE stream closed[/dim]")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    console.rule("[bold magenta]HTB Lab MCP + Keycloak Client")

    token_set = get_tokens(SETTINGS)
    print_token_info(token_set)

    try:
        asyncio.run(run_tests(SETTINGS, token_set))
    except PermissionError as exc:
        console.print(f"\n[bold red]Auth error:[/bold red] {exc}")
    except Exception as exc:
        console.print(f"\n[bold red]Unexpected error:[/bold red] {exc}")
        raise

    console.rule("[bold magenta]Done")


if __name__ == "__main__":
    main()
