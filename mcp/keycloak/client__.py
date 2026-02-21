# mcp_keycloak_client.py

import asyncio
import base64
import hashlib
import json
import os
import secrets
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from httpx_sse import aconnect_sse
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import print as rprint

load_dotenv()
console = Console()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

KC_BASE_URL     = os.getenv("KC_BASE_URL", "http://localhost:8080")
KC_REALM        = os.getenv("KC_REALM", "mcp-realm")
KC_CLIENT_ID    = os.getenv("KC_CLIENT_ID", "mcp-client")
MCP_SERVER_URL  = os.getenv("MCP_SERVER_URL", "http://localhost:3000")
REDIRECT_PORT   = int(os.getenv("REDIRECT_PORT", "9999"))
REDIRECT_URI    = f"http://localhost:{REDIRECT_PORT}/callback"

KC_AUTH_URL     = f"{KC_BASE_URL}/realms/{KC_REALM}/protocol/openid-connect/auth"
KC_TOKEN_URL    = f"{KC_BASE_URL}/realms/{KC_REALM}/protocol/openid-connect/token"
KC_USERINFO_URL = f"{KC_BASE_URL}/realms/{KC_REALM}/protocol/openid-connect/userinfo"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TokenSet:
    access_token: str
    refresh_token: str | None
    id_token: str | None
    expires_in: int
    scope: str


@dataclass
class McpToolResult:
    tool_name: str
    content: list[dict]
    is_error: bool = False


# ---------------------------------------------------------------------------
# PKCE helpers
# ---------------------------------------------------------------------------

def generate_pkce_pair() -> tuple[str, str]:
    """Returns (code_verifier, code_challenge)."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# ---------------------------------------------------------------------------
# Local callback server (catches the auth code redirect)
# ---------------------------------------------------------------------------

_auth_code: str | None = None
_auth_error: str | None = None


class _CallbackHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global _auth_code, _auth_error
        params = parse_qs(urlparse(self.path).query)

        if "code" in params:
            _auth_code = params["code"][0]
            body = b"<h2>Auth successful! You can close this tab.</h2>"
        else:
            _auth_error = params.get("error_description", ["Unknown error"])[0]
            body = b"<h2>Auth failed. Check the terminal.</h2>"

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # suppress default HTTP logs


def _wait_for_callback() -> str:
    """Spins up a one-shot local HTTP server and waits for the auth code."""
    global _auth_code, _auth_error
    _auth_code = None
    _auth_error = None

    server = HTTPServer(("localhost", REDIRECT_PORT), _CallbackHandler)
    server.handle_request()  # blocks until one request is received
    server.server_close()

    if _auth_error:
        raise RuntimeError(f"Keycloak auth error: {_auth_error}")
    if not _auth_code:
        raise RuntimeError("No auth code received")

    return _auth_code


# ---------------------------------------------------------------------------
# Keycloak auth
# ---------------------------------------------------------------------------

def authenticate() -> TokenSet:
    """
    Full Authorization Code + PKCE flow.
    Opens the browser, waits for the redirect, exchanges the code for tokens.
    """
    verifier, challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(16)

    params = {
        "client_id":             KC_CLIENT_ID,
        "redirect_uri":          REDIRECT_URI,
        "response_type":         "code",
        "scope":                 "openid email profile mcp:tools:read mcp:tools:write",
        "state":                 state,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    }

    auth_url = f"{KC_AUTH_URL}?{urlencode(params)}"

    console.print("\n[bold cyan]Opening browser for Keycloak login...[/bold cyan]")
    console.print(f"[dim]If it doesn't open, visit:[/dim] {auth_url}\n")

    # Start callback listener in a background thread before opening browser
    result: list[str] = []
    error: list[Exception] = []

    def listen():
        try:
            result.append(_wait_for_callback())
        except Exception as e:
            error.append(e)

    t = Thread(target=listen, daemon=True)
    t.start()
    webbrowser.open(auth_url)
    t.join(timeout=120)

    if error:
        raise error[0]
    if not result:
        raise TimeoutError("Timed out waiting for Keycloak callback (120s)")

    code = result[0]

    # Exchange code for tokens
    with httpx.Client() as http:
        resp = http.post(
            KC_TOKEN_URL,
            data={
                "grant_type":    "authorization_code",
                "client_id":     KC_CLIENT_ID,
                "redirect_uri":  REDIRECT_URI,
                "code":          code,
                "code_verifier": verifier,
            },
        )
        resp.raise_for_status()
        data = resp.json()

    token_set = TokenSet(
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token"),
        id_token=data.get("id_token"),
        expires_in=data["expires_in"],
        scope=data.get("scope", ""),
    )

    console.print("[bold green]✓ Authenticated successfully[/bold green]")
    return token_set


def refresh_tokens(token_set: TokenSet) -> TokenSet:
    """Uses the refresh token to get a new access token."""
    if not token_set.refresh_token:
        raise RuntimeError("No refresh token available — re-authenticate")

    with httpx.Client() as http:
        resp = http.post(
            KC_TOKEN_URL,
            data={
                "grant_type":    "refresh_token",
                "client_id":     KC_CLIENT_ID,
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
    )


# ---------------------------------------------------------------------------
# MCP Client
# ---------------------------------------------------------------------------

class McpClient:
    def __init__(self, token_set: TokenSet):
        self.token_set = token_set
        self._session_id: str | None = None
        self._request_id = 0

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token_set.access_token}",
            "Content-Type":  "application/json",
            "Accept":        "application/json, text/event-stream",
        }

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    async def _post(
        self, client: httpx.AsyncClient, method: str, params: dict | None = None
    ) -> dict:
        payload = {
            "jsonrpc": "2.0",
            "id":      self._next_id(),
            "method":  method,
        }
        if params:
            payload["params"] = params

        resp = await client.post(
            f"{MCP_SERVER_URL}/mcp",
            json=payload,
            headers=self._headers(),
        )

        if resp.status_code == 401:
            raise PermissionError("401 Unauthorized — token may be expired")
        if resp.status_code == 403:
            raise PermissionError("403 Forbidden — insufficient scopes/roles")

        resp.raise_for_status()
        return resp.json()

    async def initialize(self, client: httpx.AsyncClient) -> dict:
        result = await self._post(
            client,
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "clientInfo": {
                    "name":    "mcp-keycloak-test-client",
                    "version": "1.0.0",
                },
                "capabilities": {},
            },
        )
        console.print("[bold green]✓ MCP session initialized[/bold green]")
        return result

    async def list_tools(self, client: httpx.AsyncClient) -> list[dict]:
        result = await self._post(client, "tools/list")
        tools = result.get("result", {}).get("tools", [])
        return tools

    async def call_tool(
        self,
        client: httpx.AsyncClient,
        tool_name: str,
        arguments: dict,
    ) -> McpToolResult:
        result = await self._post(
            client,
            "tools/call",
            {"name": tool_name, "arguments": arguments},
        )
        data = result.get("result", {})
        return McpToolResult(
            tool_name=tool_name,
            content=data.get("content", []),
            is_error=data.get("isError", False),
        )

    async def subscribe_sse(self, client: httpx.AsyncClient):
        """
        Listens to the SSE stream and prints events as they arrive.
        Ctrl+C to stop.
        """
        console.print("\n[bold cyan]Subscribing to SSE stream (Ctrl+C to stop)...[/bold cyan]")
        url = f"{MCP_SERVER_URL}/mcp/sse"

        async with aconnect_sse(client, "GET", url, headers=self._headers()) as source:
            async for event in source.aiter_sse():
                rprint(f"[dim]event:[/dim] [yellow]{event.event}[/yellow]  "
                       f"[dim]data:[/dim] {event.data}")


# ---------------------------------------------------------------------------
# Pretty printers
# ---------------------------------------------------------------------------

def print_token_info(token_set: TokenSet):
    import jwt  # pyjwt

    try:
        claims = jwt.decode(
            token_set.access_token,
            options={"verify_signature": False},
        )
    except Exception:
        claims = {}

    table = Table(title="Token Info", show_header=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Subject",   claims.get("sub", "?"))
    table.add_row("Username",  claims.get("preferred_username", "?"))
    table.add_row("Email",     claims.get("email", "?"))
    table.add_row("Expires in", f"{token_set.expires_in}s")
    table.add_row("Scopes",    token_set.scope)
    table.add_row(
        "Realm roles",
        ", ".join(claims.get("realm_access", {}).get("roles", [])) or "none",
    )

    console.print(table)


def print_tools(tools: list[dict]):
    table = Table(title="Available MCP Tools")
    table.add_column("Name",        style="cyan")
    table.add_column("Description", style="white")

    for tool in tools:
        table.add_row(tool["name"], tool.get("description", ""))

    console.print(table)


def print_result(result: McpToolResult):
    status = "[bold red]ERROR[/bold red]" if result.is_error else "[bold green]OK[/bold green]"
    console.print(f"\nTool [cyan]{result.tool_name}[/cyan] → {status}")
    for item in result.content:
        if item.get("type") == "text":
            rprint(item["text"])
        else:
            rprint(item)


# ---------------------------------------------------------------------------
# Main test runner
# ---------------------------------------------------------------------------

async def run_tests(token_set: TokenSet):
    async with httpx.AsyncClient(timeout=30) as client:
        mcp = McpClient(token_set)

        # 1. Initialize
        console.rule("[bold]1. Initialize MCP Session")
        await mcp.initialize(client)

        # 2. List tools
        console.rule("[bold]2. List Tools")
        tools = await mcp.list_tools(client)
        print_tools(tools)

        if not tools:
            console.print("[yellow]No tools returned — check server or scopes[/yellow]")
            return

        # 3. Call first available tool as a smoke test
        console.rule("[bold]3. Smoke Test — Call First Tool")
        first_tool = tools[0]
        console.print(f"Calling [cyan]{first_tool['name']}[/cyan] with empty args...")
        result = await mcp.call_tool(client, first_tool["name"], {})
        print_result(result)

        # 4. Permission denial test — attempt a tool requiring mcp:admin:config
        console.rule("[bold]4. Permission Denial Test")
        console.print("Attempting [cyan]admin_config_tool[/cyan] (expects 403 or error)...")
        try:
            denied = await mcp.call_tool(client, "admin_config_tool", {})
            print_result(denied)
        except PermissionError as e:
            console.print(f"[bold green]✓ Correctly denied:[/bold green] {e}")

        # 5. Token refresh
        console.rule("[bold]5. Token Refresh")
        try:
            refreshed = refresh_tokens(token_set)
            console.print(
                f"[bold green]✓ Token refreshed.[/bold green] "
                f"New expiry: {refreshed.expires_in}s"
            )
        except Exception as e:
            console.print(f"[yellow]Refresh skipped: {e}[/yellow]")

        # 6. SSE (optional)
        console.rule("[bold]6. SSE Stream (optional)")
        console.print("Skip SSE? [y/N] ", end="")
        skip = input().strip().lower()
        if skip != "y":
            try:
                await mcp.subscribe_sse(client)
            except KeyboardInterrupt:
                console.print("\n[dim]SSE stream closed[/dim]")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    console.rule("[bold magenta]MCP + Keycloak Test Client")

    # Auth
    token_set = authenticate()
    print_token_info(token_set)

    # Run test suite
    try:
        asyncio.run(run_tests(token_set))
    except PermissionError as e:
        console.print(f"\n[bold red]Auth error:[/bold red] {e}")
    except Exception as e:
        console.print(f"\n[bold red]Unexpected error:[/bold red] {e}")
        raise

    console.rule("[bold magenta]Done")


if __name__ == "__main__":
    main()
