# MCP + Keycloak Integration ..beta..

A spec and reference implementation for integrating Keycloak as an
OAuth 2.0 / OIDC authorization provider with a network-hosted MCP
(Model Context Protocol) server, including a Python test client.

---

## Repo Structure

```text
mcp-keycloak/
├── SPEC.md                      # This document (full technical spec)
├── mcp-keycloak-client.py       # Standalone Python test client
├── .env.example                 # Environment variable template
├── server/                      # MCP server (TypeScript)
│   ├── src/
│   │   ├── auth/
│   │   │   ├── keycloak.ts      # JWKS client + JWT validation
│   │   │   ├── middleware.ts    # Express auth middleware
│   │   │   ├── permissions.ts  # Scope/role → tool resolver
│   │   │   └── types.ts        # Auth context types
│   │   ├── tools/
│   │   │   ├── registry.ts     # Tool registration w/ scope guards
│   │   │   └── handlers/       # Individual tool implementations
│   │   ├── audit/
│   │   │   └── logger.ts       # Structured audit logger
│   │   └── server.ts           # Entry point
│   ├── .env.example
│   └── package.json
```

---

## How It Works

```text
  MCP Client (e.g. Claude Desktop / custom agent)
        |
        |  1. Initial MCP request (no token)
        v
  ┌─────────────────────┐
  │     MCP Server      │
  │  Auth middleware    │──── 2. Returns 401 + WWW-Authenticate header
  │  detects no token   │         with Keycloak auth endpoint
  └─────────────────────┘
        |
        |  3. Client initiates OAuth2 Authorization Code + PKCE flow
        v
  ┌─────────────────────┐
  │      Keycloak       │
  │   (OIDC Provider)   │
  │  - Authenticates    │
  │  - Applies roles    │
  │  - Issues JWT       │
  └─────────────────────┘
        |
        |  4. Returns auth code → client exchanges for tokens
        v
        |  5. Retries MCP request with Bearer token
        v
  ┌─────────────────────┐
  │     MCP Server      │
  │  Validates JWT via  │◄──── JWKS endpoint (cached)
  │  JWKS, extracts     │
  │  scopes + roles,    │
  │  enforces per-tool  │
  │  permissions        │
  └─────────────────────┘
        |
        |  6. Executes tool, returns result
        v
  MCP Client / Agent
```

---

## Prerequisites

- **Keycloak 24+** running and accessible
- **Node.js 20+** for the MCP server
- **Python 3.11+** for the test client

---

## Keycloak Setup

### 1. Create a Realm

In the Keycloak admin console, create a new realm named `mcp-realm`.

### 2. Create the Server Client (`mcp-server`)

| Setting | Value |
|---|---|
| Client ID | `mcp-server` |
| Access Type | `confidential` |
| Bearer Only | `true` |
| Service Accounts | `enabled` |

### 3. Create the Public Client (`mcp-client`)

| Setting | Value |
|---|---|
| Client ID | `mcp-client` |
| Access Type | `public` |
| Standard Flow | `enabled` |
| PKCE Method | `S256` |
| Redirect URIs | `http://localhost:9999/callback` |

### 4. Create Realm Roles

```text
mcp:admin      → full access including admin tools
mcp:user       → standard tool access
mcp:readonly   → read-only tools only
mcp:service    → M2M service account access
```

### 5. Create Client Scopes

```text
mcp:tools:read
mcp:tools:write
mcp:tools:execute
mcp:resources:read
mcp:resources:write
mcp:admin:config
```

Map these scopes to roles via **Client Scopes → Scope Mappings**
in the Keycloak admin console.

---

## MCP Server Setup

```bash
cd server
cp .env.example .env
# fill in your values

npm install
npm run build
npm start
```

### Server Environment Variables

```bash
KC_BASE_URL=https://your-keycloak-host
KC_REALM=mcp-realm
KC_CLIENT_ID=mcp-server
KC_CLIENT_SECRET=your-client-secret
PORT=3000
NODE_ENV=production
```

---

## Python Test Client Setup

```bash
pip install httpx httpx-sse python-dotenv pyjwt cryptography rich

cp .env.example .env
# fill in your values

python mcp_keycloak_client.py
```

### Client Environment Variables

```bash
KC_BASE_URL=http://localhost:8080
KC_REALM=mcp-realm
KC_CLIENT_ID=mcp-client
MCP_SERVER_URL=http://localhost:3000
REDIRECT_PORT=9999
```

### What the Test Client Does

| Step | Description |
|---|---|
| 1 | Opens Keycloak login in browser via PKCE |
| 2 | Catches the auth code redirect on `localhost:9999` |
| 3 | Exchanges code for tokens, displays decoded claims |
| 4 | Initializes an MCP session |
| 5 | Lists all available tools |
| 6 | Smoke tests the first available tool |
| 7 | Attempts `admin_config_tool` — expects a 403 denial |
| 8 | Tests token refresh |
| 9 | Optionally subscribes to the SSE stream |

---

## Security Notes

- Access tokens are short-lived (5 min). Refresh tokens are used
  automatically.
- JWT validation is done **locally** via the Keycloak JWKS endpoint
  (cached, rate-limited). No introspection round-trips on hot paths.
- PKCE (`S256`) is enforced on all public clients. No client secret
  is ever exposed to the browser or test client.
- All tool handlers receive a verified `AuthContext` — raw token
  claims are never trusted directly from the request.
- Use `ssl-required: all` in Keycloak for production deployments.

---

## Open Questions

- [ ] Token revocation: short TTL only, or Redis-backed jti blocklist?
- [ ] M2M: client credentials flow for service accounts needed?
- [ ] Multi-tenancy: one realm per tenant, or realm roles + groups?
- [ ] Rate limiting: per-user token bucket on MCP server layer?
- [ ] Refresh token handling: MCP client manages refresh, or a proxy?

---

## References

- [MCP Specification](https://spec.modelcontextprotocol.io)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OAuth 2.0 PKCE — RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
