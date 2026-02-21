# MCP + Keycloak Integration Spec

## Overview

A secure, production-grade integration between a network-hosted MCP server and Keycloak as the OIDC/OAuth 2.0 authorization server. Designed for multi-tenant, enterprise, or team-based deployments where tool-level access control and auditability are required.

---

## Stack Assumptions

| Component | Technology |
|---|---|
| MCP Server | Node.js (TypeScript) w/ `@modelcontextprotocol/sdk` |
| Auth Server | Keycloak 24+ |
| Transport | HTTP + SSE (Streamable HTTP) |
| Token Format | JWT (RS256) |
| Client Auth | PKCE (public clients) / client secret (confidential) |
| Session | Stateless (bearer token per request) |

---

## Auth Flow (ASCII)

```text
  MCP Client (e.g. Claude Desktop / custom agent)
        |
        |  1. Initial MCP request (no token)
        v
  ┌─────────────────────┐
  │     MCP Server      │
  │  (Express + SDK)    │
  │                     │
  │  Auth middleware    │──── 2. Returns 401 + WWW-Authenticate header
  │  detects no token   │         with Keycloak auth endpoint
  └─────────────────────┘
        |
        |  3. Client initiates OAuth2 Authorization Code + PKCE flow
        v
  ┌─────────────────────┐
  │      Keycloak       │
  │   (OIDC Provider)   │
  │                     │
  │  - Authenticates    │
  │    user/service     │
  │  - Checks realm     │
  │  - Applies roles    │
  │  - Issues JWT       │
  └─────────────────────┘
        |
        |  4. Returns authorization code to redirect_uri
        v
  MCP Client exchanges code for tokens (access + refresh)
        |
        |  5. Retries MCP request with Bearer token in Authorization header
        v
  ┌─────────────────────┐
  │     MCP Server      │
  │                     │
  │  6. Validates JWT   │◄──── fetches JWKS from Keycloak (cached)
  │     locally via     │      https://{kc}/realms/{realm}/
  │     JWKS endpoint   │      protocol/openid-connect/certs
  │                     │
  │  7. Extracts:       │
  │    - sub (user id)  │
  │    - realm_access   │
  │    - resource_access│
  │    - scope          │
  │                     │
  │  8. Resolves tool   │
  │     permissions     │
  │     from claims     │
  └─────────────────────┘
        |
        |  9. Executes MCP tool if authorized
        v
  ┌─────────────────────┐
  │   Tool Handler      │
  │                     │
  │  - Has access to    │
  │    verified ctx     │
  │  - Scoped to user   │
  │  - Audit logged     │
  └─────────────────────┘
        |
        | 10. Returns tool result to MCP client
        v
  MCP Client / Agent
```

---

## Keycloak Configuration Spec

### Realm Settings

```text
Realm Name:         mcp-realm
SSL Required:       external (minimum) / all (recommended prod)
Token Lifespan:     Access  = 300s  (5 min)
                    Refresh = 1800s (30 min)
SSO Session:        1800s
Revocation Policy:  Enabled (lifespan-based + admin revoke)
```

### Client: `mcp-server`

```text
Client ID:          mcp-server
Access Type:        confidential
Standard Flow:      disabled
Direct Access:      disabled
Service Accounts:   enabled  (for M2M / service-to-service)
Bearer Only:        true     (server never initiates login)
```

### Client: `mcp-client`

```text
Client ID:          mcp-client
Access Type:        public
Standard Flow:      enabled
PKCE:               S256 (required)
Redirect URIs:      http://localhost:3000/callback   (dev)
                    https://your-app.com/callback    (prod)
Web Origins:        +  (inherits from redirect URIs)
Direct Access:      disabled
```

### Realm Roles (coarse-grained)

```text
mcp:admin           Full tool access + admin tools
mcp:user            Standard tool access
mcp:readonly        Read-only tools only
mcp:service         M2M service account access
```

### Client Scopes (fine-grained, mapped to MCP tools)

```text
mcp:tools:read          Access to read/query tools
mcp:tools:write         Access to mutating tools
mcp:tools:execute       Access to execution/shell tools
mcp:resources:read      Access to resource endpoints
mcp:resources:write     Access to resource mutation
mcp:admin:config        Access to server config tools
```

### Scope-to-Role Mapping

```text
mcp:readonly   →  mcp:tools:read, mcp:resources:read
mcp:user       →  mcp:tools:read, mcp:tools:write,
                  mcp:resources:read, mcp:resources:write,
                  mcp:tools:execute
mcp:admin      →  all scopes including mcp:admin:config
mcp:service    →  mcp:tools:read, mcp:tools:execute (configurable)
```

---

## MCP Server Implementation Spec

### Directory Structure

```text
mcp-server/
├── src/
│   ├── auth/
│   │   ├── keycloak.ts        # JWKS client + token validation
│   │   ├── middleware.ts      # Express auth middleware
│   │   ├── permissions.ts     # Scope/role → tool permission resolver
│   │   └── types.ts           # Auth context types
│   ├── tools/
│   │   ├── registry.ts        # Tool registration w/ required scopes
│   │   └── handlers/          # Individual tool implementations
│   ├── audit/
│   │   └── logger.ts          # Structured audit log
│   └── server.ts              # Entry point
├── .env
└── package.json
```

### Environment Variables

```bash
# Keycloak
KC_BASE_URL=https://keycloak.internal
KC_REALM=mcp-realm
KC_CLIENT_ID=mcp-server
KC_CLIENT_SECRET=your-client-secret

# Derived (constructed in code)
# JWKS URI = KC_BASE_URL/realms/KC_REALM/protocol/openid-connect/certs
# ISSUER   = KC_BASE_URL/realms/KC_REALM

# Server
PORT=3000
NODE_ENV=production
LOG_LEVEL=info
```

### Auth Context Type

```typescript
// src/auth/types.ts

export interface KeycloakTokenClaims {
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  jti: string;
  preferred_username: string;
  email?: string;
  realm_access?: { roles: string[] };
  resource_access?: Record<string, { roles: string[] }>;
  scope: string;
}

export interface McpAuthContext {
  userId: string;
  username: string;
  email?: string;
  realmRoles: string[];
  clientRoles: string[];
  scopes: string[];
  rawToken: KeycloakTokenClaims;
}
```

### JWKS Validation

```typescript
// src/auth/keycloak.ts

import jwksRsa from "jwks-rsa";
import jwt from "jsonwebtoken";
import { KeycloakTokenClaims, McpAuthContext } from "./types.js";

const jwksClient = jwksRsa({
  jwksUri: `${process.env.KC_BASE_URL}/realms/${process.env.KC_REALM}/protocol/openid-connect/certs`,
  cache: true,
  cacheMaxEntries: 10,
  cacheMaxAge: 600_000, // 10 min
  rateLimit: true,
  jwksRequestsPerMinute: 10,
});

export async function validateToken(
  token: string
): Promise<McpAuthContext> {
  const claims = await new Promise<KeycloakTokenClaims>(
    (resolve, reject) => {
      jwt.verify(
        token,
        (header, callback) => {
          jwksClient.getSigningKey(header.kid, (err, key) => {
            callback(err, key?.getPublicKey());
          });
        },
        {
          algorithms: ["RS256"],
          issuer: `${process.env.KC_BASE_URL}/realms/${process.env.KC_REALM}`,
          audience: process.env.KC_CLIENT_ID,
        },
        (err, decoded) => {
          if (err) reject(err);
          else resolve(decoded as KeycloakTokenClaims);
        }
      );
    }
  );

  return {
    userId: claims.sub,
    username: claims.preferred_username,
    email: claims.email,
    realmRoles: claims.realm_access?.roles ?? [],
    clientRoles:
      claims.resource_access?.[process.env.KC_CLIENT_ID!]?.roles ?? [],
    scopes: claims.scope.split(" "),
    rawToken: claims,
  };
}
```

### Auth Middleware

```typescript
// src/auth/middleware.ts

import { Request, Response, NextFunction } from "express";
import { validateToken } from "./keycloak.js";
import { McpAuthContext } from "./types.js";

declare global {
  namespace Express {
    interface Request {
      auth?: McpAuthContext;
    }
  }
}

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  const authHeader = req.headers["authorization"];

  if (!authHeader?.startsWith("Bearer ")) {
    res.set(
      "WWW-Authenticate",
      [
        `Bearer realm="${process.env.KC_REALM}"`,
        `authorization_uri="${process.env.KC_BASE_URL}/realms/${process.env.KC_REALM}/protocol/openid-connect/auth"`,
        `token_uri="${process.env.KC_BASE_URL}/realms/${process.env.KC_REALM}/protocol/openid-connect/token"`,
        `resource="${process.env.KC_CLIENT_ID}"`,
        'scope="openid mcp:tools:read mcp:tools:write"',
      ].join(", ")
    );
    res.status(401).json({ error: "missing_token" });
    return;
  }

  try {
    const token = authHeader.slice(7);
    req.auth = await validateToken(token);
    next();
  } catch (err) {
    res.status(401).json({
      error: "invalid_token",
      detail: err instanceof Error ? err.message : "unknown",
    });
  }
}
```

### Tool Registry with Scope Guards

```typescript
// src/tools/registry.ts

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAuthContext } from "../auth/types.js";

export interface ToolDefinition {
  name: string;
  description: string;
  requiredScopes: string[];
  requiredRoles?: string[];
  handler: (args: unknown, auth: McpAuthContext) => Promise<unknown>;
}

export function registerTool(
  server: McpServer,
  tool: ToolDefinition
): void {
  server.tool(tool.name, tool.description, {}, async (args, extra) => {
    const auth = (extra.requestContext as { auth: McpAuthContext }).auth;

    const hasScopes = tool.requiredScopes.every((s) =>
      auth.scopes.includes(s)
    );
    const hasRoles =
      !tool.requiredRoles ||
      tool.requiredRoles.some(
        (r) =>
          auth.realmRoles.includes(r) || auth.clientRoles.includes(r)
      );

    if (!hasScopes || !hasRoles) {
      return {
        content: [{ type: "text", text: "Forbidden: insufficient permissions" }],
        isError: true,
      };
    }

    const result = await tool.handler(args, auth);
    return {
      content: [{ type: "text", text: JSON.stringify(result) }],
    };
  });
}
```

---

## Security Controls Summary

```text
Control                        Implementation
─────────────────────────────────────────────────────────────────
Token validation               Local JWT/RS256 via JWKS (cached)
Token expiry                   Enforced via exp claim (5 min AT)
Replay protection              jti claim tracking (optional Redis)
Transport security             TLS required (KC ssl-required: all)
Scope enforcement              Per-tool scope check in registry
Role enforcement               Per-tool role check in registry
Token revocation               KC admin API + short TTL fallback
PKCE enforcement               Required on mcp-client (public)
Secret protection              KC client secret in env / vault
Audit trail                    Structured log: user+tool+timestamp
Clock skew tolerance           ±30s (jwt clockTolerance option)
JWKS cache poisoning           Rate-limited JWKS fetches (10/min)
```

---

## Audit Log Schema

```typescript
interface AuditEvent {
  timestamp: string;       // ISO 8601
  eventType: "tool_call" | "auth_failure" | "permission_denied";
  userId: string;          // sub claim
  username: string;
  toolName?: string;
  scopes: string[];
  realmRoles: string[];
  sourceIp: string;
  requestId: string;       // trace ID
  success: boolean;
  errorReason?: string;
}
```

---

## Open Questions / Decisions Needed

- [ ] Token revocation: short TTL only, or Redis-backed jti blocklist?
- [ ] M2M: client credentials flow for service accounts needed?
- [ ] Multi-tenancy: one realm per tenant, or realm roles + groups?
- [ ] Rate limiting: per-user token bucket on MCP server layer?
- [ ] Refresh token handling: does the MCP client manage refresh, or a proxy layer?

---
