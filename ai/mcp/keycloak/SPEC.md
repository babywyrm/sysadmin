
# MCP + Keycloak Integration Spec

> Production-grade integration between a network-hosted MCP server and Keycloak
> as the OIDC/OAuth 2.0 authorization server. Designed for multi-tenant,
> enterprise, or team-based deployments where tool-level access control and
> auditability are required.

---

## Table of Contents

1. [Stack](#stack)
2. [Auth Flow](#auth-flow)
3. [Keycloak Configuration](#keycloak-configuration)
4. [MCP Server Implementation](#mcp-server-implementation)
5. [Security Controls](#security-controls)
6. [Audit Log Schema](#audit-log-schema)
7. [Open Questions](#open-questions)

---

## Stack

| Component    | Technology                                    |
| ------------ | --------------------------------------------- |
| MCP Server   | Node.js (TypeScript) w/ `@modelcontextprotocol/sdk` |
| Auth Server  | Keycloak 24+                                  |
| Transport    | HTTP + SSE (Streamable HTTP)                  |
| Token Format | JWT (RS256)                                   |
| Client Auth  | PKCE (public clients) / client secret (confidential) |
| Session      | Stateless (bearer token per request)          |
| Rate Limit   | Per-user in-memory token bucket (Redis for multi-instance) |
| Audit Log    | Structured JSON via `pino`                    |

---

## Auth Flow

```text
  MCP Client (e.g. Claude Desktop / custom agent)
        │
        │  1. Initial MCP request (no token)
        ▼
  ┌─────────────────────────┐
  │       MCP Server        │
  │   (Express + SDK)       │
  │                         │
  │   authMiddleware        │──── 2. Returns 401 + WWW-Authenticate
  │   detects no token      │         with Keycloak endpoints +
  │                         │         required scopes
  └─────────────────────────┘
        │
        │  3. Client initiates OAuth2 Authorization Code + PKCE flow
        ▼
  ┌─────────────────────────┐
  │        Keycloak         │
  │    (OIDC Provider)      │
  │                         │
  │  · Authenticates user   │
  │  · Checks realm         │
  │  · Applies roles        │
  │  · Issues JWT (RS256)   │
  └─────────────────────────┘
        │
        │  4. Returns authorization code → redirect_uri
        ▼
  MCP Client exchanges code for tokens (access + refresh)
        │
        │  5. Retries MCP request with Bearer token
        ▼
  ┌─────────────────────────┐
  │       MCP Server        │
  │                         │
  │  6. Validates JWT       │◄── fetches JWKS from Keycloak (cached,
  │     locally via JWKS    │    rate-limited, poisoning-detected)
  │                         │
  │  7. Validates azp claim │◄── rejects tokens from untrusted clients
  │                         │
  │  8. Extracts context:   │
  │    · sub  (user id)     │
  │    · azp  (client id)   │
  │    · jti  (token id)    │
  │    · realm_access       │
  │    · resource_access    │
  │    · scope              │
  │    · exp  (expiry)      │
  │                         │
  │  9. Per-user rate limit │
  │                         │
  │  10. Resolves tool      │
  │      permissions from   │
  │      claims             │
  └─────────────────────────┘
        │
        │  11. Executes MCP tool if authorized
        ▼
  ┌─────────────────────────┐
  │      Tool Handler       │
  │                         │
  │  · Verified auth ctx    │
  │  · Scoped to user       │
  │  · Args schema-valid    │
  │  · Audit logged         │
  │  · Duration tracked     │
  └─────────────────────────┘
        │
        │  12. Returns tool result to MCP client
        ▼
  MCP Client / Agent

  ── SSE Long-lived Streams ──────────────────────────────────────────

  After step 5, for SSE connections:

  MCP Server (every 30s) ──► checks auth.isExpired()
                         ──► if expiring within 60s: sends token_expiring
                         ──► if expired: sends auth_expired + closes stream
                         ──► client must reconnect with refreshed token

  ── Token Proxy / BFF (optional) ────────────────────────────────────

  Agent ──► BFF/Proxy ──► MCP Server
             │
             └── holds refresh token
             └── transparently re-issues access tokens
             └── agent never manages token lifecycle directly
             └── recommended for all AI agent deployments
```

---

## Keycloak Configuration

### Realm Settings

```
Realm Name:         mcp-realm
SSL Required:       external (minimum) / all (recommended prod)
Token Lifespan:     Access  = 300s   (5 min)
                    Refresh = 1800s  (30 min)
SSO Session:        1800s
Revocation Policy:  Enabled (lifespan-based + admin revoke)
Organizations:      Enabled (KC 24+ — use instead of realm-per-tenant)
```

### Client: `mcp-server`

```
Client ID:          mcp-server
Access Type:        confidential
Standard Flow:      disabled
Direct Access:      disabled
Service Accounts:   enabled  (M2M / service-to-service)
Bearer Only:        true     (server never initiates login)
```

### Client: `mcp-client`

```
Client ID:          mcp-client
Access Type:        public
Standard Flow:      enabled
PKCE:               S256 (required — reject plain)
Redirect URIs:      http://localhost:3000/callback   (dev)
                    https://your-app.com/callback    (prod)
Web Origins:        + (inherits from redirect URIs)
Direct Access:      disabled
```

### Realm Roles (coarse-grained)

```
mcp:admin       Full tool access + admin tools
mcp:user        Standard tool access
mcp:readonly    Read-only tools only
mcp:service     M2M service account access
                ⚠ must NOT include mcp:admin:config or
                  mcp:tools:execute unless explicitly required
```

### Client Scopes (fine-grained, mapped to MCP tools)

```
mcp:tools:read          Access to read/query tools
mcp:tools:write         Access to mutating tools
mcp:tools:execute       Access to execution/shell tools
mcp:resources:read      Access to resource endpoints
mcp:resources:write     Access to resource mutation
mcp:admin:config        Access to server config tools
```

### Scope-to-Role Mapping

```
mcp:readonly  →  mcp:tools:read
                 mcp:resources:read

mcp:user      →  mcp:tools:read
                 mcp:tools:write
                 mcp:tools:execute
                 mcp:resources:read
                 mcp:resources:write

mcp:admin     →  all scopes including mcp:admin:config

mcp:service   →  mcp:tools:read
                 mcp:tools:execute
                 (configurable — default to least privilege)
```

---

## MCP Server Implementation

### Directory Structure

```text
mcp-keycloak/
├── src/
│   ├── auth/
│   │   ├── types.ts          # Auth context types, Scopes/Roles constants,
│   │   │                     # PermissionDeniedError
│   │   ├── jwks.ts           # JWKS client, token validation,
│   │   │                     # azp check, KC connectivity preflight
│   │   ├── middleware.ts     # Express auth middleware, per-user rate
│   │   │                     # limiting, SSE auth guard
│   │   └── permissions.ts    # assertPermissions / hasPermissions
│   ├── audit/
│   │   └── logger.ts         # Structured audit log (pino), sanitizeArgs
│   ├── tools/
│   │   ├── registry.ts       # registerTool — wraps handlers with auth,
│   │   │                     # permissions, audit, error handling
│   │   └── handlers/         # Individual tool implementations
│   ├── well-known/
│   │   └── oauth-resource.ts # /.well-known/oauth-protected-resource
│   ├── proxy/
│   │   └── token-proxy.ts    # Optional BFF token proxy
│   ├── config.ts             # Zod-validated env config + derived URLs
│   └── server.ts             # Entry point, startup preflight
├── keycloak/
│   └── realm-export.json     # Importable realm config
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── .env.example
├── tsconfig.json
├── package.json
└── README.md
```

### Environment Variables

```bash
# ── Keycloak ──────────────────────────────────────────────────────────────────
KC_BASE_URL=https://keycloak.internal
KC_REALM=mcp-realm
KC_CLIENT_ID=mcp-server
KC_CLIENT_SECRET=your-client-secret

# Comma-separated OAuth client IDs trusted to present tokens
# to this resource server (enforced via azp claim)
KC_ALLOWED_CLIENT_IDS=mcp-client,mcp-service-account

# ── Derived (constructed in config.ts — do not set manually) ──────────────────
# KC_ISSUER   = KC_BASE_URL/realms/KC_REALM
# KC_JWKS_URI = KC_ISSUER/protocol/openid-connect/certs
# KC_AUTH_URI = KC_ISSUER/protocol/openid-connect/auth
# KC_TOKEN_URI= KC_ISSUER/protocol/openid-connect/token

# ── Server ────────────────────────────────────────────────────────────────────
PORT=3000
NODE_ENV=production
LOG_LEVEL=info

# ── Rate limiting ─────────────────────────────────────────────────────────────
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX_PER_USER=100

# ── Token proxy / BFF (optional) ─────────────────────────────────────────────
TOKEN_PROXY_ENABLED=false
TOKEN_PROXY_CLIENT_ID=mcp-client
TOKEN_PROXY_CLIENT_SECRET=
```

### `src/config.ts`

```typescript
import { z } from "zod";

const schema = z.object({
  KC_BASE_URL: z.string().url(),
  KC_REALM: z.string().min(1),
  KC_CLIENT_ID: z.string().min(1),
  KC_CLIENT_SECRET: z.string().min(1),
  KC_ALLOWED_CLIENT_IDS: z
    .string()
    .transform((v) =>
      v.split(",").map((s) => s.trim()).filter(Boolean)
    ),

  PORT: z.coerce.number().int().positive().default(3000),
  NODE_ENV: z
    .enum(["development", "production", "test"])
    .default("production"),
  LOG_LEVEL: z
    .enum(["fatal", "error", "warn", "info", "debug", "trace"])
    .default("info"),

  RATE_LIMIT_WINDOW_MS: z.coerce
    .number().int().positive().default(60_000),
  RATE_LIMIT_MAX_PER_USER: z.coerce
    .number().int().positive().default(100),

  TOKEN_PROXY_ENABLED: z
    .string()
    .transform((v) => v === "true")
    .default("false"),
  TOKEN_PROXY_CLIENT_ID: z.string().optional(),
  TOKEN_PROXY_CLIENT_SECRET: z.string().optional(),
});

function loadConfig() {
  const result = schema.safeParse(process.env);
  if (!result.success) {
    console.error("❌ Invalid environment configuration:");
    for (const issue of result.error.issues) {
      console.error(`   ${issue.path.join(".")}: ${issue.message}`);
    }
    process.exit(1);
  }
  return result.data;
}

export const config = loadConfig();

// Single source of truth for all Keycloak URLs
export const KC_ISSUER =
  `${config.KC_BASE_URL}/realms/${config.KC_REALM}` as const;
export const KC_JWKS_URI =
  `${KC_ISSUER}/protocol/openid-connect/certs` as const;
export const KC_AUTH_URI =
  `${KC_ISSUER}/protocol/openid-connect/auth` as const;
export const KC_TOKEN_URI =
  `${KC_ISSUER}/protocol/openid-connect/token` as const;
export const KC_DISCOVERY_URI =
  `${KC_ISSUER}/.well-known/openid-configuration` as const;
```

### `src/auth/types.ts`

```typescript
/**
 * Raw Keycloak JWT claims as decoded from the access token.
 */
export interface KeycloakTokenClaims {
  // Standard JWT (RFC 7519)
  sub: string;
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
  jti: string;
  nbf?: number;

  // OIDC
  preferred_username: string;
  email?: string;
  email_verified?: boolean;
  name?: string;

  // OAuth
  azp?: string;           // authorized party — the client that got the token
  scope: string;
  session_state?: string;

  // Keycloak role claims
  realm_access?: { roles: string[] };
  resource_access?: Record<string, { roles: string[] }>;
}

/**
 * Normalized, verified auth context attached to every authenticated request
 * and passed into every tool handler.
 */
export interface McpAuthContext {
  userId: string;         // sub
  username: string;       // preferred_username
  email?: string;
  clientId: string;       // azp — which OAuth client obtained this token
  realmRoles: string[];
  clientRoles: string[];  // roles on KC_CLIENT_ID resource
  scopes: string[];
  tokenId: string;        // jti — for audit correlation with Keycloak logs
  expiresAt: number;      // exp — Unix timestamp

  /** True if the token has passed its exp claim. */
  isExpired(): boolean;

  /**
   * True if the token expires within the given number of seconds.
   * Use in SSE streams to send proactive token_expiring notifications.
   */
  expiresWithin(thresholdSeconds: number): boolean;

  /** Raw decoded claims — available for custom claim extraction. */
  rawClaims: KeycloakTokenClaims;
}

/** Scope constants — single source of truth. */
export const Scopes = {
  TOOLS_READ:      "mcp:tools:read",
  TOOLS_WRITE:     "mcp:tools:write",
  TOOLS_EXECUTE:   "mcp:tools:execute",
  RESOURCES_READ:  "mcp:resources:read",
  RESOURCES_WRITE: "mcp:resources:write",
  ADMIN_CONFIG:    "mcp:admin:config",
} as const;

export type Scope = (typeof Scopes)[keyof typeof Scopes];

/** Realm role constants. */
export const RealmRoles = {
  ADMIN:    "mcp:admin",
  USER:     "mcp:user",
  READONLY: "mcp:readonly",
  SERVICE:  "mcp:service",
} as const;

export type RealmRole = (typeof RealmRoles)[keyof typeof RealmRoles];

/** Structured permission denial — thrown by assertPermissions. */
export type DenialReason =
  | "missing_scope"
  | "missing_role"
  | "token_expired"
  | "untrusted_client";

export class PermissionDeniedError extends Error {
  constructor(
    public readonly reason: DenialReason,
    public readonly detail: string
  ) {
    super(`Permission denied: ${reason} — ${detail}`);
    this.name = "PermissionDeniedError";
  }
}
```

### `src/auth/jwks.ts`

```typescript
import jwksRsa, { type SigningKey } from "jwks-rsa";
import jwt from "jsonwebtoken";
import { KC_JWKS_URI, KC_ISSUER, KC_DISCOVERY_URI, config } from
  "../config.js";
import type { KeycloakTokenClaims, McpAuthContext } from "./types.js";
import { PermissionDeniedError } from "./types.js";
import { logger } from "../audit/logger.js";

// ── JWKS key-set poisoning detection ─────────────────────────────────────────

/**
 * Tracks key IDs seen in the last successful JWKS fetch.
 * A response that removes ALL previously known keys is suspicious —
 * log a warning so ops can distinguish genuine emergency rotation
 * from a poisoned response.
 */
let _knownKeyIds = new Set<string>();

// ── JWKS client ───────────────────────────────────────────────────────────────

const jwksClient = jwksRsa({
  jwksUri: KC_JWKS_URI,
  cache: true,
  cacheMaxEntries: 10,
  cacheMaxAge: 600_000,       // 10 min
  rateLimit: true,
  jwksRequestsPerMinute: 10,
  fetcher: async (jwksUri) => {
    const res = await fetch(jwksUri);
    if (!res.ok) {
      throw new Error(
        `JWKS fetch failed: ${res.status} ${res.statusText}`
      );
    }

    const body = (await res.json()) as {
      keys: Array<{ kid?: string; alg?: string }>;
    };

    const freshIds = new Set(
      body.keys
        .map((k) => k.kid)
        .filter((id): id is string => !!id)
    );

    if (_knownKeyIds.size > 0) {
      const overlap = [...freshIds].filter((id) => _knownKeyIds.has(id));
      if (overlap.length === 0) {
        logger.warn(
          {
            previousKeyIds: [..._knownKeyIds],
            freshKeyIds: [...freshIds],
          },
          "JWKS key set fully replaced — verify this is an intentional " +
          "rotation and not a poisoned response"
        );
      }
    }

    _knownKeyIds = freshIds;
    return body;
  },
});

// ── Signing key retrieval ─────────────────────────────────────────────────────

function getSigningKey(kid: string | undefined): Promise<string> {
  return new Promise((resolve, reject) => {
    jwksClient.getSigningKey(kid, (err, key?: SigningKey) => {
      if (err) return reject(err);
      if (!key) return reject(new Error("Signing key not found"));

      // Enforce expected algorithm at the key level
      const alg = (key as { alg?: string }).alg;
      if (alg && alg !== "RS256") {
        return reject(
          new Error(`Unexpected key algorithm: ${alg} (expected RS256)`)
        );
      }

      resolve(key.getPublicKey());
    });
  });
}

// ── Token validation ──────────────────────────────────────────────────────────

/**
 * Validates a raw Bearer token and returns a normalized McpAuthContext.
 *
 * Enforces:
 *  - RS256 signature via JWKS
 *  - Issuer matches configured KC_ISSUER
 *  - Audience contains KC_CLIENT_ID
 *  - azp is in KC_ALLOWED_CLIENT_IDS
 *  - ±30s clock skew tolerance
 */
export async function validateToken(
  token: string
): Promise<McpAuthContext> {
  const header = jwt.decode(token, { complete: true })?.header;
  const publicKey = await getSigningKey(header?.kid);

  const claims = await new Promise<KeycloakTokenClaims>(
    (resolve, reject) => {
      jwt.verify(
        token,
        publicKey,
        {
          algorithms: ["RS256"],
          issuer: KC_ISSUER,
          audience: config.KC_CLIENT_ID,
          clockTolerance: 30,
        },
        (err, decoded) => {
          if (err) reject(err);
          else resolve(decoded as KeycloakTokenClaims);
        }
      );
    }
  );

  // ── azp validation ────────────────────────────────────────────────────────
  // Prevents tokens issued to other clients in the same realm from being
  // accepted by this resource server.
  if (
    claims.azp &&
    !config.KC_ALLOWED_CLIENT_IDS.includes(claims.azp)
  ) {
    throw new PermissionDeniedError(
      "untrusted_client",
      `Client '${claims.azp}' is not in KC_ALLOWED_CLIENT_IDS`
    );
  }

  const expiresAt = claims.exp;

  return {
    userId:      claims.sub,
    username:    claims.preferred_username,
    email:       claims.email,
    clientId:    claims.azp ?? config.KC_CLIENT_ID,
    realmRoles:  claims.realm_access?.roles ?? [],
    clientRoles:
      claims.resource_access?.[config.KC_CLIENT_ID]?.roles ?? [],
    scopes:      claims.scope.split(" ").filter(Boolean),
    tokenId:     claims.jti,
    expiresAt,
    isExpired: () =>
      Math.floor(Date.now() / 1000) > expiresAt,
    expiresWithin: (thresholdSeconds: number) =>
      Math.floor(Date.now() / 1000) > expiresAt - thresholdSeconds,
    rawClaims: claims,
  };
}

// ── Startup preflight ─────────────────────────────────────────────────────────

/**
 * Validates Keycloak is reachable and the OIDC discovery document
 * matches our configured issuer and JWKS URI.
 * Called once at server startup — fail fast before accepting traffic.
 */
export async function validateKeycloakConnectivity(): Promise<void> {
  logger.info(
    { uri: KC_DISCOVERY_URI },
    "Validating Keycloak connectivity"
  );

  let discovery: { issuer?: string; jwks_uri?: string };

  try {
    const res = await fetch(KC_DISCOVERY_URI);
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    discovery = (await res.json()) as typeof discovery;
  } catch (err) {
    throw new Error(
      `Keycloak unreachable at startup (${KC_DISCOVERY_URI}): ${String(err)}`
    );
  }

  if (discovery.issuer !== KC_ISSUER) {
    throw new Error(
      `Issuer mismatch — expected: ${KC_ISSUER}, ` +
      `got: ${discovery.issuer}`
    );
  }

  if (discovery.jwks_uri !== KC_JWKS_URI) {
    logger.warn(
      { expected: KC_JWKS_URI, actual: discovery.jwks_uri },
      "JWKS URI in discovery document differs from configured value"
    );
  }

  logger.info("Keycloak connectivity verified ✓");
}
```

### `src/auth/middleware.ts`

```typescript
import type { Request, Response, NextFunction } from "express";
import { validateToken } from "./jwks.js";
import type { McpAuthContext } from "./types.js";
import { PermissionDeniedError, Scopes } from "./types.js";
import { KC_AUTH_URI, KC_TOKEN_URI, config } from "../config.js";
import { auditLog } from "../audit/logger.js";
import { v4 as uuidv4 } from "uuid";

// ── Express type augmentation ─────────────────────────────────────────────────

declare global {
  namespace Express {
    interface Request {
      auth?: McpAuthContext;
      requestId?: string;
    }
  }
}

// ── Per-user rate limiting (in-memory token bucket) ───────────────────────────
// For multi-instance deployments, replace with a Redis-backed implementation.

interface RateBucket {
  tokens: number;
  lastRefill: number;
}

const _rateBuckets = new Map<string, RateBucket>();

function checkRateLimit(userId: string): boolean {
  const now = Date.now();
  const { RATE_LIMIT_WINDOW_MS: windowMs,
          RATE_LIMIT_MAX_PER_USER: maxTokens } = config;

  let bucket = _rateBuckets.get(userId);
  if (!bucket) {
    bucket = { tokens: maxTokens, lastRefill: now };
    _rateBuckets.set(userId, bucket);
  }

  const elapsed = now - bucket.lastRefill;
  const refill = Math.floor((elapsed / windowMs) * maxTokens);
  if (refill > 0) {
    bucket.tokens = Math.min(maxTokens, bucket.tokens + refill);
    bucket.lastRefill = now;
  }

  if (bucket.tokens <= 0) return false;
  bucket.tokens--;
  return true;
}

// Prune stale buckets every 5 min to prevent unbounded memory growth
setInterval(() => {
  const cutoff = Date.now() - config.RATE_LIMIT_WINDOW_MS * 2;
  for (const [id, bucket] of _rateBuckets) {
    if (bucket.lastRefill < cutoff) _rateBuckets.delete(id);
  }
}, 5 * 60 * 1000).unref();

// ── WWW-Authenticate builder ──────────────────────────────────────────────────

function buildWwwAuthenticate(): string {
  const scopeList = Object.values(Scopes).join(" ");
  return [
    `Bearer realm="${config.KC_REALM}"`,
    `authorization_uri="${KC_AUTH_URI}"`,
    `token_uri="${KC_TOKEN_URI}"`,
    `resource="${config.KC_CLIENT_ID}"`,
    `scope="openid ${scopeList}"`,
  ].join(", ");
}

// ── Auth middleware ───────────────────────────────────────────────────────────

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  req.requestId = uuidv4();

  const authHeader = req.headers["authorization"];

  if (!authHeader?.startsWith("Bearer ")) {
    res.set("WWW-Authenticate", buildWwwAuthenticate());

    auditLog({
      eventType: "auth_failure",
      requestId: req.requestId,
      sourceIp: req.ip ?? "unknown",
      errorReason: "missing_token",
      success: false,
    });

    res.status(401).json({
      error: "missing_token",
      error_description:
        "A Bearer token is required. See WWW-Authenticate header.",
    });
    return;
  }

  try {
    const token = authHeader.slice(7);
    const auth = await validateToken(token);

    // Belt-and-suspenders expiry check on top of jwt.verify
    if (auth.isExpired()) {
      res.status(401).json({
        error: "token_expired",
        error_description:
          "The access token has expired. Please refresh.",
      });
      return;
    }

    // Per-user rate limit
    if (!checkRateLimit(auth.userId)) {
      auditLog({
        eventType: "auth_failure",
        requestId:  req.requestId,
        userId:     auth.userId,
        username:   auth.username,
        sourceIp:   req.ip ?? "unknown",
        errorReason: "rate_limited",
        success: false,
      });

      res.status(429).json({
        error: "rate_limited",
        error_description: "Too many requests — please slow down.",
      });
      return;
    }

    req.auth = auth;
    next();
  } catch (err) {
    const isPermErr = err instanceof PermissionDeniedError;

    auditLog({
      eventType:   "auth_failure",
      requestId:   req.requestId,
      sourceIp:    req.ip ?? "unknown",
      errorReason: isPermErr ? err.reason : "invalid_token",
      success:     false,
    });

    res.status(401).json({
      error: isPermErr ? err.reason : "invalid_token",
      error_description:
        err instanceof Error ? err.message : "Token validation failed",
    });
  }
}

// ── SSE auth guard ────────────────────────────────────────────────────────────

/**
 * Starts a periodic auth check on an active SSE stream.
 *
 * - Every `checkIntervalMs` (default 30s): checks token state
 * - If expiring within 60s: sends token_expiring notification
 * - If expired: sends auth_expired + closes the stream
 *
 * Returns the interval handle — clear it when the stream closes.
 */
export function startSseAuthGuard(
  res: Response,
  auth: McpAuthContext,
  requestId: string,
  checkIntervalMs = 30_000
): NodeJS.Timeout {
  const interval = setInterval(() => {
    if (auth.isExpired()) {
      auditLog({
        eventType:   "auth_failure",
        requestId,
        userId:      auth.userId,
        username:    auth.username,
        sourceIp:    "sse-stream",
        errorReason: "token_expired_mid_stream",
        success:     false,
      });

      res.write(
        `data: ${JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/auth",
          params: {
            type: "auth_expired",
            message:
              "Access token expired. Reconnect with a refreshed token.",
          },
        })}\n\n`
      );
      res.end();
      clearInterval(interval);
      return;
    }

    if (auth.expiresWithin(60)) {
      res.write(
        `data: ${JSON.stringify({
          jsonrpc: "2.0",
          method: "notifications/auth",
          params: {
            type: "token_expiring",
            expiresIn:
              auth.expiresAt - Math.floor(Date.now() / 1000),
          },
        })}\n\n`
      );
    }
  }, checkIntervalMs);

  interval.unref();
  return interval;
}
```

### `src/auth/permissions.ts`

```typescript
import type { McpAuthContext } from "./types.js";
import { PermissionDeniedError } from "./types.js";

export interface PermissionRequirement {
  /** ALL of these scopes must be present on the token. */
  scopes?: string[];
  /**
   * AT LEAST ONE of these roles must be present.
   * Checked across both realmRoles and clientRoles.
   */
  roles?: string[];
}

/**
 * Asserts that the auth context satisfies the given requirement.
 * Throws PermissionDeniedError with a structured reason on failure.
 * Use this inside tool handlers for enforcement.
 */
export function assertPermissions(
  auth: McpAuthContext,
  requirement: PermissionRequirement
): void {
  const { scopes = [], roles = [] } = requirement;

  const missingScopes = scopes.filter(
    (s) => !auth.scopes.includes(s)
  );
  if (missingScopes.length > 0) {
    throw new PermissionDeniedError(
      "missing_scope",
      `Required scopes not present: ${missingScopes.join(", ")}`
    );
  }

  if (roles.length > 0) {
    const allRoles = new Set([...auth.realmRoles, ...auth.clientRoles]);
    const hasRole = roles.some((r) => allRoles.has(r));
    if (!hasRole) {
      throw new PermissionDeniedError(
        "missing_role",
        `Requires one of: [${roles.join(", ")}]`
      );
    }
  }
}

/**
 * Non-throwing variant — returns true if the requirement is satisfied.
 * Use for conditional UI/feature gating rather than enforcement.
 */
export function hasPermissions(
  auth: McpAuthContext,
  requirement: PermissionRequirement
): boolean {
  try {
    assertPermissions(auth, requirement);
    return true;
  } catch {
    return false;
  }
}
```

### `src/audit/logger.ts`

```typescript
import pino from "pino";
import { config } from "../config.js";

// ── Base logger ───────────────────────────────────────────────────────────────

export const logger = pino({
  level: config.LOG_LEVEL,
  transport:
    config.NODE_ENV === "development"
      ? { target: "pino-pretty", options: { colorize: true } }
      : undefined,
  base: { service: "mcp-keycloak", env: config.NODE_ENV },
  timestamp: pino.stdTimeFunctions.isoTime,
});

// ── Audit event schema ────────────────────────────────────────────────────────

export type AuditEventType =
  | "tool_call"
  | "auth_failure"
  | "permission_denied"
  | "token_validated"
  | "stream_open"
  | "stream_close";

export interface AuditEvent {
  // Always present
  eventType:  AuditEventType;
  requestId:  string;
  sourceIp:   string;
  success:    boolean;

  // Present when auth context is available
  userId?:    string;         // sub
  username?:  string;
  clientId?:  string;         // azp
  tokenId?:   string;         // jti — correlate with Keycloak logs
  realm?:     string;

  // Tool calls
  toolName?:   string;
  toolArgs?:   Record<string, string>; // sanitized — key names + types only
  durationMs?: number;
  scopes?:     string[];
  realmRoles?: string[];

  // Errors
  errorReason?:  string;
  errorMessage?: string;

  // SSE
  mcpSessionId?: string;
}

/**
 * Emits a structured audit log entry via pino.
 * All tool calls, auth events, and permission denials must flow through here.
 */
export function auditLog(event: AuditEvent): void {
  const level = event.success ? "info" : "warn";
  logger[level](
    { audit: true, ...event },
    `audit:${event.eventType}`
  );
}

/**
 * Sanitizes tool args for audit logging.
 * Records key names and value types — never actual values.
 * Prevents PII / secrets from appearing in logs.
 *
 * Example:
 *   { query: "SELECT ...", limit: 100 }
 *   → { query: "string", limit: "number" }
 */
export function sanitizeArgs(
  args: unknown
): Record<string, string> {
  if (typeof args !== "object" || args === null) {
    return { _type: typeof args };
  }
  return Object.fromEntries(
    Object.entries(args as Record<string, unknown>).map(
      ([k, v]) => [
        k,
        Array.isArray(v) ? `array[${(v as unknown[]).length}]` : typeof v,
      ]
    )
  );
}
```

### `src/tools/registry.ts`

```typescript
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ZodRawShape } from "zod";
import type { McpAuthContext } from "../auth/types.js";
import { PermissionDeniedError } from "../auth/types.js";
import type { PermissionRequirement } from "../auth/permissions.js";
import { assertPermissions } from "../auth/permissions.js";
import { auditLog, sanitizeArgs } from "../audit/logger.js";

// ── Tool definition ───────────────────────────────────────────────────────────

export interface ToolDefinition<TArgs = unknown> {
  name:        string;
  description: string;
  inputSchema: ZodRawShape;
  permissions: PermissionRequirement;
  handler: (
    args: TArgs,
    auth: McpAuthContext
  ) => Promise<unknown>;
}

// ── Context extraction helpers ────────────────────────────────────────────────

/**
 * Safely extracts McpAuthContext from the MCP SDK's extra/requestContext.
 * Throws a clear, actionable error if auth middleware is misconfigured.
 */
function extractAuth(extra: unknown): McpAuthContext {
  const auth = (
    extra as { requestContext?: { auth?: McpAuthContext } } | undefined
  )?.requestContext?.auth;

  if (!auth) {
    throw new Error(
      "Auth context missing — ensure authMiddleware is applied " +
      "before MCP routes"
    );
  }
  return auth;
}

function extractRequestId(extra: unknown): string {
  return (
    (extra as { requestContext?: { requestId?: string } })
      ?.requestContext?.requestId ?? "unknown"
  );
}

function extractSourceIp(extra: unknown): string {
  return (
    (extra as { requestContext?: { sourceIp?: string } })
      ?.requestContext?.sourceIp ?? "unknown"
  );
}

// ── Tool registration ─────────────────────────────────────────────────────────

/**
 * Registers a tool with the MCP server.
 *
 * Every registered tool automatically gets:
 *  - Auth context extraction (fails loudly on misconfiguration)
 *  - Token expiry check before execution
 *  - Permission enforcement (scopes + roles)
 *  - Structured audit logging (call start, result, duration)
 *  - Sanitized arg logging (types only — no values)
 *  - Structured error responses (never throws through MCP boundary)
 */
export function registerTool<TArgs>(
  server: McpServer,
  tool: ToolDefinition<TArgs>
): void {
  server.tool(
    tool.name,
    tool.description,
    tool.inputSchema,
    async (args, extra) => {
      const auth      = extractAuth(extra);
      const requestId = extractRequestId(extra);
      const sourceIp  = extractSourceIp(extra);
      const startMs   = Date.now();

      const baseAudit = {
        requestId,
        sourceIp,
        userId:    auth.userId,
        username:  auth.username,
        clientId:  auth.clientId,
        tokenId:   auth.tokenId,
        toolName:  tool.name,
        scopes:    auth.scopes,
        realmRoles: auth.realmRoles,
        toolArgs:  sanitizeArgs(args),
      };

      // ── Token expiry (mid-stream guard) ─────────────────────────────────
      if (auth.isExpired()) {
        auditLog({
          ...baseAudit,
          eventType:   "auth_failure",
          errorReason: "token_expired",
          success:     false,
        });
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              error: "token_expired",
              message:
                "Access token expired. Reconnect with a refreshed token.",
            }),
          }],
          isError: true,
        };
      }

      // ── Permission check ─────────────────────────────────────────────────
      try {
        assertPermissions(auth, tool.permissions);
      } catch (err) {
        if (err instanceof PermissionDeniedError) {
          auditLog({
            ...baseAudit,
            eventType:    "permission_denied",
            errorReason:  err.reason,
            errorMessage: err.message,
            success:      false,
          });
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                error:   err.reason,
                message: err.message,
              }),
            }],
            isError: true,
          };
        }
        throw err;
      }

      // ── Handler execution ────────────────────────────────────────────────
      try {
        const result = await tool.handler(args as TArgs, auth);
        const durationMs = Date.now() - startMs;

        auditLog({
          ...baseAudit,
          eventType:  "tool_call",
          durationMs,
          success:    true,
        });

        return {
          content: [{
            type: "text",
            text: JSON.stringify(result),
          }],
        };
      } catch (err) {
        const durationMs = Date.now() - startMs;

        auditLog({
          ...baseAudit,
          eventType:    "tool_call",
          durationMs,
          errorMessage: err instanceof Error ? err.message : String(err),
          success:      false,
        });

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              error:   "tool_error",
              message: err instanceof Error ? err.message : "Unknown error",
            }),
          }],
          isError: true,
        };
      }
    }
  );
}
```

### `src/well-known/oauth-resource.ts`

```typescript
import type { Router } from "express";
import { Router as createRouter } from "express";
import {
  KC_AUTH_URI,
  KC_TOKEN_URI,
  KC_JWKS_URI,
  KC_ISSUER,
  config,
} from "../config.js";
import { Scopes } from "../auth/types.js";

/**
 * Serves /.well-known/oauth-protected-resource
 *
 * Allows OAuth-aware MCP clients to discover auth requirements
 * without hitting a protected endpoint first.
 *
 * Spec: https://www.ietf.org/archive/id/draft-ietf-oauth-resource-metadata-05.txt
 */
export function oauthResourceRouter(): Router {
  const router = createRouter();

  router.get(
    "/.well-known/oauth-protected-resource",
    (_req, res) => {
      res.json({
        resource:                    config.KC_CLIENT_ID,
        authorization_servers:       [KC_ISSUER],
        jwks_uri:                    KC_JWKS_URI,
        scopes_supported:            Object.values(Scopes),
        bearer_methods_supported:    ["header"],
        resource_signing_alg_values: ["RS256"],
        authorization_uri:           KC_AUTH_URI,
        token_uri:                   KC_TOKEN_URI,
      });
    }
  );

  return router;
}
```

### `src/server.ts`

```typescript
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { SSEServerTransport } from
  "@modelcontextprotocol/sdk/server/sse.js";
import { config } from "./config.js";
import { logger } from "./audit/logger.js";
import { validateKeycloakConnectivity } from "./auth/jwks.js";
import { authMiddleware, startSseAuthGuard } from
  "./auth/middleware.js";
import { oauthResourceRouter } from "./well-known/oauth-resource.js";
import { registerTool } from "./tools/registry.js";
import { Scopes, RealmRoles } from "./auth/types.js";
import { v4 as uuidv4 } from "uuid";

// ── MCP server instance ───────────────────────────────────────────────────────

const mcp = new McpServer({
  name: "mcp-keycloak",
  version: "1.0.0",
});

// ── Tool registration ─────────────────────────────────────────────────────────

registerTool(mcp, {
  name: "example_read",
  description: "Example read-only tool",
  inputSchema: {},
  permissions: {
    scopes: [Scopes.TOOLS_READ],
  },
  handler: async (_args, auth) => ({
    message: `Hello, ${auth.username}`,
    userId:  auth.userId,
  }),
});

registerTool(mcp, {
  name: "example_write",
  description: "Example mutating tool",
  inputSchema: {},
  permissions: {
    scopes: [Scopes.TOOLS_READ, Scopes.TOOLS_WRITE],
    roles:  [RealmRoles.USER, RealmRoles.ADMIN],
  },
  handler: async (_args, auth) => ({
    written: true,
    by:      auth.username,
  }),
});

registerTool(mcp, {
  name: "admin_config",
  description: "Server configuration tool — admin only",
  inputSchema: {},
  permissions: {
    scopes: [Scopes.ADMIN_CONFIG],
    roles:  [RealmRoles.ADMIN],
  },
  handler: async (_args, auth) => ({
    config: "...",
    accessedBy: auth.username,
  }),
});

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();
app.use(express.json());
app.disable("x-powered-by");

// /.well-known/oauth-protected-resource (unauthenticated)
app.use(oauthResourceRouter());

// All MCP routes require auth
app.use("/mcp", authMiddleware);

// SSE transport
app.get("/mcp/sse", async (req, res) => {
  const sessionId = uuidv4();
  const auth = req.auth!;

  logger.info(
    { sessionId, userId: auth.userId, clientId: auth.clientId },
    "SSE stream opened"
  );

  const guard = startSseAuthGuard(
    res,
    auth,
    req.requestId ?? sessionId
  );

  const transport = new SSEServerTransport("/mcp/messages", res);
  await mcp.connect(transport);

  res.on("close", () => {
    clearInterval(guard);
    logger.info({ sessionId }, "SSE stream closed");
  });
});

// Message endpoint
app.post("/mcp/messages", async (req, res) => {
  // requestContext carries auth + requestId into tool handlers
  await (mcp as unknown as {
    handleMessage: (
      body: unknown,
      res: express.Response,
      ctx: unknown
    ) => Promise<void>;
  }).handleMessage(req.body, res, {
    auth:      req.auth,
    requestId: req.requestId,
    sourceIp:  req.ip,
  });
});

// Health (unauthenticated)
app.get("/health", (_req, res) => {
  res.json({ status: "ok", service: "mcp-keycloak" });
});

// ── Startup ───────────────────────────────────────────────────────────────────

async function start() {
  logger.info("Starting mcp-keycloak server");

  // Validate env config (already done in config.ts — this is belt-and-
  // suspenders at the point where we actually need connectivity)
  await validateKeycloakConnectivity();

  app.listen(config.PORT, () => {
    logger.info(
      { port: config.PORT, env: config.NODE_ENV },
      `MCP server listening on :${config.PORT}`
    );
    logger.info(
      `Discovery: http://localhost:${config.PORT}` +
      `/.well-known/oauth-protected-resource`
    );
  });
}

start().catch((err) => {
  logger.fatal({ err }, "Server failed to start");
  process.exit(1);
});
```

---

## Security Controls

| Control                    | Implementation                                                   |
| -------------------------- | ---------------------------------------------------------------- |
| Token signature            | RS256 via JWKS (cached 10 min, rate-limited 10 req/min)         |
| Token expiry               | `exp` enforced by `jwt.verify` + belt-and-suspenders check      |
| Audience validation        | `aud` must contain `KC_CLIENT_ID`                               |
| Authorized party (azp)     | `azp` checked against `KC_ALLOWED_CLIENT_IDS` allowlist         |
| Clock skew                 | ±30s `clockTolerance` in `jwt.verify`                           |
| PKCE enforcement           | Required on `mcp-client` (S256, plain rejected)                 |
| Scope enforcement          | Per-tool `requiredScopes` — ALL must be present                 |
| Role enforcement           | Per-tool `requiredRoles` — at least ONE must be present         |
| Transport security         | TLS required (`ssl-required: all` in KC)                        |
| Token revocation           | Short AT TTL (5 min) + KC admin API revoke                      |
| Replay protection          | `jti` logged on every audit event for correlation               |
| JWKS key-set poisoning     | Logged warning on full key-set replacement                      |
| Key algorithm pinning      | RS256 asserted at signing key level                             |
| Per-user rate limiting     | In-memory token bucket (swap Redis for multi-instance)          |
| SSE token expiry           | Periodic guard — `token_expiring` warn + `auth_expired` close   |
| Arg sanitization           | Types only logged — values never reach audit log                |
| Secret management          | Client secret in env / external vault only                      |
| Startup preflight          | Keycloak connectivity + issuer verified before accepting traffic |
| `/.well-known` discovery   | `oauth-protected-resource` document served for client discovery |
| M2M isolation              | `mcp:service` role excludes `execute` + `admin` by default      |

---

## Audit Log Schema

```typescript
interface AuditEvent {
  // Always present
  eventType:  "tool_call" | "auth_failure" | "permission_denied"
            | "token_validated" | "stream_open" | "stream_close";
  requestId:  string;   // UUID — trace across logs
  sourceIp:   string;
  success:    boolean;

  // Present when auth is available
  userId?:    string;   // sub
  username?:  string;
  clientId?:  string;   // azp — which OAuth client made the call
  tokenId?:   string;   // jti — correlate with Keycloak's own logs
  realm?:     string;

  // Tool calls
  toolName?:   string;
  toolArgs?:   Record<string, string>; // sanitized: key names + types only
  durationMs?: number;
  scopes?:     string[];
  realmRoles?: string[];

  // Errors
  errorReason?:  string;
  errorMessage?: string;

  // SSE streams
  mcpSessionId?: string;
}
```

---

## Open Questions

| # | Question | Recommendation |
|---|----------|----------------|
| 1 | **Token revocation** — short TTL only, or Redis `jti` blocklist? | Short TTL (5 min) + KC admin revoke is sufficient for most deployments. Add Redis `jti` blocklist only if you have a hard SLA of <5 min revocation (e.g. terminated employee). Make it an optional deployment profile. |
| 2 | **M2M** — client credentials flow for service accounts? | Yes. Isolate via `mcp:service` realm role. Explicitly exclude `mcp:tools:execute` and `mcp:admin:config` from that role by default. Service accounts hitting execution tools is high blast-radius. |
| 3 | **Multi-tenancy** — one realm per tenant, or roles + groups? | Use **KC Organizations** (KC 24+). Gives tenant isolation within a single realm without the realm-per-tenant ops tax. Fall back to realm-per-tenant only if you need full JWKS isolation between tenants. |
| 4 | **Rate limiting** — per-user token bucket on MCP server? | Yes, at two layers: (1) nginx/gateway by IP, (2) MCP server per `sub` claim. In-memory bucket for single-instance; Redis for multi-instance deployments. |
| 5 | **Refresh token handling** — MCP client or proxy layer? | Proxy/BFF layer always. Agents (Claude Desktop, custom agents) must not manage refresh tokens directly — no reliable secure storage. BFF holds the refresh token, transparently re-issues access tokens, and the agent only ever sees short-lived access tokens. |
| 6 | **`jti` replay tracking** — log-only or active blocklist? | Log `jti` on every audit event for forensic correlation. Active blocklist (Redis `SET jti TTL`) only if your threat model includes token theft within the AT lifespan. |
````
---

##
##
