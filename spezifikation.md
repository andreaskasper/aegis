# Aegis — Technical Specification

**Version:** 1.0 (draft) · **Status:** specification, implementation pending

This document is the build plan. Where it and the README disagree, this
document wins.

---

## Table of contents

1. [Scope and terminology](#1-scope-and-terminology)
2. [Runtime and deployment](#2-runtime-and-deployment)
3. [Configuration](#3-configuration)
4. [Configuration reload](#4-configuration-reload)
5. [OAuth 2.1 authorization server](#5-oauth-21-authorization-server)
6. [Session state](#6-session-state)
7. [MCP transport](#7-mcp-transport)
8. [Tools](#8-tools)
9. [Request pipeline](#9-request-pipeline)
10. [Target matching](#10-target-matching)
11. [Network guard](#11-network-guard)
12. [Rate limiting](#12-rate-limiting)
13. [Secret injection](#13-secret-injection)
14. [Response processing](#14-response-processing)
15. [Audit log](#15-audit-log)
16. [Errors](#16-errors)
17. [CLI](#17-cli)
18. [Source layout](#18-source-layout)
19. [Test requirements](#19-test-requirements)
20. [Open questions](#20-open-questions)

---

## 1. Scope and terminology

| Term | Meaning |
| --- | --- |
| **User** | A principal defined in `config.yaml`. Owns secrets and targets. The unit of authorisation. |
| **Target** | A permitted upstream destination: base URL, allowed methods, allowed paths, injection rules. |
| **Secret** | A named credential belonging to a user. Never leaves the process in readable form. |
| **Client** | An MCP client registered via OAuth DCR. |
| **Session** | An issued access token bound to exactly one user. |

Keywords **MUST**, **SHOULD**, **MAY** follow RFC 2119.

## 2. Runtime and deployment

- **Language:** Go 1.22+
- **Dependencies:** `gopkg.in/yaml.v3`, `golang.org/x/crypto/bcrypt`. Nothing
  else. Any additional dependency requires justification.
- **Binary:** single static binary, `CGO_ENABLED=0`
- **Image:** multi-stage build, final stage `scratch` or `gcr.io/distroless/static`,
  with CA certificates. Runs as a non-root UID.
- **Port:** `2019/tcp`, plain HTTP. TLS is terminated upstream.
- **Filesystem:** read-only. Aegis MUST NOT write to disk at runtime.
- **Signals:** `SIGHUP` → config reload. `SIGTERM`/`SIGINT` → graceful
  shutdown, 10 s drain.
- **Health:** `GET /healthz` → `{"status":"ok"}`, unauthenticated, no rate
  limit.

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `AEGIS_CONFIG` | `/etc/aegis/config.yaml` | Config path |
| `AEGIS_LISTEN` | from config, else `:2019` | Listen address |
| `AEGIS_PUBLIC_URL` | from config | External base URL |
| `AEGIS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

Environment overrides config for `listen` and `public_url`.

## 3. Configuration

### 3.1 Schema

```yaml
server:
  listen: ":2019"                    # optional
  public_url: "https://aegis.example.com"   # REQUIRED (or AEGIS_PUBLIC_URL)
  max_response_bytes: 1048576        # optional, default 1 MiB
  request_timeout: "30s"             # optional, default 30s
  token_ttl: "12h"                   # optional, default 12h
  code_ttl: "60s"                    # optional, default 60s
  login_rate_limit: "10/m"           # optional, default 10/m per IP

users:
  - name: string                     # REQUIRED, unique, [a-zA-Z0-9._-]{1,64}
    password: string                 # REQUIRED, see 3.2
    allow_any: false                 # optional, default false

    secrets:                         # optional map name -> value
      <name>: <value>                # name: [a-zA-Z0-9_]{1,64}

    targets:                         # optional list
      - id: string                   # REQUIRED, unique within the user
        description: string          # REQUIRED, shown to the model
        base_url: string             # REQUIRED, https:// or http://, no query/fragment
        methods: [GET, POST]         # optional, default [GET]
        paths: ["/v1/**"]            # optional, default ["/**"]
        rate_limit: "60/m"           # optional, default unlimited
        timeout: "30s"               # optional, overrides server default
        max_response_bytes: 2097152  # optional, overrides server default
        follow_redirects: false      # optional, default false
        inject:                      # optional
          headers: {Name: "value"}
          query:   {name: "value"}
          body:    {"$.path": "value"}   # JSON body only
```

### 3.2 Value resolution

Every `secrets` value and every `password` is resolved at load time by prefix:

| Prefix | Behaviour |
| --- | --- |
| *(none)* | Literal value. |
| `env:NAME` | `os.Getenv("NAME")`. Empty or unset → config error. |
| `file:/abs/path` | File contents, trailing newline trimmed. Unreadable → config error. |
| `bcrypt:$2…` | **Passwords only.** Stored as a bcrypt hash. |

A literal value beginning with a prefix keyword can be escaped as
`literal:env:not-a-reference`.

Resolved secret values MUST be held in memory only and MUST NOT be written to
any log, error, tool response or HTTP response body.

### 3.3 Password verification

- `bcrypt:` values → `bcrypt.CompareHashAndPassword`.
- Literal values → constant-time comparison (`subtle.ConstantTimeCompare`).
- On an unknown username, Aegis MUST still perform a dummy comparison of
  comparable cost before returning failure, to avoid a user-enumeration timing
  oracle.

### 3.4 Validation

Loading fails, with all errors reported at once, if:

- `public_url` is missing, is not absolute, or has a path other than `/`
- a user name or target id is duplicated, or a name violates its charset
- `base_url` is not absolute, is not `http`/`https`, or contains a query or
  fragment
- a method is not one of `GET POST PUT PATCH DELETE HEAD OPTIONS`
- a path pattern is malformed (see §10.2)
- an injection template references an undefined secret of that user
- an injected header appears in the reserved list (§13.3)
- an `env:` or `file:` reference cannot be resolved
- a duration or rate-limit string cannot be parsed
- `users` is empty

A configuration with zero targets for a user is valid; that user can
authenticate and gets an empty `list_targets`.

### 3.5 Rate-limit syntax

`<count>/<unit>` where unit is `s`, `m` or `h`. Examples: `10/s`, `60/m`,
`1000/h`.

## 4. Configuration reload

- Aegis watches `AEGIS_CONFIG` for changes (polling `mtime` + size at 2 s
  intervals is sufficient and avoids an inotify dependency; it MUST also handle
  atomic replace, i.e. the inode changing).
- `SIGHUP` triggers an immediate reload.
- A reload parses, resolves and validates into a **new** config object. Only on
  full success is the active pointer swapped (`atomic.Pointer`). On failure the
  previous config stays active and one `error`-level line is logged.
- In-flight requests complete against the config they started with.
- **Sessions survive a reload.** A token remains valid as long as its user still
  exists. If the user was removed, the token is invalidated on its next use. If
  the user's password changed, existing tokens remain valid (they were issued
  against a prior successful authentication); a future version MAY add
  `revoke_on_password_change`.
- Target changes take effect on the next request. A removed target is simply no
  longer matched.

## 5. OAuth 2.1 authorization server

All endpoints are derived from `public_url`.

### 5.1 `GET /.well-known/oauth-protected-resource`

```json
{
  "resource": "https://aegis.example.com/mcp",
  "authorization_servers": ["https://aegis.example.com"],
  "bearer_methods_supported": ["header"]
}
```

### 5.2 `GET /.well-known/oauth-authorization-server`

```json
{
  "issuer": "https://aegis.example.com",
  "authorization_endpoint": "https://aegis.example.com/authorize",
  "token_endpoint": "https://aegis.example.com/token",
  "registration_endpoint": "https://aegis.example.com/register",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
  "scopes_supported": ["aegis"]
}
```

Both documents are served unauthenticated with `Cache-Control: max-age=300`.

### 5.3 `POST /register` — Dynamic Client Registration (RFC 7591)

Request:

```json
{
  "client_name": "Claude",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

Response `201`:

```json
{
  "client_id": "<random 128-bit, base64url>",
  "client_id_issued_at": 1785000000,
  "client_name": "Claude",
  "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"],
  "token_endpoint_auth_method": "none"
}
```

Rules:

- Public clients only in v1 (`token_endpoint_auth_method: none`); PKCE is
  therefore mandatory.
- At least one `redirect_uri` is required. Each MUST be an absolute URI, MUST
  be `https` unless the host is `localhost`/`127.0.0.1`, and MUST NOT contain a
  fragment.
- Registration is rate limited (20/h per source IP) and the client table is
  capped (1000 entries, LRU eviction).
- Registrations live in memory and are lost on restart.

### 5.4 `GET /authorize`

Query: `response_type=code`, `client_id`, `redirect_uri`, `state`,
`code_challenge`, `code_challenge_method=S256`, optional `scope`, optional
`resource`.

Validation before rendering anything:

- `client_id` is known → else `400` HTML error page (never a redirect)
- `redirect_uri` exactly matches one registered for that client → else `400`
  HTML error page
- `response_type=code` and `code_challenge_method=S256` → else redirect with
  `error=invalid_request` / `unsupported_response_type`

Renders a self-contained HTML login page: username, password, submit. Inline
CSS, no external assets, no JavaScript required. It carries a hidden
single-use CSRF token bound to the request parameters, valid 10 minutes.
Headers: `Cache-Control: no-store`, `X-Frame-Options: DENY`,
`Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`.

### 5.5 `POST /authorize`

Verifies the CSRF token, then the credentials (§3.3).

- **Failure** → re-render the login page with a generic "Invalid username or
  password", HTTP `401`. No distinction between unknown user and wrong
  password. Failed attempts are rate limited per source IP
  (`server.login_rate_limit`, default 10/m) and logged.
- **Success** → mint an authorization code and `302` to
  `redirect_uri?code=…&state=…`.

An authorization code is 256 bits of `crypto/rand`, base64url, single use, TTL
`code_ttl` (default 60 s), and is bound to: user, client_id, redirect_uri,
code_challenge.

There is no consent step. The resulting session is scoped to all targets of the
authenticated user at the time of each request.

### 5.6 `POST /token`

`application/x-www-form-urlencoded`.

**`grant_type=authorization_code`** — requires `code`, `redirect_uri`,
`client_id`, `code_verifier`. Verifies the code exists, is unexpired and
unused; `client_id` and `redirect_uri` match those bound to it; and
`BASE64URL(SHA256(code_verifier)) == code_challenge`. The code is consumed
whether or not verification succeeds.

**`grant_type=refresh_token`** — requires `refresh_token`, `client_id`. Issues
a new access token and rotates the refresh token; the old one is invalidated
immediately. Reuse of an already-rotated refresh token invalidates the entire
token family for that client and user.

Response `200`:

```json
{
  "access_token": "<256-bit base64url>",
  "token_type": "Bearer",
  "expires_in": 43200,
  "refresh_token": "<256-bit base64url>",
  "scope": "aegis"
}
```

Errors follow RFC 6749 §5.2 (`invalid_grant`, `invalid_request`,
`invalid_client`, `unsupported_grant_type`) with HTTP `400`, `Cache-Control:
no-store`.

### 5.7 Bearer authentication on `/mcp`

`Authorization: Bearer <access_token>`. Missing or invalid:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://aegis.example.com/.well-known/oauth-protected-resource"
```

Tokens are looked up by a constant-time-compared hash of the presented value.

## 6. Session state

Everything below lives in memory, guarded by a mutex, and is lost on restart.

| Table | Key | Fields | TTL |
| --- | --- | --- | --- |
| clients | client_id | name, redirect_uris, created | none (LRU 1000) |
| codes | code hash | user, client_id, redirect_uri, code_challenge, expiry | `code_ttl` |
| tokens | token hash | user, client_id, family, expiry | `token_ttl` |
| refresh | token hash | user, client_id, family, expiry | 30 d |

A janitor goroutine sweeps expired entries every 60 s. All secret-bearing
values are stored as SHA-256 hashes; the plaintext exists only in the response
that issued it.

Caps: 10 000 tokens, 10 000 refresh tokens. On overflow, the oldest are
evicted and a `warn` line is logged.

## 7. MCP transport

- **Endpoint:** `/mcp`
- **Protocol:** MCP over Streamable HTTP, JSON-RPC 2.0
- **`POST /mcp`** — a single JSON-RPC request or a batch. Responds
  `application/json`, or `text/event-stream` if the client sent
  `Accept: text/event-stream` and the response benefits from streaming.
- **`GET /mcp`** — opens an SSE stream for server-initiated messages. v1 sends
  only keep-alive comments every 30 s.
- **`DELETE /mcp`** — terminates the session; `204`.
- **`Mcp-Session-Id`** — issued on `initialize`, echoed by the client on
  subsequent requests. Bound to the access token; a mismatch is `404`.
- **`Origin`** — if present, it MUST be `public_url`'s origin or a loopback
  origin; otherwise `403` (DNS-rebinding protection).

### Supported methods

| Method | Notes |
| --- | --- |
| `initialize` | Returns `protocolVersion`, `serverInfo` (`aegis`, version), `capabilities: {tools: {listChanged: true}}` |
| `notifications/initialized` | Accepted, no response |
| `tools/list` | See §8 |
| `tools/call` | See §8 |
| `ping` | Empty result |

Unknown methods → JSON-RPC `-32601`.

`notifications/tools/list_changed` is sent after a config reload that changes
the calling user's targets.

## 8. Tools

### 8.1 `list_targets`

**Description shown to the model:** *"List the HTTP targets you are permitted
to reach through Aegis. Call this before http_request to learn which hosts,
paths and methods are available."*

**Input schema:** `{"type":"object","properties":{},"additionalProperties":false}`

**Result** — JSON in a text content block:

```json
{
  "targets": [
    {
      "id": "github",
      "description": "GitHub REST API, read-only",
      "base_url": "https://api.github.com",
      "methods": ["GET"],
      "paths": ["/repos/andreaskasper/**", "/user"],
      "rate_limit": "120/m"
    }
  ],
  "allow_any": false
}
```

The response MUST NOT contain injection rules, secret names or secret values.

### 8.2 `http_request`

**Description shown to the model:** *"Perform an HTTP request through Aegis.
Credentials are added by the server — never include API keys, tokens or
Authorization headers yourself. Only URLs matching a permitted target will be
sent."*

**Input schema:**

```json
{
  "type": "object",
  "properties": {
    "url":     {"type": "string", "description": "Absolute URL, including scheme and host"},
    "method":  {"type": "string", "enum": ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"], "default": "GET"},
    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
    "query":   {"type": "object", "additionalProperties": {"type": "string"}},
    "body":    {"type": "string", "description": "Raw request body"}
  },
  "required": ["url"],
  "additionalProperties": false
}
```

**Result on success:**

```json
{
  "status": 200,
  "headers": {"content-type": "application/json"},
  "body": "…",
  "truncated": false,
  "target": "github",
  "duration_ms": 143
}
```

Upstream 4xx/5xx are **successful tool calls** — the status is reported, not
raised as a tool error. Only Aegis-side refusals (§16) are errors with
`isError: true`.

## 9. Request pipeline

Ordered. Any step may terminate the request.

```
 1  authenticate            bearer token → user            401
 2  parse & normalise       absolute URL, lowercase host,
                            clean path, reject credentials
                            in the URL (user:pass@)        400
 3  match target            §10                            403
 4  network guard           §11                            403
 5  rate limit              §12                            429
 6  method check            target.methods                 403
 7  header check            reserved / injected names      400
 8  body size check         ≤ 1 MiB request body           413
 9  inject                  §13
10  send                    timeout, redirects per config
11  redact                  §14.1
12  truncate                §14.2
13  audit                   §15
14  respond
```

## 10. Target matching

### 10.1 Algorithm

For the authenticated user, in config order, the first target where **all** of
the following hold wins:

1. `url.scheme == base_url.scheme`
2. `url.host == base_url.host` (case-insensitive, default ports normalised)
3. `url.port == base_url.port`
4. `url.path` has `base_url.path` as a path-segment prefix
5. `url.path` matches at least one entry in `paths`, evaluated relative to the
   root (not to `base_url.path`)

No match → `403 no_target`, unless `allow_any` is true, in which case the
request proceeds with no injection, no target-level overrides and the server
defaults for timeout and size, and is audited with `"target": null`.

Method is checked *after* matching (step 6), so the audit log records which
target was attempted.

### 10.2 Path patterns

Glob syntax on `/`-separated segments:

| Token | Matches |
| --- | --- |
| `*` | any characters within one segment |
| `**` | zero or more whole segments; only valid as a complete segment |
| `?` | a single character within one segment |

Matching is case-sensitive and applied to the URL-decoded, `path.Clean`ed path.
A pattern MUST begin with `/`. `..` in the request path is rejected at step 2.

Examples:

| Pattern | `/v1/contacts` | `/v1/contacts/42` | `/v2/x` |
| --- | --- | --- | --- |
| `/v1/**` | ✅ | ✅ | ❌ |
| `/v1/*` | ✅ | ❌ | ❌ |
| `/**` | ✅ | ✅ | ✅ |

### 10.3 Query handling

Model-supplied `query` entries are merged into the URL's existing query.
Injected query parameters (§13) are applied last and **overwrite** any
same-named parameter.

## 11. Network guard

Applied to every outbound request, for every user, including `allow_any`, and
re-applied to each redirect hop.

Blocked destinations:

- `127.0.0.0/8`, `::1`
- `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- `169.254.0.0/16`, `fe80::/10` (includes `169.254.169.254`)
- `fc00::/7`, `100.64.0.0/10`
- `0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`
- Any non-`http`/`https` scheme

Enforcement resolves DNS and checks the **resolved IPs**, then dials that IP
directly via a custom `DialContext`, so a name cannot resolve to a public
address at check time and a private one at connect time (DNS rebinding).

`base_url` values pointing into blocked ranges are rejected at config load
time. There is no override in v1: a private-network target would defeat the
purpose.

## 12. Rate limiting

- Token bucket per `(user, target)`, capacity = the configured count, refilled
  continuously over the window.
- No `rate_limit` on a target → unlimited.
- `allow_any` requests share one bucket per user, default `60/m`.
- Exceeded → `429` with `retry_after_ms` in the error data. The request is
  audited with `status: 0` and `error: rate_limited`.
- Separate, independent limiters: `/register` (20/h per IP) and `POST
  /authorize` (`login_rate_limit`, default 10/m per IP).

## 13. Secret injection

### 13.1 Templates

Injection values are strings containing `${secret_name}` references, resolved
against the user's `secrets` map. A reference to an undefined secret is a
config-load error, not a runtime one. `$${` escapes a literal `${`.

### 13.2 Placement

| Section | Behaviour |
| --- | --- |
| `headers` | Set (overwriting any model-supplied header of the same name). |
| `query` | Set on the final URL, overwriting same-named parameters. |
| `body` | Applied only if the request body parses as JSON and `Content-Type` is JSON. Keys are JSONPath-lite (`$.token`, `$.auth.key`); intermediate objects are created. A non-JSON body with a `body` injection rule configured → `400 body_injection_failed`. |

### 13.3 Reserved headers

The model MUST NOT set: `Authorization`, `Proxy-Authorization`, `Cookie`,
`Host`, `Content-Length`, `Connection`, `Transfer-Encoding`, `Upgrade`,
`X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`, or any
header name a matched target injects. Any of these in `headers` → `400
reserved_header`, naming the offending header.

### 13.4 Invariants

- Injection happens after all validation and immediately before sending.
- The injected request is never serialised into a log, an error or a tool
  result.
- A model-supplied value can never influence *which* secret is used — only the
  matched target determines that.

## 14. Response processing

### 14.1 Redaction

Every secret value of the authenticated user is searched for, literally, in:

- the response body (as raw bytes)
- every response header value

and replaced with `[REDACTED:<secret_name>]`.

- Secret values shorter than 8 bytes are **not** redacted — the false-positive
  rate would corrupt legitimate content. This is logged once per secret at
  startup as a `warn`.
- Longest-first matching, so an overlapping pair yields the more specific name.
- The count of replacements is recorded in the audit line as `redacted`. A
  non-zero value on a target is a strong signal that the upstream reflects
  credentials.
- Redaction runs before truncation, so a secret cannot survive by straddling
  the cut.

### 14.2 Truncation

The body is cut to `max_response_bytes` (target override, else server default,
default 1 MiB) at a UTF-8 boundary. `truncated: true` is set and the audit line
records the original `bytes`.

### 14.3 Headers

- `Set-Cookie` and `Set-Cookie2` are dropped entirely.
- All other headers are returned with lower-cased names. Multi-valued headers
  are joined with `", "`.

### 14.4 Redirects

`follow_redirects: false` (default) returns the `3xx` and its `Location` header
to the model. With `follow_redirects: true`, up to 5 hops are followed; each
hop re-runs §10 (target match) and §11 (network guard), and injection is
re-applied only while the target still matches. A hop that leaves the target →
`403 redirect_out_of_scope`.

## 15. Audit log

One JSON object per line on stdout, for every `http_request` — allowed or
refused.

```json
{
  "ts": "2026-07-28T21:14:02.183Z",
  "level": "info",
  "event": "request",
  "user": "andreas",
  "client_id": "aBc123…",
  "target": "github",
  "method": "GET",
  "url": "https://api.github.com/user",
  "status": 200,
  "duration_ms": 143,
  "bytes": 312,
  "truncated": false,
  "injected": ["github_pat"],
  "redacted": 0
}
```

- `url` is logged **after** query redaction: any query parameter whose name
  appears in the target's `inject.query` is written as `name=[REDACTED]`.
- `injected` lists secret **names** only.
- Refusals carry `"status": 0` and `"error": "<code>"` (§16).
- Request and response bodies are never logged, at any log level.
- Other events: `startup`, `shutdown`, `config_reloaded`, `config_error`,
  `login_success`, `login_failed`, `client_registered`, `token_issued`,
  `token_reuse_detected`.

## 16. Errors

### 16.1 Tool errors

Returned as a JSON-RPC result with `isError: true` and a JSON text block:

```json
{"error": "no_target", "message": "No permitted target matches this URL.", "status": 403}
```

| Code | HTTP-equivalent | Meaning |
| --- | --- | --- |
| `invalid_url` | 400 | Not absolute, bad scheme, credentials in URL, `..` in path |
| `reserved_header` | 400 | Model tried to set a reserved or injected header |
| `body_injection_failed` | 400 | Body injection configured but body is not JSON |
| `no_target` | 403 | No target matched |
| `method_not_allowed` | 403 | Target matched, method not permitted |
| `blocked_network` | 403 | Destination resolves into a blocked range |
| `redirect_out_of_scope` | 403 | A redirect left the target |
| `request_too_large` | 413 | Request body over 1 MiB |
| `rate_limited` | 429 | Bucket empty; `retry_after_ms` included |
| `upstream_timeout` | 504 | Upstream did not respond in time |
| `upstream_error` | 502 | Connection or TLS failure |

Error messages MUST NOT reveal the existence of targets belonging to other
users, and MUST NOT contain a secret value.

### 16.2 HTTP errors

Non-MCP endpoints return `{"error":"…","status":<code>}`, except `/authorize`
which returns an HTML page.

## 17. CLI

| Command | Purpose |
| --- | --- |
| `aegis` | Run the server |
| `aegis hashpw` | Read a password from stdin (or prompt on a TTY), print a bcrypt hash |
| `aegis validate [path]` | Parse, resolve and validate a config; print findings; exit non-zero on error |
| `aegis version` | Version, commit, build date |

`aegis validate` MUST NOT print secret values — only names and whether they
resolved.

## 18. Source layout

```
.
├── Dockerfile
├── docker-compose.yml
├── config.example.yaml
├── README.md
├── projektbeschreibung.md
├── spezifikation.md
└── src/
    ├── go.mod
    ├── main.go          # entry point, CLI, routing, graceful shutdown
    ├── config.go        # YAML schema, validation, value resolution
    ├── reload.go        # watcher + SIGHUP, atomic swap
    ├── oauth.go         # discovery, DCR, /authorize, /token, PKCE
    ├── login.go         # login page, password verification
    ├── session.go       # in-memory clients, codes, tokens, janitor
    ├── mcp.go           # Streamable HTTP, JSON-RPC, session ids
    ├── tools.go         # list_targets, http_request, schemas
    ├── match.go         # target matching, path globs
    ├── netguard.go      # DNS resolution + IP range checks + safe dialer
    ├── ratelimit.go     # token buckets
    ├── inject.go        # header/query/body injection
    ├── redact.go        # redaction, truncation, header filtering
    └── audit.go         # structured logging
```

## 19. Test requirements

Minimum coverage before v1 is called done:

- **Path globs** — table-driven, including `**` at start/middle/end, encoded
  characters, and traversal attempts.
- **Target matching** — port normalisation, scheme mismatch, base-path prefix,
  first-match-wins ordering.
- **Network guard** — every blocked range, IPv4-mapped IPv6, DNS rebinding
  (name resolving to a private IP), redirect into a private IP.
- **Injection** — header overwrite, query overwrite, nested JSON body,
  non-JSON body rejection, `$${` escaping.
- **Redaction** — secret in body, in a header, split across a truncation
  boundary, overlapping secrets, sub-8-byte secret not redacted.
- **OAuth** — PKCE failure, code replay, refresh rotation, refresh reuse
  killing the family, redirect_uri mismatch, unknown client.
- **Reload** — invalid config leaves the old one active; removed user
  invalidates tokens; changed targets take effect.
- **Leak test** — a fuzz-style harness asserting that no secret value appears
  in any tool result, error message or log line across a broad matrix of
  inputs. This is the test that matters most.

## 20. Open questions

Deferred, to be resolved before or during implementation:

1. **Token revocation on password change** — currently no. Should a
   `revoke_on_password_change: true` per user be added?
2. **Body injection for non-JSON** — form-encoded bodies are common. Add
   `content_type: form` support to `inject.body`?
3. **`list_targets` and `allow_any`** — how should an `allow_any: true` user's
   permission be described to the model so it does not simply try everything?
4. **Refresh token TTL** — 30 days is arbitrary. Configurable per user?
5. **Streaming responses** — v1 buffers the whole response in order to redact
   it. Large downloads are therefore bounded by `max_response_bytes`. Is a
   streaming redactor with a sliding window worth the complexity later?
