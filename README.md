# aegis 🛡️

A secrets firewall for LLM agents. Aegis is an **MCP server** that lets a model
make HTTP requests to your APIs — without ever letting it see the credentials
those requests are authenticated with.


### Status & Stats

![Last Commit](https://img.shields.io/github/last-commit/andreaskasper/aegis.svg)
![Commit Activity](https://img.shields.io/github/commit-activity/m/andreaskasper/aegis.svg)
[![Issues](https://img.shields.io/github/issues/andreaskasper/aegis.svg)](https://github.com/andreaskasper/aegis/issues)
![Repo Size](https://img.shields.io/github/repo-size/andreaskasper/aegis.svg)
[![Docker Pulls](https://img.shields.io/docker/pulls/andreaskasper/aegis.svg)](https://hub.docker.com/r/andreaskasper/aegis)
![Stars](https://img.shields.io/github/stars/andreaskasper/aegis.svg?style=social)

---

## The problem

To let an agent use an API, you normally hand it the API key — in an
environment variable, an MCP server config, a `.env` file. From that moment the
key is one prompt injection, one careless log line or one screenshot away from
leaking. The model does not need the key. It needs the *result*.

Aegis sits in between. The model asks for a request; Aegis decides whether it
is allowed, adds the credentials on the way out, strips them on the way back.

```
┌─────────┐   MCP (OAuth 2.1)   ┌───────────┐   HTTPS + secret   ┌──────────┐
│   LLM   │ ──────────────────► │   aegis   │ ─────────────────► │   API    │
│  agent  │ ◄────────────────── │  :2019    │ ◄───────────────── │          │
└─────────┘   redacted result   └───────────┘      response      └──────────┘
                                      │
                                 config.yaml
                            users · targets · secrets
```

- **Language:** Go (standard library, plus `gopkg.in/yaml.v3` and `x/crypto`)
- **Transport:** MCP over Streamable HTTP on port `2019`
- **Auth:** OAuth 2.1 with Dynamic Client Registration; Aegis is its own
  authorization server with a login screen
- **Config:** a single `config.yaml`, hot-reloaded
- **State:** in memory only — nothing is persisted, ever

## Where to get it

The image is published to two registries from the same build, with the same
digest and the same tags. Neither is a mirror of the other; pick whichever you
already trust.

| Registry                  | Image                          |
| ------------------------- | ------------------------------ |
| GitHub Container Registry | `ghcr.io/andreaskasper/aegis`  |
| Docker Hub                | `andreaskasper/aegis`          |

`linux/amd64` and `linux/arm64`, with an SBOM and a signed
[build provenance attestation](https://github.com/andreaskasper/aegis/attestations)
on every release.

The examples below use the ghcr.io address throughout — a compose file can only
pull one, and printing both would make them ambiguous rather than helpful.
Substitute `andreaskasper/aegis` anywhere you see it if you prefer Docker Hub.

## Quick start

```bash
docker run -d --name aegis -p 2019:2019 \
  -v "$PWD/config.yaml:/etc/aegis/config.yaml:ro" \
  -e AEGIS_PUBLIC_URL=https://aegis.example.com \
  ghcr.io/andreaskasper/aegis:latest
```

Or with Compose:

```yaml
services:
  aegis:
    # or: andreaskasper/aegis:latest
    image: ghcr.io/andreaskasper/aegis:latest
    ports: ["2019:2019"]
    volumes:
      - ./config.yaml:/etc/aegis/config.yaml:ro
    environment:
      AEGIS_PUBLIC_URL: https://aegis.example.com
    restart: unless-stopped
```

Then point an MCP client at `https://aegis.example.com/mcp`. The client
discovers the OAuth endpoints, registers itself, opens the login page in a
browser, and you sign in with a user from your `config.yaml`.

Aegis speaks plain HTTP and does **not** terminate TLS. Put it behind a reverse
proxy (Traefik, Caddy, nginx, Cloudflare) in production.

### Image tags

| Tag           | Points at                               |
| ------------- | --------------------------------------- |
| `latest`      | the most recent release                 |
| `0.1.6`       | that exact release                      |
| `0.1`         | the newest patch of that minor          |
| `edge`        | current `main`, rebuilt on every commit |
| `sha-1a2b3c4` | one exact commit                        |

`edge` is built from every push to `main`. It is where a fix lands first, and
also where a mistake lands first — pin a release for anything you care about.

## Configuration

Everything lives in one YAML file. Users are the top-level unit: each user
brings their own secrets and their own targets.

```yaml
server:
  listen: ":2019"
  public_url: "https://aegis.example.com"   # or AEGIS_PUBLIC_URL
  max_response_bytes: 1048576                # 1 MiB
  token_ttl: "12h"

users:
  - name: andreas
    password: "bcrypt:$2a$12$Xk8f...redacted..."
    allow_any: false

    secrets:
      lexware_token: "env:LEXWARE_TOKEN"
      github_pat:    "file:/run/secrets/github_pat"
      weather_key:   "abcdef123456"

    targets:
      - id: lexware
        description: "Lexware Office accounting API — invoices, contacts, vouchers"
        base_url: "https://api.lexware.io"
        methods: [GET, POST]
        paths: ["/v1/**"]
        rate_limit: "60/m"
        inject:
          headers:
            Authorization: "Bearer ${lexware_token}"

      - id: github
        description: "GitHub REST API, read-only"
        base_url: "https://api.github.com"
        methods: [GET]
        paths: ["/repos/andreaskasper/**", "/user"]
        rate_limit: "120/m"
        inject:
          headers:
            Authorization: "Bearer ${github_pat}"
            Accept: "application/vnd.github+json"

      - id: weather
        description: "OpenWeatherMap current conditions"
        base_url: "https://api.openweathermap.org"
        methods: [GET]
        paths: ["/data/2.5/**"]
        inject:
          query:
            appid: "${weather_key}"
```

### Value prefixes

Any secret value — and any password — may be written literally or as a
reference:

| Form                     | Meaning                                   |
| ------------------------ | ----------------------------------------- |
| `hunter2`                | literal value                             |
| `env:NAME`               | read from the environment                 |
| `file:/path`             | read from a file (Docker/Podman secrets)  |
| `bcrypt:$2a$12$…`        | passwords only: a bcrypt hash             |

Generate a hash with `docker run --rm ghcr.io/andreaskasper/aegis hashpw`.

### Reloading

Aegis watches `config.yaml` and reloads it when it changes; `SIGHUP` forces a
reload. If the new file does not parse or does not validate, the old
configuration stays active and the error is logged. Existing sessions survive a
reload.

## Authentication

Aegis is a full OAuth 2.1 authorization server, so a compliant MCP client needs
nothing but the URL:

| Endpoint                                       | Purpose                          |
| ---------------------------------------------- | -------------------------------- |
| `/.well-known/oauth-protected-resource`        | points at the authorization server |
| `/.well-known/oauth-authorization-server`      | endpoint + capability metadata   |
| `POST /register`                               | dynamic client registration      |
| `GET /authorize`                               | login form                       |
| `POST /authorize`                              | credential check → auth code     |
| `POST /token`                                  | code (PKCE, S256) → access token |

The login form asks for a username and password from `config.yaml`. There is no
consent screen: a successful login issues a token scoped to that user's
targets. The token *is* the identity — it decides which targets may be reached
and which secrets get injected.

**Everything is in memory.** Registered clients, authorization codes and access
tokens do not survive a restart. After `docker restart aegis`, clients
re-register and users sign in again. This is deliberate: a container holding
credentials should leave nothing behind on disk.

## Tools

Aegis exposes exactly two tools. A small surface is the point.

### `list_targets`

No arguments. Returns the targets the calling user may reach — id, description,
base URL, allowed methods and path patterns. The model needs this to know what
it can even attempt. Secrets and injection rules are **not** part of the
response.

```json
{
  "targets": [
    {
      "id": "github",
      "description": "GitHub REST API, read-only",
      "base_url": "https://api.github.com",
      "methods": ["GET"],
      "paths": ["/repos/andreaskasper/**", "/user"]
    }
  ]
}
```

### `http_request`

| Argument  | Type   | Notes                                    |
| --------- | ------ | ---------------------------------------- |
| `url`     | string | **required**, absolute                   |
| `method`  | string | default `GET`                            |
| `headers` | object | optional; reserved headers are rejected  |
| `query`   | object | optional                                 |
| `body`    | string | optional                                 |

Returns status, response headers and body — after redaction and truncation.

```json
{
  "status": 200,
  "headers": {"content-type": "application/json"},
  "body": "{\"login\":\"andreaskasper\"}",
  "truncated": false,
  "target": "github",
  "duration_ms": 143
}
```

## How a request is handled

1. **Authenticate** the bearer token → resolves to exactly one user.
2. **Match** the URL against that user's targets: host, path pattern, method.
   No match → `403`, and nothing leaves the container. Unless the user has
   `allow_any: true`, in which case any public host is permitted — but private
   ranges, loopback and cloud metadata endpoints stay blocked, always.
3. **Rate-limit** per user and target.
4. **Inject** the declared headers, query parameters and body fields, resolving
   `${secret}` references. The model cannot influence this step and never sees
   the result.
5. **Send** the request. Redirects are not followed automatically.
6. **Redact** the response: every one of the user's secret values is searched
   for in the body and headers and replaced with `[REDACTED:name]`. `Set-Cookie`
   is dropped.
7. **Truncate** to `max_response_bytes` and flag it.
8. **Log** one JSON line to stdout.

## Security notes

- **Deny by default.** A URL that matches no target is never fetched.
- **SSRF guards.** `127.0.0.0/8`, `10/8`, `172.16/12`, `192.168/16`,
  `169.254/16`, `::1`, `fc00::/7` and DNS names resolving into them are refused
  — including on redirects and including for `allow_any` users.
- **Secrets are one-way.** They travel outbound only. No tool, error message or
  log line returns a secret value; the audit log records secret *names*.
- **Reflection is caught.** An API that echoes your token back — in a debug
  endpoint, in an error message — cannot leak it into the model's context,
  because the response is scanned for it.
- **Header allowlist.** The model may not set `Authorization`, `Cookie`,
  `Host`, `X-Forwarded-*` or any header a target injects.
- **Constant-time** comparison for tokens and passwords.
- **No persistence.** Nothing is written to disk, so nothing can be read off it.

Aegis reduces the blast radius of a compromised or manipulated agent. It does
not make one safe: a `POST`-enabled target can still be used to do damage
*within* what you allowed. Scope your targets to what the agent actually needs.

## Audit log

One JSON line per request on stdout:

```json
{"ts":"2026-07-28T21:14:02Z","user":"andreas","target":"github",
 "method":"GET","url":"https://api.github.com/user","status":200,
 "duration_ms":143,"bytes":312,"truncated":false,
 "injected":["github_pat"],"redacted":0}
```

`injected` lists secret *names*. Values never appear — not here, not anywhere.

## Project layout

```
.
├── Dockerfile
├── .dockerignore
├── docker-compose.yml
├── config.example.yaml
├── README.md
├── .docker/README.md         # the Docker Hub overview
├── projektbeschreibung.md    # what and why
├── spezifikation.md          # the full spec
└── src/
    ├── go.mod
    ├── main.go               # entry point, routing, graceful shutdown
    ├── config.go             # YAML schema, validation, value resolution
    ├── reload.go             # file watcher + SIGHUP
    ├── oauth.go              # discovery, DCR, /authorize, /token
    ├── login.go              # login form + password verification
    ├── session.go            # in-memory clients, codes, tokens
    ├── mcp.go                # Streamable HTTP transport, JSON-RPC
    ├── tools.go              # list_targets, http_request
    ├── match.go              # target matching, path globs, SSRF guard
    ├── inject.go             # secret injection
    ├── redact.go             # response redaction + truncation
    ├── ratelimit.go          # per user/target limiter
    └── audit.go              # structured log
```


## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a Pull Request.

## 📝 License

MIT License — feel free to use this in your own projects!

## 💰 Support the project

If this project saves you time, consider supporting its development:

[![donate via Patreon](https://img.shields.io/badge/Donate-Patreon-green.svg)](https://www.patreon.com/AndreasKasper)
[![donate via PayPal](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.me/AndreasKasper)
[![donate via Ko-fi](https://img.shields.io/badge/Donate-Ko--fi-green.svg)](https://ko-fi.com/andreaskasper)
[![Sponsors](https://img.shields.io/github/sponsors/andreaskasper)](https://github.com/sponsors/andreaskasper)

---

**Made with ❤️ by [Andreas Kasper](https://github.com/andreaskasper)**
