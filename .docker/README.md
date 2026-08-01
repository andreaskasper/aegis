# aegis 🛡️

**A secrets firewall for LLM agents.**

aegis is an [MCP](https://modelcontextprotocol.io) server that lets a model make
HTTP requests to your APIs — without ever letting it see the credentials those
requests are authenticated with.

[![Source](https://img.shields.io/badge/source-github-181717?logo=github)](https://github.com/andreaskasper/aegis)
[![License](https://img.shields.io/badge/license-MIT-blue)](https://github.com/andreaskasper/aegis/blob/main/LICENSE)
[![Image size](https://img.shields.io/docker/image-size/andreaskasper/aegis/latest)](https://hub.docker.com/r/andreaskasper/aegis/tags)
[![Pulls](https://img.shields.io/docker/pulls/andreaskasper/aegis)](https://hub.docker.com/r/andreaskasper/aegis)

---

## Why

To let an agent use an API, you normally hand it the API key — in an environment
variable, an MCP server config, a `.env` file. From that moment the key is one
prompt injection, one careless log line or one screenshot away from leaking.

The model does not need the key. It needs the *result*.

aegis sits in between. The model asks for a request; aegis decides whether it is
allowed, adds the credentials on the way out, and strips them out of whatever
comes back.

```
┌─────────┐   MCP (OAuth 2.1)   ┌───────────┐   HTTPS + secret   ┌──────────┐
│   LLM   │ ──────────────────► │   aegis   │ ─────────────────► │   API    │
│  agent  │ ◄────────────────── │  :2019    │ ◄───────────────── │          │
└─────────┘   redacted result   └───────────┘      response      └──────────┘
                                      │
                                 config.yaml
                            users · targets · secrets
```

## Quick start

```bash
# 1. A password hash for the login screen
docker run --rm -it andreaskasper/aegis hashpw

# 2. Write a config.yaml (see below), then check it before it ever runs
docker run --rm -v "$PWD/config.yaml:/etc/aegis/config.yaml:ro" \
  andreaskasper/aegis validate /etc/aegis/config.yaml

# 3. Run it
docker run -d --name aegis -p 2019:2019 \
  -v "$PWD/config.yaml:/etc/aegis/config.yaml:ro" \
  -e AEGIS_PUBLIC_URL=https://aegis.example.com \
  --read-only --cap-drop ALL \
  andreaskasper/aegis:latest
```

aegis writes nothing to disk, so `--read-only` is not a precaution you are taking
on its behalf — it is how the container is meant to run.

With Compose:

```yaml
services:
  aegis:
    image: andreaskasper/aegis:latest
    ports: ["2019:2019"]
    volumes:
      - ./config.yaml:/etc/aegis/config.yaml:ro
    environment:
      AEGIS_PUBLIC_URL: https://aegis.example.com
    read_only: true
    cap_drop: [ALL]
    restart: unless-stopped
```

Then point an MCP client at `https://aegis.example.com/mcp`. The client discovers
the OAuth endpoints, registers itself, opens the login page in a browser, and you
sign in with a user from your `config.yaml`.

aegis speaks plain HTTP and does **not** terminate TLS. Put it behind a reverse
proxy (Traefik, Caddy, nginx, Cloudflare) in production. Ready-made Compose
setups for Traefik and Cloudflare Tunnel are
[in the repository](https://github.com/andreaskasper/aegis/tree/main/deploy).

## Configuration

One YAML file. Users are the top-level unit: each brings their own secrets and
their own targets.

```yaml
server:
  public_url: "https://aegis.example.com"   # or AEGIS_PUBLIC_URL
  max_response_bytes: 1048576               # 1 MiB
  token_ttl: "12h"

users:
  - name: andreas
    password: "bcrypt:$2a$12$Xk8f...redacted..."

    secrets:
      github_pat: "file:/run/secrets/github_pat"

    targets:
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
```

Secrets and passwords may be written literally or as a reference: `env:NAME`,
`file:/path` (for Docker secrets), or `bcrypt:$2a$12$…` for passwords.

The file is watched and hot-reloaded. If an edit does not validate, the previous
configuration stays live and the error is logged — a typo cannot take the server
down.

### Environment

| Variable           | Default                  | Notes                       |
| ------------------ | ------------------------ | --------------------------- |
| `AEGIS_CONFIG`     | `/etc/aegis/config.yaml` | mount your file here        |
| `AEGIS_LISTEN`     | `:2019`                  |                             |
| `AEGIS_PUBLIC_URL` | —                        | the URL clients reach it on |

## What the model gets

Exactly two tools — a small surface is the point.

- **`list_targets`** — which APIs this user may reach, with methods and path
  patterns. Secrets and injection rules are not part of the answer.
- **`http_request`** — url, method, headers, query, body. Returns status, headers
  and body, after redaction and truncation.

## Security

- **Deny by default.** A URL matching no target is never fetched.
- **SSRF guards.** Loopback, RFC1918, link-local and cloud metadata addresses are
  refused — including via DNS names that resolve into them, and including on
  redirects.
- **Secrets travel outbound only.** No tool result, error message or log line
  returns a secret value; the audit log records secret *names*.
- **Reflection is caught.** An API that echoes your token back in a debug
  endpoint cannot leak it into the model's context: the response is scanned for
  every secret value and rewritten to `[REDACTED:name]`.
- **Header allowlist.** The model may not set `Authorization`, `Cookie`, `Host`
  or `X-Forwarded-*`.
- **No persistence.** Nothing is written to disk, so nothing can be read off it.
  Tokens and registered clients do not survive a restart, by design.

aegis reduces the blast radius of a compromised or manipulated agent. It does not
make one safe: a `POST`-enabled target can still be used to do damage *within*
what you allowed. Scope targets to what the agent actually needs.

## The image

- Built `FROM gcr.io/distroless/static-debian12:nonroot` — no shell, no package
  manager, a single static Go binary.
- Runs as `nonroot` (UID 65532). Works with `--read-only` and `--cap-drop ALL`.
- `linux/amd64` and `linux/arm64`.
- Every release carries an SBOM and a signed
  [build provenance attestation](https://github.com/andreaskasper/aegis/attestations).

### Tags

| Tag           | Points at                               |
| ------------- | --------------------------------------- |
| `latest`      | the most recent release                 |
| `0.1.6`       | that exact release                      |
| `0.1`         | the newest patch of that minor          |
| `edge`        | current `main`, rebuilt on every commit |
| `sha-1a2b3c4` | one exact commit                        |

### Also on GitHub Container Registry

The identical image — same digest, same build:

```bash
docker pull ghcr.io/andreaskasper/aegis:latest
```

## Links

- **Source & issues:** <https://github.com/andreaskasper/aegis>
- **Full specification:** <https://github.com/andreaskasper/aegis/blob/main/spezifikation.md>
- **License:** MIT

Made with ❤️ by [Andreas Kasper](https://github.com/andreaskasper)
