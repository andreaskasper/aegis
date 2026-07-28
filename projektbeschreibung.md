# Aegis — Project Description

*What this is, who it is for, and why it is built the way it is.*

---

## 1. The problem

Giving an LLM agent access to an API means giving it a credential. Today that
credential ends up in an environment variable, an MCP server definition, a
`.env` file or a config JSON that the agent itself can read. Once it is there,
it is exposed to everything the agent touches:

- **Prompt injection.** A web page, an email, a ticket comment or an API
  response can instruct the agent to send the key somewhere. The agent has the
  key and the ability to make requests. Nothing structural prevents it.
- **Context leakage.** Keys land in transcripts, in logs, in screenshots, in
  bug reports, in whatever the provider retains.
- **Over-scoping.** A key is all-or-nothing. An agent that should read invoices
  can, with the same key, delete them.
- **Rotation.** A key handed to five agents on three machines is a key you will
  not rotate.

The uncomfortable part: **the model does not need the credential.** It needs the
*result* of an authenticated request. The credential is an implementation
detail of the transport that we have been handing over out of convenience.

## 2. The idea

Aegis is a mediator. The agent describes the request it wants; Aegis decides
whether that request is permitted, attaches the credentials itself, sends it,
and returns a response with every trace of the credential removed.

The credential lives in exactly one place — Aegis's configuration, inside a
container the model has no access to. The model gets capability without
possession.

This is the same shift as `sudo` versus handing out the root password, or an
OAuth scope versus sharing an account: **delegate the ability, not the secret.**

## 3. Threat model

### What Aegis defends against

| Threat | Defence |
| --- | --- |
| Prompt-injected agent exfiltrating a key | The key is never in the agent's context. It cannot send what it does not have. |
| Agent calling an unintended endpoint | Deny-by-default target matching on host, path and method. |
| Agent reaching internal infrastructure | Private ranges, loopback and cloud metadata IPs are blocked unconditionally. |
| An API reflecting the token back | Responses are scanned for every secret value and redacted before the model sees them. |
| Runaway loop burning an API quota | Per-user, per-target rate limits. |
| Key leaking through transcripts or logs | The key never enters a transcript; the audit log records names only. |
| Not knowing what the agent did | One structured audit line per request. |

### What Aegis does *not* defend against

- **Anything you explicitly allowed.** If a target permits `DELETE /v1/**`, a
  manipulated agent can delete. Aegis constrains the blast radius; it does not
  read intent. Scope targets narrowly.
- **A compromised host.** Root on the machine running Aegis means access to the
  config and the process memory. Aegis is a boundary between the *model* and
  the secret, not between an attacker and the machine.
- **A malicious MCP client.** Any client that completes the OAuth flow with
  valid user credentials gets that user's capabilities. Password strength and
  who you hand credentials to remain your responsibility.
- **Data exfiltration through allowed targets.** If a user has a writable
  target, that target can in principle be used as a channel. Read-only targets
  where possible.

## 4. Goals and non-goals

**Goals**

1. A secret configured in Aegis must never reach the model — not in a tool
   result, not in an error, not in a log.
2. Deny by default. Every outbound request is explicitly permitted or refused.
3. One file to configure, editable while running.
4. Small enough to audit by reading it.
5. Work with a standard MCP client without special setup: paste a URL, log in.

**Non-goals**

- Not a general HTTP proxy or a WebFetch replacement.
- Not a secret *manager*. It has no rotation, versioning or checkout. Point it
  at Vault or Docker secrets through `env:` / `file:` references if you need
  that.
- Not an API gateway. No transformation, aggregation, caching or schema
  translation.
- Not multi-tenant SaaS. It is a personal or small-team component.
- No web admin UI. The config file is the interface.

## 5. Architecture

```
                         ┌────────────────────────────────────┐
  MCP client             │              aegis :2019           │
  (Claude, agent, …)     │                                    │
        │                │  OAuth 2.1 AS                      │
        ├─ discovery ───►│   /.well-known/*  /register        │
        ├─ login ───────►│   /authorize (login form)          │
        ├─ token ───────►│   /token (PKCE)                    │
        │                │           │                        │
        │                │        identity = user             │
        │                │           │                        │
        └─ MCP ─────────►│  /mcp ──► list_targets             │
                         │           http_request             │
                         │              │                     │
                         │      ┌───────▼────────┐            │
                         │      │ match  → 403?  │            │
                         │      │ ratelimit      │            │
                         │      │ inject secrets │            │
                         │      │ send           │──────────► upstream API
                         │      │ redact         │◄────────── response
                         │      │ truncate       │            │
                         │      │ audit → stdout │            │
                         │      └────────────────┘            │
                         │                                    │
                         │  config.yaml (watched, hot-reload) │
                         └────────────────────────────────────┘
```

Three layers, each with one job:

1. **Identity** — OAuth 2.1 establishes *which user* is calling. Everything
   downstream is scoped to that user.
2. **Authorisation** — the user's targets decide what may be requested.
3. **Mediation** — injection on the way out, redaction on the way back.

## 6. Design decisions

Each decision, and what it cost.

### Go

The same choice as [secondbrain](https://github.com/andreaskasper/secondbrain):
a static binary, a container measured in megabytes, no runtime underneath, and
a dependency list short enough to read. For a process whose entire purpose is
holding credentials, a small supply chain is a security property. Only two
external packages: `gopkg.in/yaml.v3` and `golang.org/x/crypto` for bcrypt.

### MCP over Streamable HTTP, port 2019

Streamable HTTP is the current transport for remote MCP servers and is what
modern clients speak. stdio was rejected because Aegis is a shared network
service, not a per-client subprocess — the whole point is that it runs
*somewhere the model isn't*.

### OAuth 2.1 with a login screen, not a static bearer token

A static token would have been a fraction of the code. It was rejected because
of what the login gives us: **the login is how Aegis learns who is asking.**
Identity is not decoration here, it is the authorisation key — it selects the
target set and the secret set. A shared token would collapse all users into
one.

Dynamic Client Registration is included so that adding Aegis to a client is
pasting a URL, not editing a config on both ends.

There is no consent screen. Deliberately: the user is the operator, the
targets were chosen by the same person who wrote the config, and a
click-through nobody reads is not a security control.

### In-memory state only

Registered clients, authorization codes, access and refresh tokens exist only
in RAM. Restarting means everyone logs in again.

This is a real cost, accepted for a real benefit: **a container full of
credentials that writes nothing to disk leaves nothing behind.** No token
database to steal, back up by accident, or forget to encrypt. It also keeps the
container image free of a writable volume.

Hot-reloading the configuration is the mitigation: adding a target or rotating
a secret does not require a restart, so restarts stay rare.

### Deny by default, with a per-user escape hatch

The default is that a URL matching no target is not fetched. Anything else
would turn Aegis into an open HTTP proxy with the server's network position —
which is exactly the SSRF primitive an attacker wants.

`allow_any: true` exists for the user who wants Aegis to double as a general
fetcher. Even then the private-network guard is not negotiable.

### Declarative injection only

Injection rules are attached to the target, not chosen by the model. The
alternative — letting the model write `${secret.x}` where it likes — was
rejected because it hands placement back to a component that can be
manipulated. A model that can decide *where* a secret goes can, under
injection, put it into a query parameter of an allowed host that echoes it
back.

Declaring the rule once, at the target, means the model's input can be wrong
but never dangerous in this specific way.

### Response redaction

Injection alone is not enough. `POST /debug/echo`, a verbose 401, a webhook
inspector — plenty of endpoints will happily hand your token back. Aegis
searches every response for the user's secret values and replaces them.

The cost is a scan per response, proportional to body size times secret count.
That is cheap next to a network round-trip.

### Two tools, not many

`http_request` plus `list_targets`. Generating one tool per configured target
would improve the model's aim, but makes the tool list a function of the user
and the config, which complicates caching and makes the surface grow without
bound. `list_targets` recovers most of the discoverability at a fraction of the
complexity — without it the model is guessing at hosts and paths.

### YAML, nested per user

Configuration is written and read by humans, and YAML tolerates comments and
long values better than JSON. The cost is one dependency.

Targets and secrets are nested inside their user rather than referenced from a
shared pool. Flat-with-references would avoid duplication when two users share
an API; nesting was chosen because it makes the security-relevant question —
*what exactly can this user do?* — answerable by reading one contiguous block,
with no indirection to follow. In a security tool, legibility beats DRY.

## 7. Typical uses

- **Personal agent, real accounts.** Your Claude setup can query your
  accounting API, your GitHub, your monitoring — without any of those tokens
  ever entering a conversation.
- **Read-only production access.** A `GET`-only target on a narrow path prefix
  lets an agent investigate without the ability to change anything.
- **Shared team credential.** One team API key sits in Aegis; each colleague
  logs in as themselves. The audit log shows who did what. Rotating means
  editing one line.
- **Untrusted or experimental agents.** Give a new agent a user with one narrow
  target and watch the audit log before widening it.

## 8. Roadmap

**v1** — everything described here: OAuth with DCR and login, `list_targets`
and `http_request`, target matching, rate limiting, injection, redaction,
truncation, SSRF guard, hot-reload, audit log, Docker image.

**Later, if it earns its place**

- Response filters per target (allowed JSON paths) to shrink what reaches the
  context
- Per-target tool generation as an opt-in
- Optional persistence for deployments that value uptime over amnesia
- mTLS or IP allowlisting in front of the MCP endpoint
- Audit log shipping (webhook, syslog)
- Request approval: hold a request until a human confirms it

**Explicitly rejected** — a web admin UI, request/response transformation, a
plugin system. Each would add attack surface to a component whose value comes
from having very little.
