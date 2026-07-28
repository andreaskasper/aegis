# Deployment examples

Runnable Docker Compose setups. Each directory is self-contained: copy it,
fill in `.env`, drop a `config.yaml` next to it, and start.

| Directory | Setup | When to use it |
| --- | --- | --- |
| [`traefik/`](traefik/) | Traefik + Let's Encrypt | Your own server, your own certificates. The standard case. |
| [`cloudflared/`](cloudflared/) | Cloudflare Tunnel | No open port, no firewall rule, no certificate on the server. The smallest attack surface. |

Cloudflare's proxy in front of Traefik uses the `traefik/` files unchanged —
what differs is the Cloudflare configuration. The
[deployment guide](https://andreaskasper.github.io/aegis/deploy.html) covers
that combination, along with the details that bite: the client IP behind a
proxy, Cloudflare Access breaking MCP clients, SSE timeouts, and how to get
secrets into the container.

## Three rules

1. **`public_url` is the contract.** Every OAuth redirect is derived from it.
   It must be the URL the client uses, including `https://` — not the
   container name and not the internal address.

2. **Never publish port 2019.** In both examples the aegis service has no
   `ports:` section on purpose. Publishing it means a plaintext OAuth
   endpoint on the open internet.

3. **Validate before you start.** `docker compose run --rm aegis validate
   /etc/aegis/config.yaml` reports every problem at once and never prints a
   secret value.
