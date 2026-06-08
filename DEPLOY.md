# Deploying Monarch MCP Server (single-VM Docker host)

Test-gated continuous deployment to a Docker VM, mirroring the-flooring-system
setup. On every push to `main`, GitHub runs the pytest suite; **only if it
passes** does `.github/workflows/deploy.yml` SSH into the server, `git pull`,
rebuild, and restart the container.

The container serves plain HTTP on a loopback port; the host's existing **nginx**
reverse proxy and **Cloudflare** (which terminates public TLS) are the public
entrypoint — so "one container bound to 127.0.0.1" is exactly the design.

```
Internet ──TLS──> Cloudflare ──http──> host nginx :80 ──> 127.0.0.1:${HOST_PORT}
                  (monarch-mcp.jackstoller.com)              │ (monarch-mcp container)
                                                             ├── /healthz  (public)
                                                             ├── /.well-known/oauth-protected-resource
                                                             └── /mcp  (Bearer JWT required)
```

## One-time server setup

1. **Clone the repo** to the path the deploy workflow expects:
   ```bash
   sudo mkdir -p /opt/docker && cd /opt/docker
   sudo git clone https://github.com/jackstoller/monarch-mcp-server.git monarch-mcp
   cd monarch-mcp
   ```

2. **Create the server `.env`** (next to `docker-compose.yml`, gitignored):
   ```bash
   cp .env.example .env && nano .env
   ```
   Set at least:
   - `TRANSPORT=http`, `HOST_PORT=8100` (a free loopback port on this host)
   - `PUBLIC_URL` / `OAUTH_AUDIENCE` = `https://monarch-mcp.jackstoller.com`
   - `OAUTH_ISSUER=https://jackstoller.us.auth0.com/`
   - `OAUTH_JWKS_URI=https://jackstoller.us.auth0.com/.well-known/jwks.json`
   - `MONARCH_EMAIL` / `MONARCH_PASSWORD` / `MONARCH_MFA_SECRET`
   - `READ_ONLY=true`

3. **First boot:**
   ```bash
   sudo docker compose build
   sudo docker compose up -d
   curl -fsS http://127.0.0.1:8100/healthz   # -> {"status":"ok"}
   ```

4. **nginx vhost** at `/etc/nginx/conf.d/monarch-mcp.jackstoller.com.conf`:
   ```nginx
   server {
       listen 10.0.0.186:80;
       server_name monarch-mcp.jackstoller.com;
       location / {
           proxy_pass http://127.0.0.1:8100;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_buffering off;              # stream MCP/SSE responses
           proxy_read_timeout 3600s;
       }
   }
   ```
   Then `sudo nginx -t && sudo systemctl reload nginx`.

5. **Cloudflare**: `monarch-mcp.jackstoller.com` is a proxied (orange-cloud)
   record. SSL/TLS mode "Flexible" or "Full" both work (origin is HTTP:80 behind
   nginx, same as tfs).

## GitHub Actions secrets (repo → Settings → Secrets → Actions)

| Secret | Value |
|---|---|
| `SERVER_HOST` | `129.153.138.54` |
| `SERVER_USER` | `ubuntu` (can run `sudo docker`) |
| `SSH_PRIVATE_KEY` | private key whose pubkey is in the user's `authorized_keys` |

## How a deploy runs

1. Push to `main` → the `test` job runs `pytest`.
2. On success, `deploy` SSHes in: `git pull`, `docker compose build`,
   `up -d`, image prune, `ps`, and a `/healthz` probe.
3. A red suite blocks the deploy.

## Notes

- The server-side `.env` and the named `monarch-session` volume (the persisted
  Monarch token) survive rebuilds — they are never in git.
- To rotate Monarch creds or change OAuth config, edit `.env` on the server and
  `sudo docker compose up -d` (recreates the container with new env).
