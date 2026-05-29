# webauthn-proxy

A forward-auth proxy for [Traefik](https://traefik.io) that replaces passwords with **biometrics** — fingerprint, Face ID, or any FIDO2 passkey.  
It speaks the same forward-auth contract as [oauth2-proxy](https://github.com/oauth2-proxy/oauth2-proxy) but authenticates with [WebAuthn](https://webauthn.io) instead of OIDC.

```
Browser ──► Traefik ──► Your App
                │
          forwardAuth
                │
         webauthn-proxy
           (session?)
           ✓ 200  /  ✗ 302 → /login
```

---

## Features

- **Fingerprint / Face ID / passkey** — no passwords, no OIDC provider
- **Discoverable credentials** — login requires only a fingerprint tap, no username entry
- **Multi-device** — users can register as many authenticators as they like
- **Zero-credential bootstrap** — first-run registration is open; locks itself after the first credential is stored
- **Offline user creation** — `create-user` subcommand seeds the store without exposing a web endpoint
- **Encrypted session cookies** — AES-GCM + HMAC, keys derived from `--cookie-secret`
- **Audit log** — every forward-auth decision is structured-logged to stdout
- **No database** — credentials stored in a single JSON file
- **Single static binary** — ~10 MB Docker image, no runtime dependencies
- **Traefik-native** — drops in as a `forwardAuth` middleware, compatible with Traefik v2 and v3

---

## Quick start

```bash
git clone https://github.com/your-org/webauthn-proxy
cd webauthn-proxy

task init   # generates .env with a random COOKIE_SECRET
task pull   # pull traefik + whoami images (once, needs network)
task up     # build proxy, start stack
```

Then open **http://localhost:8000/_webauthn/register** — because no credentials exist yet, the page is open for first-run setup. Register your fingerprint, then visit the protected app at **http://localhost:8000/whoami**.

---

## Zero-credential bootstrap (detailed)

The proxy uses a **zero-credential state** to eliminate the chicken-and-egg problem of securing the registration endpoint before any admin exists.

### How it works

| State | Who can reach `/_webauthn/register` |
|-------|--------------------------------------|
| **No credentials in store** (first run) | Anyone — first-run banner shown |
| Credentials exist, user **authenticated** | Allowed — adding a second device |
| Credentials exist, user **not authenticated** | Redirected to login |
| `ALLOW_REGISTRATION=true` + `REGISTRATION_TOKEN` set | Anyone with `?token=<secret>` |

Once the first credential is registered the registration page is invisible to unauthenticated visitors — it self-locks automatically.

### Step-by-step: secure first deployment

**Option A — web bootstrap (recommended for single-user)**

1. Deploy with an empty data volume (no `users.json`).
2. Visit `http://<your-host>/_webauthn/register`.
3. Enter a username and tap your fingerprint.
4. Done — the proxy is now locked to your device.

**Option B — offline bootstrap (recommended for teams)**

Pre-create user accounts before the proxy is publicly reachable:

```bash
# Creates the user entry with no credentials (safe to run before `task up`)
task create-user USER=alice
task create-user USER=bob

# Start the proxy
task up
```

Each user then visits `/_webauthn/register` **while authenticated** to add their own device.  
But wait — they have no credentials yet to authenticate with. Use a temporary registration token:

```bash
# In docker-compose.yaml or .env, set:
ALLOW_REGISTRATION=true
REGISTRATION_TOKEN=<strong-random-secret>

task restart

# Share with each team member:
# http://localhost:8000/_webauthn/register?token=<strong-random-secret>
```

After all users have registered their devices, disable open registration:

```bash
ALLOW_REGISTRATION=false   # remove REGISTRATION_TOKEN too
task restart
```

### Adding a second device

Sign in normally, then visit `/_webauthn/register`. The username field is pre-filled and locked. Tap your new authenticator to add it.

---

## Configuration

All flags can also be set as environment variables (uppercase, underscores).

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--http-address` | `HTTP_ADDRESS` | `:4180` | Listen address |
| `--proxy-url` | `PROXY_URL` | `` | Public base URL of this proxy (e.g. `http://localhost:8000`). Required for correct login redirects through Traefik. |
| `--cookie-secret` | `COOKIE_SECRET` | — | **Required.** Min 32 chars. Used to derive AES and HMAC keys. |
| `--cookie-name` | `COOKIE_NAME` | `_webauthn_proxy` | Session cookie name |
| `--cookie-domain` | `COOKIE_DOMAIN` | `` | Cookie domain (leave blank for current host) |
| `--cookie-expire` | — | `168h` | Session lifetime (7 days) |
| `--cookie-secure` | `COOKIE_SECURE` | `true` | Set `Secure` flag — disable only for HTTP dev |
| `--cookie-samesite` | — | `lax` | `lax` \| `strict` \| `none` |
| `--rp-id` | `RP_ID` | `localhost` | WebAuthn Relying Party ID — must equal the domain users access the proxy from |
| `--rp-display-name` | `RP_DISPLAY_NAME` | `WebAuthn Proxy` | Name shown in browser passkey prompts |
| `--rp-origins` | `RP_ORIGINS` | `http://localhost:4180` | Comma-separated allowed origins (`scheme://host:port`) |
| `--authenticator-attachment` | `AUTHENTICATOR_ATTACHMENT` | `` | `` (any) \| `platform` (built-in sensor) \| `cross-platform` (security key) |
| `--users-file` | `USERS_FILE` | `/data/users.json` | Path to the credential store |
| `--allow-registration` | `ALLOW_REGISTRATION` | `false` | Allow unauthenticated registration (use with `--registration-token`) |
| `--registration-token` | `REGISTRATION_TOKEN` | `` | If set, unauthenticated registration requires `?token=` in the URL |
| `--whitelist-domain` | `WHITELIST_DOMAIN` | `` | Comma-separated domains allowed as redirect targets after login |

---

## Traefik integration

### Static routes (recommended — works with rootless Podman)

Define routes in a file mounted into Traefik — no Docker socket access required.

**`traefik/dynamic/routes.yml`**
```yaml
http:
  routers:
    # Proxy UI — no auth (would loop)
    webauthn:
      rule: "PathPrefix(`/_webauthn/`) || Path(`/ping`)"
      service: webauthn-proxy
      entryPoints: [web]

    # Your protected app
    myapp:
      rule: "PathPrefix(`/app`)"
      service: myapp
      middlewares: [webauthn-auth]
      entryPoints: [web]

  middlewares:
    webauthn-auth:
      forwardAuth:
        address: "http://webauthn-proxy:4180/_webauthn/auth"
        trustForwardHeader: true
        authResponseHeaders:
          - "X-Webauthn-User"   # forwarded to your backend

  services:
    webauthn-proxy:
      loadBalancer:
        servers: [{url: "http://webauthn-proxy:4180"}]
    myapp:
      loadBalancer:
        servers: [{url: "http://myapp:8080"}]
```

**`traefik/traefik.yml`**
```yaml
entryPoints:
  web:
    address: ":8000"
api:
  insecure: true
providers:
  file:
    directory: /etc/traefik/dynamic
```

### Docker labels (requires socket access)

```yaml
# docker-compose service labels
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.myapp.rule=PathPrefix(`/app`)"
  - "traefik.http.routers.myapp.middlewares=webauthn-auth"
  - "traefik.http.middlewares.webauthn-auth.forwardauth.address=http://webauthn-proxy:4180/_webauthn/auth"
  - "traefik.http.middlewares.webauthn-auth.forwardauth.trustForwardHeader=true"
  - "traefik.http.middlewares.webauthn-auth.forwardauth.authResponseHeaders=X-Webauthn-User"
```

---

## Endpoints

| Path | Method | Auth required | Description |
|------|--------|--------------|-------------|
| `/_webauthn/auth` | GET | — | **Forward-auth endpoint** — called by Traefik |
| `/_webauthn/login` | GET | — | Login page (biometric prompt) |
| `/_webauthn/logout` | GET | — | Clear session |
| `/_webauthn/register` | GET | See bootstrap rules | Registration page |
| `/_webauthn/api/authenticate/begin` | POST | — | Start WebAuthn assertion ceremony |
| `/_webauthn/api/authenticate/finish` | POST | — | Complete ceremony, issue session |
| `/_webauthn/api/register/begin` | POST | See bootstrap rules | Start WebAuthn attestation ceremony |
| `/_webauthn/api/register/finish` | POST | — | Complete ceremony, store credential |
| `/ping` | GET | — | Health check |

---

## Audit log

Every forward-auth decision is written to stdout as a structured log line:

```
2024/01/15 10:23:45 INFO forward-auth allowed user=alice src=192.168.1.5 method=GET host=myapp.example.com uri=/dashboard
2024/01/15 10:23:47 INFO forward-auth denied src=192.168.1.99 method=POST host=myapp.example.com uri=/admin
```

Ship stdout to your log aggregator (Loki, CloudWatch, etc.) for a full access trail.

---

## Security model

- **Secure context required** — WebAuthn only works on `https://` or exactly `localhost`. Set `--proxy-url` to your public HTTPS URL in production.
- **Cookie security** — cookies are AES-256-GCM encrypted and HMAC-SHA256 signed. Set `--cookie-secure=true` (default) in production.
- **Replay protection** — authenticator sign counters are persisted and checked on every login.
- **Self-locking registration** — registration requires authentication once any credential exists. No persistent open endpoint.
- **No credential leakage** — only public keys are stored; private keys never leave the device.
- **RP ID binding** — credentials are scoped to the `--rp-id` domain and cannot be replayed on other domains.

---

## Taskfile reference

```bash
task init                  # generate .env with a random COOKIE_SECRET
task pull                  # pull third-party images (once, needs network)
task up                    # build + start full stack
task down                  # stop (keep data volume)
task destroy               # stop + wipe credentials (prompts)
task restart               # rebuild + restart proxy only
task logs                  # tail proxy logs
task create-user USER=alice  # offline user bootstrap
task list-users            # print users.json
task test                  # smoke-test the running stack
```

---

## Development

```bash
go build ./...
go test ./...

# Run locally without Docker
COOKIE_SECRET=$(openssl rand -hex 32) \
RP_ID=localhost \
RP_ORIGINS=http://localhost:4180 \
PROXY_URL=http://localhost:4180 \
USERS_FILE=/tmp/users.json \
ALLOW_REGISTRATION=true \
go run ./cmd/webauthn-proxy
```

---

## Contributing

1. Fork and create a feature branch.
2. `go build ./...` and `go vet ./...` must pass.
3. Open a pull request with a clear description of the change.

Please report security issues privately before opening a public issue.

---

## License

MIT — see [LICENSE](LICENSE).
