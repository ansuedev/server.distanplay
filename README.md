# Distanplay server

Accounts, friends and the connection handshake for Distanplay. One Rust binary
(axum + sqlx) on Postgres, built for Railway.

- **Sign in with Discord** (more providers, passwords and passkeys are ready in the schema)
- **Friends** with Discord-style usernames, requests, blocks, and per-friend permissions
  ("can connect without asking", control input, hear audio…)
- **Recents and favorites** synced across a user's devices
- **Handshake** over WebSocket: presence, connection requests with approval, a fresh
  session key + signed ticket per connection, candidate exchange for NAT hole punching,
  and a relay fallback
- **Roles & permissions** and an **audit log**, ready for a web admin

## Run locally

```bash
docker compose up -d          # Postgres 17 on localhost:55432
cp .env.example .env          # fill in secrets (see below)
set -a; . ./.env; set +a
cargo run                     # migrations run automatically on start
```

For testing without Discord, run a debug build with `DEV_LOGIN=1`: `POST /v1/auth/dev`
signs anyone in by username. It is not compiled into release builds.
The desktop app can use it with `DP_SERVER=http://localhost:8787 DP_DEV_LOGIN=yourname`.

## Discord app

1. https://discord.com/developers/applications → **New Application**.
2. **OAuth2** → copy the Client ID and Client Secret.
3. **OAuth2 → Redirects** → add `<PUBLIC_URL>/v1/auth/discord/callback`
   (e.g. `https://distanplay.up.railway.app/v1/auth/discord/callback`, and
   `http://localhost:8787/v1/auth/discord/callback` for local runs).

Scopes used: `identify email`. The server keeps only the profile (Discord id, username,
avatar, verified email) and revokes Discord's token right after reading it.

### The `/jugar` bot and invite links (optional)

`/jugar` (`/play` in English Discord) posts a **Join** button that opens Distanplay on the
friend's PC and connects them to yours:

- `/jugar @Luis @Pedro` → one link per friend, tied to *their* Discord account, single use:
  they go straight in.
- `/jugar` alone → one open link (8 uses): anyone signed in can use it and **you approve each
  person** in the app. Also `mensaje:` for a short note.
- Links last 30 minutes and only work while the host's app is online. Nothing secret is in
  them: the server checks the token (stored as a SHA-256 hash) and sets up the connection
  like a friend connection.

It's an HTTP interactions endpoint (no bot token, no gateway). Setup, in the same Discord app:

1. **General Information** → copy **Public Key** → Railway variable `DISCORD_PUBLIC_KEY`.
2. Deploy, then set **Interactions Endpoint URL** to `<PUBLIC_URL>/discord/interactions` and
   save (Discord sends a signed ping; the server answers it).
3. **Installation** → Installation Contexts: tick **User Install** and **Guild Install**
   (scope `applications.commands` for both; no bot permissions needed). Share the
   **Install Link**: on a server, or on your own account so `/jugar` works in any DM.
4. Optional: `DOWNLOAD_URL=https://…` adds a "Download Distanplay" button to invites and the
   invite page.

The server registers the command itself at start (client credentials; log line
`Discord: /jugar command registered`); `DISCORD_REGISTER_COMMANDS=0` turns that off.

The app also shows **"Playing Distanplay"** with a **Join** button on the host's Discord
profile while they share (an open invite from `POST /v1/invites`, replaced every 90 min and
revoked when sharing stops). It talks to the local Discord app over IPC with the app's client
id from `GET /v1/config`, so nothing else needs setting up; the name shown is the Discord
app's name.

## Deploy on Railway

1. New project → **Deploy from GitHub repo**, set the service's **Root Directory** to
   `webserver` (Railway builds the `Dockerfile`; `railway.json` sets the health check).
2. **+ New → Database → PostgreSQL**.
3. Service **Variables**:
   - `DATABASE_URL` = `${{Postgres.DATABASE_URL}}`
   - `PUBLIC_URL` = the service's public URL (Settings → Networking → Generate Domain)
   - `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`
   - `JWT_SECRET` = `openssl rand -base64 48`
   - `TICKET_SIGNING_KEY` = `openssl rand -base64 32` (keep it stable: apps verify tickets with its public key)
4. Deploy. `GET /healthz` should return `{"ok":true}`.
5. Build the desktop app pointing at it: `DISTANPLAY_SERVER=https://… cargo build --release`
   (or set Settings → About → Account server).

**Railway has no public UDP.** Apps learn their public UDP address from public STUN
servers (`STUN_SERVERS`) and punch through NATs directly; when that fails the media is
relayed over the WebSocket (TCP). For a UDP relay, run one on a host with UDP and set
`UDP_RELAY`.

## Sessions (how the desktop app stays signed in)

- **Access token**: JWT (HS256), 15 minutes, `Authorization: Bearer`.
- **Refresh token**: random 256-bit, stored by the app in the OS keychain and only as a
  SHA-256 hash here. **Rotated on every refresh**; expiry slides 90 days from last use, so
  an app in use stays signed in indefinitely. **Reusing an old refresh token revokes the
  whole sign-in** (theft detection, OAuth 2.0 Security BCP).
- Every request also checks the sign-in isn't revoked and the account is active, so
  sign-out, "remove device" and suspensions apply immediately.
- Desktop sign-in uses the system browser + polling with a secret only the app knows
  (no custom URL scheme or local web server; an intercepted browser redirect is useless
  without it).

## API (v1)

| | |
|---|---|
| `POST /auth/discord/start` · `GET /auth/discord/callback` · `POST /auth/poll` | Sign in with Discord |
| `POST /auth/refresh` · `POST /auth/logout` · `GET/DELETE /auth/sessions[/{id}]` | Sessions |
| `GET/PATCH /me` · `GET /me/devices` · `PATCH/DELETE /me/devices/{id}` | Profile & devices |
| `GET /users/by-username/{name}` | Exact lookup |
| `GET /friends` · `POST /friends/requests` · `POST /friends/{id}/accept` · `DELETE /friends/{id}` | Friends |
| `PUT /friends/{id}/permissions` · `GET /blocks` · `PUT/DELETE /blocks/{id}` | Permissions & blocks |
| `GET/POST /recents` · `DELETE /recents/{id}` · `GET/POST /favorites` · `PUT /favorites/order` · `DELETE /favorites/{id}` · `GET /history` | Library |
| `POST /invites` · `GET /invites/{token}` · `DELETE /invites/{id}` | Invite links (open invite for the calling device, preview, revoke) |
| `GET /j/{token}` · `POST /discord/interactions` | Invite page (opens the app) · the `/jugar` bot |
| `GET /ws` | Live hub (below) |
| `GET /config` | STUN servers, relay options, ticket public key |
| `GET /admin/users` · `PUT /admin/users/{id}/status` · `POST/DELETE /admin/users/{id}/roles` · `GET /admin/live` | Admin (permission-checked) |

### Presence

Each signed-in app keeps one WebSocket open (`/v1/ws`, pings every 25 s; the server drops
it after 75 s of silence). A device that disconnects still shows online for **60 s**
(Wi-Fi blips and app restarts don't flicker); after that friends get a `presence`
offline event and `GET /friends` returns `online: false` with `last_seen_ago_secs`.
`users.last_seen_at` / `devices.last_seen_at` are updated on connect, disconnect and
once a minute while connected.

### Hub messages (`/v1/ws`, JSON)

App → server: `connect {device_id}`, `connect_code {code, password}`, `connect_invite {token}`
(`connect_failed` reasons for invites: `not_found`, `expired`, `used`, `revoked`,
`not_for_you`, `self`, `offline`), `cancel {request_id}`, `respond {request_id, accept}`,
`candidates {session_id, candidates:[{addr, kind}]}`, `relay {session_id}`,
`route {session_id, route}`, `end {session_id}`, `ping`. Binary frames
`[16-byte session id][payload]` are relayed once both sides sent `relay`.

Server → app: `hello`, `presence`, `friends_changed`, `incoming`, `request_sent`,
`request_canceled`, `connect_failed {reason}`, `session {role, peer, session_key, ticket,
permissions, stun, relay}`, `candidates`, `relay_ready`, `session_end`, `pong`.

## Database

`migrations/` (applied on start):

- **Identity**: `users` (citext `username` with Discord rules, `display_name`, email, status),
  `user_identities` (Discord now; Google/Apple/Microsoft/GitHub/Steam ready),
  `user_passwords`, `user_passkeys`, `email_tokens`
- **Sessions**: `devices`, `auth_sessions` (rotating refresh-token families), `login_requests`
- **Social**: `friendships` (one row per pair), `user_blocks`, `friend_permissions`
- **Connections**: `connection_requests`, `connection_sessions` (route, relayed bytes)
- **Library**: `recent_connections`, `favorites` (a friend's device or a raw code/address)
- **Invites**: `invites` (token hash, host device, optional Discord id it's for, uses, expiry)
- **Admin**: `roles`, `permissions`, `role_permissions`, `user_roles`, `user_permissions`
  (per-user allow/deny), `audit_log`. Seeded roles: admin, moderator, support, user.

Make yourself admin after your first sign-in:

```sql
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r WHERE u.username = 'yourname' AND r.key = 'admin';
```
# server.distanplay
