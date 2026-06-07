# Remote Database Setup — WireGuard Tunnel to VPS

Enable multi-user collaboration by sharing a single Postgres instance on a cloud VPS, accessed securely via WireGuard tunnel.

## Architecture

```
LOCAL MACHINE                              REMOTE VPS
+----------------------------+             +----------------------------+
| docker-compose.yml         |             | WireGuard Server           |
|  + remote-db.yml overlay   |             |   10.13.13.1/24            |
|                            |             |                            |
| [25+ services]             |             | PostgreSQL 16 (pgvector)   |
|    |  resolve "rag-postgres"             |   listen: lo + wg0         |
|    v                       |             |                            |
| [wireguard container]      |             | PgBouncer (port 6432)      |
|   alias: rag-postgres      |             |   transaction pooling      |
|   10.13.13.2/24            |             +----------------------------+
|    |                       |                        ^
| [db-proxy (socat)]         |                        |
|   shares wireguard netns   |                        |
|   TCP 5432 -> VPS:5432     ---- wg0 UDP 51820 -----+
+----------------------------+
```

**Zero code changes**: The wireguard container gets network alias `rag-postgres` on `agents_net`. The socat proxy shares its network namespace and listens on port 5432, forwarding to the VPS. All services resolve `rag-postgres:5432` transparently.

## Prerequisites

### Local Machine (where you run the stack)

Install WireGuard tools (needed for key generation only — the tunnel itself runs in Docker):

```bash
# Ubuntu / Debian / WSL2
sudo apt install wireguard-tools

# macOS
brew install wireguard-tools

# Windows (if not using WSL2)
# Download from https://www.wireguard.com/install/
```

### Remote VPS

- Ubuntu 22.04 or 24.04 (recommended)
- Root / sudo access
- Public IP address
- UDP port 51820 open in cloud provider firewall (AWS Security Group, DigitalOcean Firewall, etc.)

## Mode Toggle

| Mode | Command | Use case |
|------|---------|----------|
| **Local** (default) | `docker compose up -d` | Solo pentesting, local DB |
| **Remote** | `docker compose -f docker-compose.yml -f docker-compose.remote-db.yml up -d` | Team collaboration, shared DB |

## Quick Start

### Step 1: Provision VPS

**Run on: REMOTE VPS** (via SSH)

```bash
# From your LOCAL machine, copy files to VPS
scp scripts/optional/vps/setup-remote-db.sh root@<VPS_IP>:/tmp/
scp db_init/ensure_all_tables.sql root@<VPS_IP>:/tmp/

# SSH to VPS and run setup
ssh root@<VPS_IP>
REMOTE_DB_PASSWORD='YourStrongPassword' bash /tmp/setup-remote-db.sh
```

The script installs WireGuard, PostgreSQL 16, pgvector, PgBouncer, and configures UFW.

**Save the server public key** from the output — you'll need it in Step 3.

### Step 2: Generate Client Keys

**Run on: YOUR HOST MACHINE** (your laptop/desktop terminal, NOT inside a Docker container)

```bash
# Install wireguard-tools if not already installed (see Prerequisites above)
# Then generate keys for your machine:
./scripts/optional/vps/wg-genkeys.sh alice 10.13.13.2
```

This creates:
- `wireguard/alice_private.key` — your private key (never share)
- `wireguard/alice_public.key` — your public key (give to VPS admin)
- `wireguard/wg0.conf` — client config template (needs editing)

The script also prints a `[Peer]` block — copy it for Step 4.

### Step 3: Edit Client Config

**Run on: YOUR HOST MACHINE** (your laptop/desktop terminal, NOT inside a Docker container)

Edit `wireguard/wg0.conf` and replace the two placeholders:

```
[Peer]
PublicKey = <SERVER_PUBLIC_KEY>    <-- replace with VPS server pubkey from Step 1
Endpoint = <VPS_PUBLIC_IP>:51820  <-- replace with your VPS public IP
```

### Step 4: Add Peer on VPS

**Run on: REMOTE VPS** (via SSH)

Add the `[Peer]` block (printed in Step 2) to the VPS WireGuard config:

```bash
# Edit the VPS config
nano /etc/wireguard/wg0.conf

# Add the [Peer] block at the end:
# [Peer]
# # alice
# PublicKey = <alice's public key>
# AllowedIPs = 10.13.13.2/32

# Reload without downtime:
wg syncconf wg0 <(wg-quick strip wg0)

# Verify the peer is listed:
wg show
```

### Step 5: Configure .env

**Run on: YOUR HOST MACHINE** (your laptop/desktop terminal, NOT inside a Docker container)

Add to your `.env` file:

```bash
WG_SERVER_IP=10.13.13.1
REMOTE_DB_PORT=5432
REMOTE_DB_USER=app
REMOTE_DB_PASSWORD=YourStrongPassword
```

### Step 6: Start in Remote Mode

**Run on: YOUR HOST MACHINE** (your laptop/desktop terminal, NOT inside a Docker container)

```bash
docker compose -f docker-compose.yml -f docker-compose.remote-db.yml up -d
```

### Step 7: Verify

**Run on: YOUR HOST MACHINE** (your laptop/desktop terminal, NOT inside a Docker container)

```bash
./scripts/optional/test-remote-db.sh
```

This checks: WireGuard container health, tunnel ping, TCP connectivity, database access, and pgvector extension.

## Migrating Existing Data

**Run on: YOUR HOST MACHINE** (your laptop/desktop terminal, NOT inside a Docker container)

To copy your local database to the remote VPS:

```bash
# Ensure local DB and wireguard are running
docker compose up -d rag-postgres
docker compose -f docker-compose.yml -f docker-compose.remote-db.yml up -d wireguard db-proxy

# Run migration
./scripts/optional/migrate-db-to-remote.sh
```

Dumps are saved in `backups/` for safety.

## Adding Team Members

**Key generation: on each TEAM MEMBER'S LOCAL MACHINE**
**Peer config: on REMOTE VPS**

Each team member needs their own WireGuard keypair with a unique IP:

```bash
# On team member's machine (requires wireguard-tools installed):
./scripts/optional/vps/wg-genkeys.sh bob 10.13.13.3
./scripts/optional/vps/wg-genkeys.sh charlie 10.13.13.4
```

Then on the VPS, add each member's `[Peer]` block and reload:
```bash
# On VPS:
wg syncconf wg0 <(wg-quick strip wg0)
```

To **revoke access**: remove the peer block from VPS config and reload.

## Offline Sync Workflow

Once remote DB is set up, team members can work offline and sync:

1. **Pull snapshot**: `POST /sync/snapshot` or use the Sync Dashboard (`/sync`)
2. **Switch to local mode**: `docker compose up -d` (stops using remote)
3. **Work offline** — all changes tracked in `sync_log` via triggers
4. **Reconnect**: switch back to remote mode
5. **Push changes**: `./scripts/optional/sync-push.sh my-node`
6. **Pull teammates' changes**: `./scripts/optional/sync-pull.sh my-node`
7. **Resolve conflicts**: Sync Dashboard > Conflicts tab

See the Sync Dashboard in the UI under System > Sync for visual management.

## Security Notes

- Postgres only listens on `127.0.0.1` + `10.13.13.1` (WireGuard interface) — never public
- `scram-sha-256` password authentication
- WireGuard keys/configs excluded from git (`.gitignore`)
- PgBouncer limits connection exhaustion (200 max, 25 per-pool)
- UFW blocks direct Postgres access from internet
- Each team member gets a unique WireGuard keypair

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `wg: command not found` | Install wireguard-tools: `sudo apt install wireguard-tools` (Ubuntu) or `brew install wireguard-tools` (macOS) |
| Services can't connect to DB | Check `docker logs rag-wireguard` and `docker logs rag-db-proxy` |
| Ping fails through tunnel | Verify peer configs match on both sides, check VPS `wg show` for handshake time |
| "connection refused" on :5432 | Ensure db-proxy (socat) is running: `docker ps \| grep db-proxy` |
| Slow queries | Check PgBouncer stats: `psql -h 10.13.13.1 -p 6432 -U app pgbouncer -c "SHOW POOLS"` |
| Need to switch back to local | Just `docker compose up -d` (without the overlay file) |

## File Reference

| File | Run Where | Purpose |
|------|-----------|---------|
| `docker-compose.remote-db.yml` | Local | Compose overlay: disables local PG, adds WG + socat |
| `scripts/optional/vps/setup-remote-db.sh` | VPS | Provisions WG + PG16 + pgvector + PgBouncer + UFW |
| `scripts/optional/vps/wg-genkeys.sh` | Local | Generates WireGuard client keypair + config template |
| `scripts/optional/migrate-db-to-remote.sh` | Local | pg_dump local → pg_restore to remote via WG tunnel |
| `scripts/optional/test-remote-db.sh` | Local | Connectivity verification |
| `scripts/optional/sync-push.sh` | Local | Push local changes to remote DB |
| `scripts/optional/sync-pull.sh` | Local | Pull remote changes to local DB |
| `wireguard/wg0.conf` | Local | WireGuard client config (gitignored) |
