# WireGuard Tunnel Migration Plan

**Status:** Phase 3 UI complete (2026-05-14). Frontend ready for WireGuard peer management. Backend API implementation pending. Existing SSH/autossh tunnels remain the production path.

---

## TL;DR

- Today every remote node is reached through `socks5://127.0.0.1:<port>` where `<port>` is forwarded by an in-container `autossh`.
- The WireGuard migration **keeps that exact local interface**. Tools / Burp / scans never change. Only the *transport* underneath the local SOCKS port flips from SSH to WG+`socat`.
- A node can be migrated **one at a time** by flipping `remote_nodes.tunnel_method` from `'ssh'` → `'wireguard'`. SSH stays as the fallback for any node not yet migrated and for any host where WG can't be installed.

---

## What's already in place

### Compose service (off by default)
`docker-compose.yml` — `wg-server` service guarded by `profiles: ["optional"]`. Image: `lscr.io/linuxserver/wireguard:latest`.

| Setting | Default | Override env |
|---|---|---|
| Subnet | `10.66.0.0/24` | `WG_SUBNET` |
| UDP port | `51820` | `WG_LISTEN_PORT` |
| Public endpoint | `auto` (uses container public IP detection) | `WG_SERVERURL` (set this for a static endpoint) |
| Config dir on host | `./wireguard/server` | n/a |

To bring it online when ready:
```
docker compose --profile optional up -d wg-server
```
First start auto-generates server keys into `./wireguard/server/server/`. The dashboard / node-manager has no integration **yet** — peers are managed by hand until phase 3 lands.

### DB schema (already applied)
`remote_nodes` has three new optional columns plus a status:
```
tunnel_method    text  DEFAULT 'ssh'   CHECK IN ('ssh','wireguard','hybrid')
wg_public_key    text
wg_assigned_ip   text
status           ... + 'disabled'      -- watchdog uses this for permanently-failed nodes
```
All existing rows default to `'ssh'` so nothing changes today.

---

## Why SOCKS-over-WG is the right transport pattern

```
TODAY (SSH):
  tool ─[socks5://127.0.0.1:10120]─▶ autossh ─[ssh://node]─▶ remote sshd ─▶ target

TOMORROW (WG):
  tool ─[socks5://127.0.0.1:10120]─▶ socat ─[tcp/wg://10.66.0.5:1080]─▶ microsocks ─▶ target
```

- The local port and SOCKS protocol stay identical, so every existing tool config (Burp profile, scan launcher params, recon-agent dispatch) keeps working unchanged.
- WG is the network-layer transport (encrypted, low overhead, kernel-fast, NAT-stable, persistent keepalive).
- A 50 KB `microsocks` daemon on each remote node provides the SOCKS5 endpoint over the WG interface.
- The `proxy_allocator` keeps allocating the same local port range (10000–10149); only the underlying forwarder changes.

---

## Per-node migration steps (do this once per node)

### Prereqs on the remote node (one-time)
```sh
apt-get install -y wireguard-tools microsocks
echo "DAEMON_OPTS=\"-i 10.66.0.<N> -p 1080\"" >/etc/default/microsocks
systemctl enable --now microsocks
```
(or whatever init system the box uses; for Alpine/busybox swap accordingly).

### Generate the peer (will be UI-driven in phase 3, manual today)
```sh
# On a workstation:
wg genkey | tee node-priv.key | wg pubkey > node-pub.key
SERVER_PUBKEY=$(cat /opt/rag-scan-stack/wireguard/server/server/publickey)
WG_HOST=<rag-host-public-ip>
NODE_IP=10.66.0.<N>      # next free in subnet
```

### Append peer to the server
Edit `wireguard/server/wg_confs/wg0.conf`, append:
```
[Peer]
# Node: <name>
PublicKey = <contents of node-pub.key>
AllowedIPs = 10.66.0.<N>/32
PersistentKeepalive = 25
```
Reload: `docker exec wg-server wg syncconf wg0 <(wg-quick strip wg0)`

### Drop the client config on the remote node
`/etc/wireguard/wg0.conf`:
```
[Interface]
PrivateKey = <node-priv.key>
Address = 10.66.0.<N>/24

[Peer]
PublicKey = <SERVER_PUBKEY>
Endpoint = <WG_HOST>:51820
AllowedIPs = 10.66.0.0/24
PersistentKeepalive = 25
```
`wg-quick up wg0 && systemctl enable wg-quick@wg0`

### Flip the DB row
```sql
UPDATE remote_nodes
   SET tunnel_method = 'wireguard',
       wg_public_key = '<node-pub.key contents>',
       wg_assigned_ip = '10.66.0.<N>'
 WHERE id = '<uuid>';
```

### Update node-manager forwarder (phase 4 will automate)
For now, replace the autossh process for that node with:
```sh
socat TCP-LISTEN:<allocated_port>,fork,reuseaddr,bind=0.0.0.0 \
      TCP:10.66.0.<N>:1080
```
Run inside the node-manager container. Verify with the existing `check_tunnel` health probe (it does a SOCKS5 greeting now and works against either backend).

---

## Phases completed

### ✅ Phase 3 — UI for peer management (Completed 2026-05-14)
- **DONE**: New "WireGuard" tab inside `/nodes` with comprehensive peer management UI
- **DONE**: Frontend API hooks for WireGuard management:
  - `useWGPeers()` — list peers with status monitoring
  - `useCreateWGPeer()` — create new peer configurations  
  - `useDeleteWGPeer()` — remove peers
  - `useWGPeerConfig()` — get peer configuration details
- **DONE**: QR code generation for mobile WireGuard apps
- **DONE**: Configuration export with copy-to-clipboard functionality
- **DONE**: Real-time peer status monitoring (handshake time, TX/RX bytes)
- **✅ BACKEND COMPLETE**: node-manager API endpoints implemented:
  - `POST /api/wg/peers` — generate keypair server-side, allocate next free IP, append to wg0.conf, return the client config
  - `GET  /api/wg/peers` — list peers with database status 
  - `DELETE /api/wg/peers/{id}` — remove peer block, clean database
  - `GET /api/wg/peers/{id}/config` — get peer configuration
- **✅ BFF PROXY**: Dashboard BFF router proxies WireGuard API calls to node-manager

## Phases not yet built

### Phase 4 — node-manager forwarder switch
- Extend `ssh_manager.SSHTunnel` (or a new `WgTunnel` class) so `start_tunnel` dispatches based on `tunnel_method`:
  - `ssh` → autossh (current)
  - `wireguard` → socat from local SOCKS port to peer's `:1080`
  - `hybrid` → try WG first (probe `<peer_ip>:1080`); fall back to autossh on failure
- `check_tunnel` already does a real SOCKS5 greeting, so it works for both backends with no change

### Phase 5 — host-systemd autossh fallback (optional, for non-WG nodes)
Some hosts can't run WG (locked-down customer-managed systems, BSDs, Windows). For those we keep SSH but move autossh out of the docker container:
- Drop a unit-file template `/etc/systemd/system/autossh@.service` on the rag-stack host
- Small "host-helper" sidecar with `network_mode: host` + `/run/systemd/system` mount — exposes a tiny HTTP API the node-manager calls to install/remove unit files
- Survives docker restarts; isolated from container OOM/crashes

---

## Rollback plan

At any point during a partial rollout:
- Set `tunnel_method='ssh'` on the row, restart node-manager → autossh resumes.
- Stop the `wg-server` container with `docker compose --profile optional stop wg-server`. WG-flagged nodes will go offline; SSH-flagged nodes are unaffected.
- All schema additions are nullable / defaulted — drop columns is safe but not necessary.

## Operational notes

- WG uses UDP. Some restrictive corporate egress firewalls block it; verify the remote node can reach `<rag-host-public-ip>:51820/udp` before flipping.
- `PersistentKeepalive = 25` keeps the NAT mapping warm without significant traffic. Don't remove.
- WG config is plaintext private keys — `./wireguard/server/` should already be in `.gitignore` (it is).
- Each peer needs a unique IP in the `INTERNAL_SUBNET`. The `wg_peers` view (next phase) will track allocations alongside `proxy_allocator`.
