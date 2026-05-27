#!/usr/bin/env python3
"""
Reset WireGuard Installation Status
Resets stuck WireGuard peer installations back to 'not_attempted' status
"""

import psycopg2
import sys
import os
from datetime import datetime

def get_db_connection():
    """Get database connection using environment variables"""
    try:
        return psycopg2.connect(
            host=os.getenv('POSTGRES_HOST', 'localhost'),
            database=os.getenv('POSTGRES_DB', 'scans'),
            user=os.getenv('POSTGRES_USER', 'app'),
            password=os.getenv('POSTGRES_PASSWORD', 'app'),
            port=os.getenv('POSTGRES_PORT', 5432)
        )
    except Exception as e:
        print(f"Database connection failed: {e}")
        sys.exit(1)

def list_wireguard_peers():
    """List all WireGuard peers and their installation status"""
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT id, name, hostname, installation_status, created_at,
               array_length(installation_logs, 1) as log_count
        FROM remote_nodes
        WHERE wg_public_key IS NOT NULL
        ORDER BY created_at DESC
    """)

    peers = cur.fetchall()
    cur.close()
    conn.close()

    if not peers:
        print("No WireGuard peers found")
        return []

    print("WireGuard Peers:")
    print("-" * 80)
    print(f"{'ID':<8} {'Name':<15} {'Hostname':<20} {'Status':<12} {'Logs':<6} {'Created'}")
    print("-" * 80)

    for peer in peers:
        peer_id, name, hostname, status, created_at, log_count = peer
        created_str = created_at.strftime("%Y-%m-%d %H:%M") if created_at else "N/A"
        log_count_str = str(log_count) if log_count else "0"
        print(f"{peer_id[:8]:<8} {name:<15} {hostname or 'N/A':<20} {status:<12} {log_count_str:<6} {created_str}")

    return peers

def reset_peer_installation(peer_id, reset_logs=True):
    """Reset a specific peer's installation status"""
    conn = get_db_connection()
    cur = conn.cursor()

    # Get peer info first
    cur.execute("SELECT name, installation_status FROM remote_nodes WHERE id = %s", (peer_id,))
    result = cur.fetchone()

    if not result:
        print(f"Peer {peer_id} not found")
        cur.close()
        conn.close()
        return False

    name, current_status = result
    print(f"Resetting installation status for peer '{name}' (current: {current_status})")

    if reset_logs:
        cur.execute("""
            UPDATE remote_nodes
            SET installation_status = 'not_attempted',
                installation_logs = '{}'
            WHERE id = %s
        """, (peer_id,))
        print("✓ Reset status to 'not_attempted' and cleared logs")
    else:
        cur.execute("""
            UPDATE remote_nodes
            SET installation_status = 'not_attempted'
            WHERE id = %s
        """, (peer_id,))
        print("✓ Reset status to 'not_attempted' (logs preserved)")

    conn.commit()
    cur.close()
    conn.close()
    return True

def reset_all_pending(reset_logs=True):
    """Reset all peers with 'pending' status"""
    conn = get_db_connection()
    cur = conn.cursor()

    # Find all pending peers
    cur.execute("""
        SELECT id, name FROM remote_nodes
        WHERE wg_public_key IS NOT NULL AND installation_status = 'pending'
    """)

    pending_peers = cur.fetchall()

    if not pending_peers:
        print("No peers with 'pending' status found")
        cur.close()
        conn.close()
        return 0

    print(f"Found {len(pending_peers)} peers with 'pending' status")

    for peer_id, name in pending_peers:
        print(f"  - {name} ({peer_id[:8]})")

    confirm = input(f"\nReset {len(pending_peers)} pending installations? [y/N]: ")
    if confirm.lower() != 'y':
        print("Cancelled")
        cur.close()
        conn.close()
        return 0

    if reset_logs:
        cur.execute("""
            UPDATE remote_nodes
            SET installation_status = 'not_attempted',
                installation_logs = '{}'
            WHERE wg_public_key IS NOT NULL AND installation_status = 'pending'
        """)
    else:
        cur.execute("""
            UPDATE remote_nodes
            SET installation_status = 'not_attempted'
            WHERE wg_public_key IS NOT NULL AND installation_status = 'pending'
        """)

    conn.commit()
    count = cur.rowcount
    cur.close()
    conn.close()

    print(f"✓ Reset {count} peer installations")
    return count

def main():
    if len(sys.argv) == 1:
        # No arguments - list peers
        list_wireguard_peers()
        print("\nUsage:")
        print(f"  {sys.argv[0]} list                    - List all WireGuard peers")
        print(f"  {sys.argv[0]} reset <peer_id>         - Reset specific peer installation")
        print(f"  {sys.argv[0]} reset-all-pending       - Reset all pending installations")
        print(f"  {sys.argv[0]} reset-all-pending --keep-logs  - Reset but preserve logs")
        return

    command = sys.argv[1]

    if command == "list":
        list_wireguard_peers()

    elif command == "reset" and len(sys.argv) >= 3:
        peer_id = sys.argv[2]
        keep_logs = "--keep-logs" in sys.argv
        reset_peer_installation(peer_id, reset_logs=not keep_logs)

    elif command == "reset-all-pending":
        keep_logs = "--keep-logs" in sys.argv
        reset_all_pending(reset_logs=not keep_logs)

    else:
        print("Invalid command")
        print("Usage:")
        print(f"  {sys.argv[0]} list")
        print(f"  {sys.argv[0]} reset <peer_id> [--keep-logs]")
        print(f"  {sys.argv[0]} reset-all-pending [--keep-logs]")

if __name__ == "__main__":
    main()