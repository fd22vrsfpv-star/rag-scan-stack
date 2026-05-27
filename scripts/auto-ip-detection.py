#!/usr/bin/env python3
"""
Auto IP Detection and Update Script
Prevents stale IP addresses in node metadata by detecting current accessible IPs
"""

import psycopg2
import subprocess
import json
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

def test_ssh_connectivity(host, user, key_file, port=22):
    """Test if SSH connection works to a given host"""
    try:
        cmd = [
            'ssh', '-i', f'/ssh-keys/{key_file}',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'ConnectTimeout=5',
            '-o', 'BatchMode=yes',
            f'{user}@{host}',
            'echo test'
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False

def fix_node_ip(node_name):
    """Fix IP address for a specific node"""
    conn = get_db_connection()
    cur = conn.cursor()

    # Get node metadata
    cur.execute('SELECT metadata, hostname FROM remote_nodes WHERE name = %s', (node_name,))
    result = cur.fetchone()

    if not result:
        print(f"Node {node_name} not found")
        return False

    metadata, hostname = result
    current_host = metadata.get('host')
    reserved_ip = metadata.get('reserved_ip')
    user = metadata.get('user', 'root')
    key_file = metadata.get('key_file', 'id_rsa')

    print(f"Checking node: {node_name}")
    print(f"  Current host: {current_host}")
    print(f"  Reserved IP: {reserved_ip}")
    print(f"  Hostname: {hostname}")

    # Test connectivity to different IPs
    ips_to_test = []
    if current_host:
        ips_to_test.append(('current_host', current_host))
    if reserved_ip:
        ips_to_test.append(('reserved_ip', reserved_ip))
    if hostname and hostname not in [current_host, reserved_ip]:
        ips_to_test.append(('hostname', hostname))

    working_ip = None
    for ip_type, ip_addr in ips_to_test:
        if ip_addr:
            print(f"  Testing {ip_type} ({ip_addr})...")
            if test_ssh_connectivity(ip_addr, user, key_file):
                print(f"    ✅ {ip_addr} works!")
                working_ip = ip_addr
                break
            else:
                print(f"    ❌ {ip_addr} failed")

    if working_ip and working_ip != current_host:
        # Update metadata with working IP
        metadata['host'] = working_ip
        cur.execute('''
            UPDATE remote_nodes
            SET metadata = %s,
                updated_at = %s
            WHERE name = %s
        ''', (json.dumps(metadata), datetime.utcnow(), node_name))

        conn.commit()
        print(f"  ✅ Updated {node_name}: {current_host} -> {working_ip}")

        # Also update hostname if it was different
        if hostname != working_ip:
            cur.execute('''
                UPDATE remote_nodes
                SET hostname = %s
                WHERE name = %s
            ''', (working_ip, node_name))
            conn.commit()
            print(f"  ✅ Updated hostname: {hostname} -> {working_ip}")

        cur.close()
        conn.close()
        return True

    elif working_ip == current_host:
        print(f"  ✅ {node_name} already has correct IP")
        cur.close()
        conn.close()
        return True

    else:
        print(f"  ❌ No working IP found for {node_name}")
        cur.close()
        conn.close()
        return False

def fix_all_nodes():
    """Fix IP addresses for all nodes"""
    conn = get_db_connection()
    cur = conn.cursor()

    # Get all nodes with metadata
    cur.execute('''
        SELECT name FROM remote_nodes
        WHERE metadata IS NOT NULL
        AND metadata ? 'host'
        ORDER BY name
    ''')

    nodes = [row[0] for row in cur.fetchall()]
    cur.close()
    conn.close()

    if not nodes:
        print("No nodes found with IP metadata")
        return

    print(f"Found {len(nodes)} nodes to check: {', '.join(nodes)}")
    print("-" * 60)

    fixed_count = 0
    for node_name in nodes:
        if fix_node_ip(node_name):
            fixed_count += 1
        print("-" * 40)

    print(f"\nSummary: Fixed {fixed_count}/{len(nodes)} nodes")

def main():
    if len(sys.argv) == 1:
        # Fix all nodes
        fix_all_nodes()
    elif len(sys.argv) == 2:
        # Fix specific node
        node_name = sys.argv[1]
        if fix_node_ip(node_name):
            print(f"Successfully fixed {node_name}")
        else:
            print(f"Failed to fix {node_name}")
            sys.exit(1)
    else:
        print("Usage:")
        print(f"  {sys.argv[0]}           # Fix all nodes")
        print(f"  {sys.argv[0]} <node>    # Fix specific node")

if __name__ == "__main__":
    main()