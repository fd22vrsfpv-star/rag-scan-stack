from typing import Optional
import httpx
from fastapi import APIRouter, HTTPException
from config import get_settings

router = APIRouter()

@router.get("/api/maintenance/nodes/analysis")
async def analyze_nodes():
    """Analyze nodes for cleanup opportunities."""
    s = get_settings()

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            # Get nodes
            nodes_resp = await client.get(f"{s.tunnel_manager_url}/nodes")
            nodes_resp.raise_for_status()
            nodes = nodes_resp.json().get("nodes", [])

            # Get WireGuard peers
            wg_resp = await client.get(f"{s.tunnel_manager_url}/api/wg/peers")
            wg_resp.raise_for_status()
            peers = wg_resp.json().get("peers", [])

        # Analyze for cleanup opportunities
        analysis = {
            "total_nodes": len(nodes),
            "offline_nodes": [n for n in nodes if n.get("status") == "offline"],
            "error_nodes": [n for n in nodes if n.get("status") == "error"],
            "stale_nodes": [n for n in nodes if n.get("status") in ["offline", "error"]],
            "total_wg_peers": len(peers),
            "inactive_wg_peers": [p for p in peers if p.get("status") == "inactive"],
            "duplicate_ips": _find_duplicate_ips(nodes),
            "orphaned_wg_peers": _find_orphaned_peers(nodes, peers),
        }

        # Add counts for easy reference
        analysis.update({
            "offline_count": len(analysis["offline_nodes"]),
            "error_count": len(analysis["error_nodes"]),
            "stale_count": len(analysis["stale_nodes"]),
            "inactive_wg_count": len(analysis["inactive_wg_peers"]),
            "duplicate_count": len(analysis["duplicate_ips"]),
            "orphaned_count": len(analysis["orphaned_wg_peers"]),
        })

        return analysis

    except httpx.RequestError as e:
        raise HTTPException(500, f"Failed to analyze nodes: {str(e)}")


@router.post("/api/maintenance/nodes/cleanup")
async def cleanup_nodes(cleanup_options: dict):
    """Execute node cleanup operations based on selected options."""
    s = get_settings()
    results = {"success": [], "failed": [], "summary": ""}

    try:
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            # Get current analysis
            analysis_resp = await client.get(f"{s.bff_base_url}/api/maintenance/nodes/analysis")
            analysis_resp.raise_for_status()
            analysis = analysis_resp.json()

            # Cleanup offline nodes
            if cleanup_options.get("remove_offline", False):
                for node in analysis["offline_nodes"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/nodes/{node['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed offline node: {node['name']}")
                        else:
                            results["failed"].append(f"Failed to remove offline node {node['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing offline node {node['name']}: {str(e)}")

            # Cleanup error nodes
            if cleanup_options.get("remove_error", False):
                for node in analysis["error_nodes"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/nodes/{node['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed error node: {node['name']}")
                        else:
                            results["failed"].append(f"Failed to remove error node {node['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing error node {node['name']}: {str(e)}")

            # Cleanup inactive WireGuard peers
            if cleanup_options.get("remove_inactive_wg", False):
                for peer in analysis["inactive_wg_peers"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/api/wg/peers/{peer['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed inactive WG peer: {peer['name']}")
                        else:
                            results["failed"].append(f"Failed to remove inactive WG peer {peer['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing inactive WG peer {peer['name']}: {str(e)}")

            # Cleanup orphaned peers (peers without corresponding nodes)
            if cleanup_options.get("remove_orphaned_wg", False):
                for peer in analysis["orphaned_wg_peers"]:
                    try:
                        resp = await client.delete(f"{s.tunnel_manager_url}/api/wg/peers/{peer['id']}")
                        if resp.status_code == 200:
                            results["success"].append(f"Removed orphaned WG peer: {peer['name']}")
                        else:
                            results["failed"].append(f"Failed to remove orphaned WG peer {peer['name']}: {resp.text}")
                    except Exception as e:
                        results["failed"].append(f"Error removing orphaned WG peer {peer['name']}: {str(e)}")

            # Generate summary
            success_count = len(results["success"])
            failed_count = len(results["failed"])
            results["summary"] = f"Cleanup completed: {success_count} successful, {failed_count} failed"

            return results

    except httpx.RequestError as e:
        raise HTTPException(500, f"Cleanup operation failed: {str(e)}")


def _find_duplicate_ips(nodes: list) -> list:
    """Find nodes with duplicate IP assignments."""
    ip_map = {}
    duplicates = []

    for node in nodes:
        wg_ip = node.get("wg_assigned_ip")
        if wg_ip:
            if wg_ip in ip_map:
                # Mark both as duplicates
                if ip_map[wg_ip] not in duplicates:
                    duplicates.append(ip_map[wg_ip])
                duplicates.append(node)
            else:
                ip_map[wg_ip] = node

    return duplicates


def _find_orphaned_peers(nodes: list, peers: list) -> list:
    """Find WireGuard peers without corresponding nodes."""
    node_ids = {node["id"] for node in nodes}
    return [peer for peer in peers if peer["id"] not in node_ids]