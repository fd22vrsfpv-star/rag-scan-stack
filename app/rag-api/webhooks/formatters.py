"""
Payload formatters for different webhook destinations.

Supports:
- Generic JSON format (default)
- Slack Block Kit format (auto-detected by URL)
- Discord webhook format (auto-detected by URL)
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional


def is_slack_webhook(url: str) -> bool:
    """Check if URL is a Slack webhook."""
    return "hooks.slack.com" in url


def is_discord_webhook(url: str) -> bool:
    """Check if URL is a Discord webhook."""
    return "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url


def get_severity_emoji(severity: str) -> str:
    """Get emoji for severity level."""
    return {
        "critical": "\U0001F534",  # Red circle
        "high": "\U0001F7E0",      # Orange circle
        "medium": "\U0001F7E1",    # Yellow circle
        "low": "\U0001F7E2",       # Green circle
        "info": "\U0001F535",      # Blue circle
    }.get(severity.lower(), "\u26AA")  # White circle for unknown


def get_severity_color(severity: str) -> str:
    """Get hex color for severity level (for Slack/Discord)."""
    return {
        "critical": "#FF0000",
        "high": "#FF6600",
        "medium": "#FFCC00",
        "low": "#00CC00",
        "info": "#0066FF",
    }.get(severity.lower(), "#808080")


def format_generic(event_type: str, source: str, data: Dict[str, Any], severity: Optional[str] = None) -> Dict[str, Any]:
    """
    Format payload as generic JSON with source-prefixed event type.

    Returns:
        {
            "event": "nuclei_scan_completed",  # Source-prefixed for easy identification
            "event_type": "scan_completed",    # Original event type (for filtering)
            "timestamp": "2026-02-01T12:00:00Z",
            "source": "nuclei",
            "severity": "high",  # if applicable
            "data": { ... }
        }
    """
    # Create source-prefixed event name for clear identification
    source_event = f"{source}_{event_type}"
    payload = {
        "event": source_event,
        "event_type": event_type,  # Keep original for backward compatibility
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "data": data,
    }
    if severity:
        payload["severity"] = severity
    return payload


def format_slack(event_type: str, source: str, data: Dict[str, Any], severity: Optional[str] = None) -> Dict[str, Any]:
    """
    Format payload as Slack Block Kit message.

    Returns Slack blocks format for rich messages.
    """
    blocks = []
    source_upper = source.upper()

    # Header based on event type - include source for clarity
    if event_type.startswith("finding_"):
        sev = severity or event_type.split("_")[-1]
        emoji = get_severity_emoji(sev)
        header_text = f"{emoji} [{source_upper}] {sev.upper()} Finding"
    elif event_type == "scan_completed":
        header_text = f"\u2705 [{source_upper}] Scan Completed"
    elif event_type == "scan_started":
        header_text = f"\U0001F680 [{source_upper}] Scan Started"
    elif event_type == "scan_stopped":
        header_text = f"\u23F9 [{source_upper}] Scan Stopped"
    elif event_type == "scan_failed":
        header_text = f"\u274C [{source_upper}] Scan Failed"
    elif event_type == "scan_summary":
        header_text = f"\U0001F4CA [{source_upper}] Scan Summary"
    else:
        header_text = f"\U0001F514 [{source_upper}] {event_type.replace('_', ' ').title()}"

    blocks.append({
        "type": "header",
        "text": {"type": "plain_text", "text": header_text, "emoji": True}
    })

    # Build message body based on event type
    if event_type.startswith("finding_"):
        # Finding event
        title = data.get("title", "Unknown")
        ip_or_url = data.get("url") or data.get("ip", "N/A")
        cve = data.get("cve", "")

        body_lines = [
            f"*Source:* {source}",
            f"*Title:* {title}",
            f"*Target:* {ip_or_url}",
        ]
        if cve:
            body_lines.append(f"*CVE:* {cve}")

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(body_lines)}
        })

    elif event_type in ("scan_completed", "scan_failed"):
        # Scan event
        job_id = data.get("job_id", "N/A")
        targets_count = data.get("targets_count", 0)
        findings_count = data.get("findings_count", 0)
        error = data.get("error", "")

        body_lines = [
            f"*Source:* {source}",
            f"*Job ID:* `{job_id}`",
            f"*Targets:* {targets_count}",
        ]
        if findings_count:
            body_lines.append(f"*Findings:* {findings_count}")
        if error:
            body_lines.append(f"*Error:* {error}")

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(body_lines)}
        })

    else:
        # Generic event
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Source:* {source}\n```{str(data)[:500]}```"}
        })

    # Add timestamp footer
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"_RAG-Scan-Stack | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}_"}
        ]
    })

    return {"blocks": blocks}


def format_discord(event_type: str, source: str, data: Dict[str, Any], severity: Optional[str] = None) -> Dict[str, Any]:
    """
    Format payload as Discord webhook message.

    Returns Discord embed format.
    """
    source_upper = source.upper()

    # Determine title and color - include source for clarity
    if event_type.startswith("finding_"):
        sev = severity or event_type.split("_")[-1]
        emoji = get_severity_emoji(sev)
        title = f"{emoji} [{source_upper}] {sev.upper()} Finding"
        color = int(get_severity_color(sev).replace("#", ""), 16)
    elif event_type == "scan_completed":
        title = f"\u2705 [{source_upper}] Scan Completed"
        color = 0x00CC00
    elif event_type == "scan_started":
        title = f"\U0001F680 [{source_upper}] Scan Started"
        color = 0x0066FF
    elif event_type == "scan_stopped":
        title = f"\u23F9 [{source_upper}] Scan Stopped"
        color = 0xFF6600
    elif event_type == "scan_failed":
        title = f"\u274C [{source_upper}] Scan Failed"
        color = 0xFF0000
    elif event_type == "scan_summary":
        title = f"\U0001F4CA [{source_upper}] Scan Summary"
        color = 0x9933FF
    else:
        title = f"\U0001F514 [{source_upper}] {event_type.replace('_', ' ').title()}"
        color = 0x808080

    # Build fields
    fields = [{"name": "Source", "value": source, "inline": True}]

    if event_type.startswith("finding_"):
        fields.append({"name": "Title", "value": data.get("title", "Unknown")[:256], "inline": False})
        fields.append({"name": "Target", "value": data.get("url") or data.get("ip", "N/A"), "inline": True})
        if data.get("cve"):
            fields.append({"name": "CVE", "value": data["cve"], "inline": True})
    else:
        fields.append({"name": "Job ID", "value": f"`{data.get('job_id', 'N/A')}`", "inline": True})
        if data.get("targets_count"):
            fields.append({"name": "Targets", "value": str(data["targets_count"]), "inline": True})
        if data.get("findings_count"):
            fields.append({"name": "Findings", "value": str(data["findings_count"]), "inline": True})
        if data.get("error"):
            fields.append({"name": "Error", "value": data["error"][:256], "inline": False})

    embed = {
        "title": title,
        "color": color,
        "fields": fields,
        "footer": {"text": "RAG-Scan-Stack"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return {"embeds": [embed]}


def format_payload(url: str, event_type: str, source: str, data: Dict[str, Any], severity: Optional[str] = None) -> Dict[str, Any]:
    """
    Auto-detect destination and format payload accordingly.

    Args:
        url: Webhook destination URL
        event_type: Event type (scan_completed, finding_high, etc.)
        source: Source scanner (nmap, nuclei, zap)
        data: Event data
        severity: Optional severity level

    Returns:
        Formatted payload dict
    """
    if is_slack_webhook(url):
        return format_slack(event_type, source, data, severity)
    elif is_discord_webhook(url):
        return format_discord(event_type, source, data, severity)
    else:
        return format_generic(event_type, source, data, severity)
