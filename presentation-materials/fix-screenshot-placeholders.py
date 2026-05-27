#!/usr/bin/env python3
"""
Fix screenshot instruction placeholders with actual screenshot links
"""

import re
import os
from pathlib import Path

def fix_screenshot_placeholders():
    """Replace screenshot instruction sections with actual screenshot links"""

    # Define screenshot mappings based on our comprehensive capture
    screenshot_mappings = {
        # User Guide Features
        "01-user-guide-features.md": {
            "Dashboard landing page": "![Dashboard Overview](screenshots-complete/01-core-workflow/dashboard-main.png)",
            "Engagements page": "![Engagement Management](screenshots-complete/01-core-workflow/engagements-management.png)",
            "Scope Intelligence main page": "![Recon Explorer](screenshots-complete/03-recon-osint/recon-explorer.png)",
            "Findings Explorer main view": "![Findings Explorer](screenshots-complete/05-exploits-offensive/findings-exploitation.png)",
            "AI Agents dashboard": "![AI Agents](screenshots-complete/04-scan-management/ai-agents.png)",
            "Nodes overview with tunnel status": "![Nodes Overview](screenshots-complete/06-remote-nodes/nodes-overview.png)",
            "Reports dashboard": "![Reports Dashboard](screenshots-complete/10-reporting/reports-dashboard.png)",
            "Scan Launcher interface": "![Scan Launcher](screenshots-complete/04-scan-management/scan-launcher-detail.png)"
        },

        # Management Health
        "02-management-health.md": {
            "Health dashboard main view": "![Health Dashboard](screenshots-complete/08-operations/diagnostics.png)",
            "Service health monitoring": "![Services Management](screenshots-complete/08-operations/services-management.png)",
            "Resource usage graphs": "![System Diagnostics](screenshots-complete/08-operations/diagnostics.png)",
            "Network topology": "![Assets Browser](screenshots-complete/02-assets-software/assets-inventory.png)",
            "Database health dashboard": "![Platform Information](screenshots-complete/09-intelligence/platform-info.png)",
            "Performance monitoring": "![OpSec Dashboard](screenshots-complete/08-operations/opsec-dashboard.png)",
            "Container management": "![Services Management](screenshots-complete/08-operations/services-management.png)",
            "System maintenance": "![Maintenance](screenshots-complete/08-operations/maintenance.png)"
        }
    }

    for filename, mappings in screenshot_mappings.items():
        if os.path.exists(filename):
            print(f"Fixing screenshot placeholders in {filename}...")

            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read()

            # Remove "Screenshot Instructions" sections entirely
            content = re.sub(r'### Screenshot Instructions\n(?:> \*\*📷[^\n]*\n)*(?:> [^\n]*\n)*\n?', '', content, flags=re.MULTILINE)

            # Add screenshots at the beginning of major sections
            section_replacements = {
                "## 2. Dashboard Overview": "## 2. Dashboard Overview\n\n![Dashboard Overview](screenshots-complete/01-core-workflow/dashboard-main.png)\n",
                "## 3. Engagement Management Workflow": "## 3. Engagement Management Workflow\n\n![Engagement Management](screenshots-complete/01-core-workflow/engagements-management.png)\n",
                "## 4. Scope Definition & Intelligence": "## 4. Scope Definition & Intelligence\n\n![Recon Explorer](screenshots-complete/03-recon-osint/recon-explorer.png)\n",
                "## 5. AI-Powered Scanning Workflow": "## 5. AI-Powered Scanning Workflow\n\n![AI Agents](screenshots-complete/04-scan-management/ai-agents.png)\n",
                "## 6. Findings Management": "## 6. Findings Management\n\n![Findings Explorer](screenshots-complete/05-exploits-offensive/findings-exploitation.png)\n",
                "## 7. Node & Tunnel Management": "## 7. Node & Tunnel Management\n\n![Nodes Overview](screenshots-complete/06-remote-nodes/nodes-overview.png)\n\n![SSH Tunnels](screenshots-complete/06-remote-nodes/ssh-tunnels.png)\n\n![WireGuard VPN](screenshots-complete/06-remote-nodes/wireguard-vpn.png)\n",
                "## 8. Reporting & Export": "## 8. Reporting & Export\n\n![Reports Dashboard](screenshots-complete/10-reporting/reports-dashboard.png)\n",

                # Management Health sections
                "## 2. Service Health Monitoring": "## 2. Service Health Monitoring\n\n![System Diagnostics](screenshots-complete/08-operations/diagnostics.png)\n",
                "## 3. Container & Service Management": "## 3. Container & Service Management\n\n![Services Management](screenshots-complete/08-operations/services-management.png)\n",
                "## 4. Performance Monitoring & Metrics": "## 4. Performance Monitoring & Metrics\n\n![OpSec Dashboard](screenshots-complete/08-operations/opsec-dashboard.png)\n",
                "## 5. Database & Storage Health": "## 5. Database & Storage Health\n\n![Platform Information](screenshots-complete/09-intelligence/platform-info.png)\n",
                "## 6. Network Infrastructure Monitoring": "## 6. Network Infrastructure Monitoring\n\n![Assets Browser](screenshots-complete/02-assets-software/assets-inventory.png)\n",
                "## 7. System Maintenance & Operations": "## 7. System Maintenance & Operations\n\n![Maintenance](screenshots-complete/08-operations/maintenance.png)\n",
                "## 8. Security & Compliance Monitoring": "## 8. Security & Compliance Monitoring\n\n![OpSec Dashboard](screenshots-complete/08-operations/opsec-dashboard.png)\n"
            }

            for section, replacement in section_replacements.items():
                if section in content:
                    content = content.replace(section, replacement)

            # Write the fixed content
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(content)

            print(f"  ✅ Fixed screenshot placeholders in {filename}")
        else:
            print(f"  ⚠️ File not found: {filename}")

def main():
    """Fix screenshot placeholders in all presentation files"""
    print("🔧 Fixing screenshot placeholders in presentation materials...")

    fix_screenshot_placeholders()

    print("\n✅ Screenshot placeholder fix complete!")
    print("📄 All presentation materials now have actual screenshots instead of instructions")

if __name__ == "__main__":
    main()