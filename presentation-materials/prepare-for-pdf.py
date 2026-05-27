#!/usr/bin/env python3
"""
Prepare presentation materials for PDF conversion by embedding screenshots
"""

import os
import re
from pathlib import Path

def update_markdown_with_screenshots(input_file, output_file):
    """Update markdown file to include actual screenshots"""

    # Read the original markdown
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Screenshot mappings based on what we captured
    screenshot_mappings = {
        # User Guide screenshots
        "📷 Take Screenshot**: Dashboard landing page": "![Dashboard Overview](screenshots/01-user-guide/dashboard-overview.png)",
        "📷 Take Screenshots**: \n> 1. Engagements page": "![Engagements Management](screenshots/01-user-guide/engagements-list.png)",
        "📷 Take Screenshots**:\n> 1. Scope Intelligence main page": "![Scope Intelligence](screenshots/01-user-guide/scope-intelligence.png)",
        "📷 Take Screenshots**:\n> 1. Findings Explorer main view": "![Findings Explorer](screenshots/01-user-guide/findings-explorer.png)",
        "📷 Take Screenshots**:\n> 1. AI Agents dashboard": "![AI Agents Dashboard](screenshots/01-user-guide/ai-agents.png)",
        "📷 Take Screenshots**:\n> 1. Nodes overview with tunnel status": "![Nodes Overview](screenshots/01-user-guide/nodes-overview.png)",
        "📷 Take Screenshots**:\n> 1. Reports dashboard": "![Reports Dashboard](screenshots/01-user-guide/reports-dashboard.png)",

        # Management screenshots
        "📷 Take Screenshots**:\n> 1. Health dashboard main view": "![Health Dashboard](screenshots/02-management/health-dashboard.png)",
        "📷 Take Screenshots**:\n> 1. Service health monitoring": "![Services Management](screenshots/02-management/services-management.png)",
        "📷 Take Screenshots**:\n> 1. Resource usage graphs": "![System Diagnostics](screenshots/02-management/diagnostics.png)",

        # Architecture screenshots
        "📷 Take Screenshots**:\n> 1. System architecture overview": "![Assets Browser](screenshots/03-architecture/assets-browser.png)",
        "📷 Take Screenshots**:\n> 1. Network topology": "![Scan Pipeline](screenshots/03-architecture/scan-launcher.png)",
        "📷 Take Screenshots**:\n> 1. Database health dashboard": "![Documentation](screenshots/03-architecture/about-documentation.png)"
    }

    # Replace screenshot instructions with actual images
    updated_content = content

    # Replace specific screenshot instructions
    for instruction, image_md in screenshot_mappings.items():
        if instruction in updated_content:
            # Find the instruction and replace the entire line/section
            updated_content = updated_content.replace(instruction, image_md)

    # Generic replacements for remaining screenshot instructions
    # Replace "### Screenshot Instructions" sections
    screenshot_pattern = r'### Screenshot Instructions\n> \*\*📷 Take Screenshots?\*\*:?[^\n]*\n(?:> [^\n]*\n)*'
    updated_content = re.sub(screenshot_pattern, '', updated_content)

    # Add screenshots where we have them for each major section
    section_screenshots = {
        "## 2. Dashboard Overview": "\n\n![Dashboard Overview](screenshots/01-user-guide/dashboard-overview.png)\n\n",
        "## 3. Engagement Management Workflow": "\n\n![Engagements Management](screenshots/01-user-guide/engagements-list.png)\n\n",
        "## 4. Scope Definition & Intelligence": "\n\n![Scope Intelligence](screenshots/01-user-guide/scope-intelligence.png)\n\n",
        "## 5. AI-Powered Scanning Workflow": "\n\n![AI Agents Dashboard](screenshots/01-user-guide/ai-agents.png)\n\n",
        "## 6. Findings Management": "\n\n![Findings Explorer](screenshots/01-user-guide/findings-explorer.png)\n\n",
        "## 7. Node & Tunnel Management": "\n\n![Nodes Overview](screenshots/01-user-guide/nodes-overview.png)\n\n![WireGuard Management](screenshots/01-user-guide/wireguard-management.png)\n\n",
        "## 8. Reporting & Export": "\n\n![Reports Dashboard](screenshots/01-user-guide/reports-dashboard.png)\n\n",
        "## 2. Service Health Monitoring": "\n\n![Health Dashboard](screenshots/02-management/health-dashboard.png)\n\n",
        "## 3. Container & Service Management": "\n\n![Services Management](screenshots/02-management/services-management.png)\n\n",
        "## 4. Performance Monitoring & Metrics": "\n\n![System Diagnostics](screenshots/02-management/diagnostics.png)\n\n",
        "## 6. Storage & Database Design": "\n\n![Assets Browser](screenshots/03-architecture/assets-browser.png)\n\n",
        "## 3. Data Flow & Integration Patterns": "\n\n![Scan Pipeline](screenshots/03-architecture/scan-launcher.png)\n\n",
        "## 9. Integration Points": "\n\n![Documentation](screenshots/03-architecture/about-documentation.png)\n\n"
    }

    # Insert screenshots after relevant section headers
    for section_header, screenshot_md in section_screenshots.items():
        if section_header in updated_content:
            updated_content = updated_content.replace(section_header, section_header + screenshot_md)

    # Write the updated content
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(updated_content)

    print(f"✅ Updated {input_file} -> {output_file} with embedded screenshots")

def main():
    """Main function to prepare all markdown files"""

    # Create PDF versions directory
    pdf_versions_dir = Path("pdf-versions")
    pdf_versions_dir.mkdir(exist_ok=True)

    # Process each markdown file
    markdown_files = [
        ("01-user-guide-features.md", "pdf-versions/01-user-guide-with-images.md"),
        ("02-management-health.md", "pdf-versions/02-management-with-images.md"),
        ("03-architecture-simple.md", "pdf-versions/03-architecture-with-images.md")
    ]

    print("📸 Preparing presentation materials with embedded screenshots...")

    for input_file, output_file in markdown_files:
        if os.path.exists(input_file):
            update_markdown_with_screenshots(input_file, output_file)
        else:
            print(f"⚠️  Warning: {input_file} not found")

    print(f"\n✅ All files prepared in {pdf_versions_dir}/ directory")
    print("📄 Ready for PDF conversion with embedded screenshots")

if __name__ == "__main__":
    main()