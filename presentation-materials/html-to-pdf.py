#!/usr/bin/env python3
"""
Alternative PDF conversion using HTML intermediate format
Works with or without pandoc
"""

import os
import subprocess
import markdown
from pathlib import Path

def markdown_to_html_to_pdf(md_file, pdf_file, title):
    """Convert markdown to PDF via HTML"""

    print(f"📄 Converting {md_file} to {pdf_file}...")

    # Read markdown content
    with open(md_file, 'r', encoding='utf-8') as f:
        md_content = f.read()

    # Convert markdown to HTML
    html_content = markdown.markdown(md_content, extensions=['tables', 'toc', 'codehilite'])

    # Create complete HTML document with styling
    full_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 40px;
            max-width: 1000px;
            margin: 0 auto;
        }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; border-bottom: 2px solid #bdc3c7; padding-bottom: 5px; margin-top: 30px; }}
        h3 {{ color: #7f8c8d; }}
        img {{ max-width: 100%; height: auto; border: 1px solid #ddd; border-radius: 4px; padding: 5px; }}
        pre {{ background-color: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px; padding: 15px; overflow-x: auto; }}
        code {{ background-color: #f8f9fa; padding: 2px 4px; border-radius: 3px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .toc {{ background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 5px; padding: 15px; margin: 20px 0; }}
        blockquote {{ border-left: 4px solid #3498db; padding-left: 15px; margin: 15px 0; font-style: italic; }}
        @page {{ margin: 1in; }}
        @media print {{
            body {{ print-color-adjust: exact; }}
            h1, h2, h3 {{ page-break-after: avoid; }}
            img {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div class="content">
        {html_content}
    </div>
    <footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666;">
        <p>Generated from RAG Scan Stack Documentation • {title}</p>
    </footer>
</body>
</html>
"""

    # Save HTML file
    html_file = md_file.replace('.md', '.html')
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(full_html)

    # Convert HTML to PDF using wkhtmltopdf if available
    try:
        subprocess.run([
            'wkhtmltopdf',
            '--page-size', 'A4',
            '--margin-top', '1in',
            '--margin-right', '0.8in',
            '--margin-bottom', '1in',
            '--margin-left', '0.8in',
            '--enable-local-file-access',
            '--print-media-type',
            html_file,
            pdf_file
        ], check=True, capture_output=True)

        print(f"✅ Created {pdf_file}")
        os.remove(html_file)  # Clean up HTML file
        return True

    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"⚠️  wkhtmltopdf not available, keeping HTML file: {html_file}")
        return False

def install_dependencies():
    """Install required Python packages"""
    try:
        import markdown
        return True
    except ImportError:
        print("📦 Installing markdown package...")
        subprocess.run(['pip', 'install', 'markdown'], check=True)
        return True

def main():
    print("📄 HTML-to-PDF Converter for RAG Scan Stack")
    print("============================================")

    # Install dependencies
    if not install_dependencies():
        print("❌ Failed to install dependencies")
        return 1

    # Create output directory
    os.makedirs('pdfs', exist_ok=True)

    # Files to convert (use the versions with images)
    files_to_convert = [
        ('pdf-versions/01-user-guide-with-images.md', 'pdfs/01-User-Guide-Features.pdf', 'RAG Scan Stack - User Guide & Features'),
        ('pdf-versions/02-management-with-images.md', 'pdfs/02-Management-Health.pdf', 'RAG Scan Stack - Management & Health'),
        ('pdf-versions/03-architecture-with-images.md', 'pdfs/03-Architecture-Simple.pdf', 'RAG Scan Stack - Simple Architecture'),
    ]

    success_count = 0
    total_count = len(files_to_convert)

    # Convert each file
    for md_file, pdf_file, title in files_to_convert:
        if os.path.exists(md_file):
            if markdown_to_html_to_pdf(md_file, pdf_file, title):
                success_count += 1
        else:
            print(f"⚠️  File not found: {md_file}")

    # Show results
    print(f"\n🏁 Conversion complete: {success_count}/{total_count} PDFs created")

    if success_count == 0:
        print("\n💡 Alternative: Use the HTML files in a browser and 'Print to PDF'")
        print("   This will preserve all styling and embedded screenshots")

    return 0 if success_count > 0 else 1

if __name__ == '__main__':
    exit(main())