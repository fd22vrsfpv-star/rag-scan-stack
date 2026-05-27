#!/usr/bin/env python3
"""
Clean presentation materials WITH screenshots for PDF conversion
"""

import os
import re
from pathlib import Path

def clean_unicode_for_pdf(content):
    """Remove or replace Unicode characters that cause LaTeX issues"""

    # Replace common emojis with text equivalents
    emoji_replacements = {
        "✅": "[SUCCESS]",
        "❌": "[ERROR]",
        "⚠️": "[WARNING]",
        "📄": "[DOCUMENT]",
        "🔍": "[SEARCH]",
        "📊": "[CHART]",
        "🎯": "[TARGET]",
        "📈": "[GRAPH]",
        "🔧": "[TOOL]",
        "⚡": "[FAST]",
        "🚀": "[LAUNCH]",
        "💡": "[IDEA]",
        "🏗️": "[BUILD]",
        "🔒": "[SECURE]",
        "📋": "[LIST]",
        "🎨": "[DESIGN]",
        "📦": "[PACKAGE]",
        "🌐": "[NETWORK]",
        "📊": "[ANALYTICS]"
    }

    for emoji, replacement in emoji_replacements.items():
        content = content.replace(emoji, replacement)

    # Replace box-drawing characters with ASCII equivalents
    box_replacements = {
        "┌": "+",
        "┐": "+",
        "└": "+",
        "┘": "+",
        "├": "+",
        "┤": "+",
        "┬": "+",
        "┴": "+",
        "┼": "+",
        "─": "-",
        "│": "|",
        "▶": "->",
        "▼": "v"
    }

    for box_char, replacement in box_replacements.items():
        content = content.replace(box_char, replacement)

    # Clean up any remaining problematic characters but keep basic ASCII
    content = content.encode('ascii', errors='ignore').decode('ascii')

    return content

def process_file_with_screenshots(input_file, output_file):
    """Process a markdown file with screenshots for PDF conversion"""

    print(f"Cleaning {input_file} -> {output_file} (with screenshots)")

    # Read the file
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Clean Unicode characters but preserve image links
    cleaned_content = clean_unicode_for_pdf(content)

    # Write the cleaned version
    with open(output_file, 'w', encoding='ascii') as f:
        f.write(cleaned_content)

def main():
    """Clean screenshot versions for PDF conversion"""

    print("Cleaning screenshot versions for PDF conversion...")

    # Create clean versions directory
    clean_dir = Path("pdf-clean-with-screenshots")
    clean_dir.mkdir(exist_ok=True)

    # Files to clean (from pdf-versions with screenshots)
    files_to_clean = [
        ("pdf-versions/01-user-guide-with-images.md", "pdf-clean-with-screenshots/01-user-guide-clean.md"),
        ("pdf-versions/02-management-with-images.md", "pdf-clean-with-screenshots/02-management-clean.md"),
        ("pdf-versions/03-architecture-with-images.md", "pdf-clean-with-screenshots/03-architecture-clean.md")
    ]

    for input_file, output_file in files_to_clean:
        if os.path.exists(input_file):
            process_file_with_screenshots(input_file, output_file)
        else:
            print(f"Warning: {input_file} not found")

    print(f"\nCleaned files with screenshots created in {clean_dir}/ directory")
    print("Ready for PDF conversion with embedded screenshots")

if __name__ == "__main__":
    main()