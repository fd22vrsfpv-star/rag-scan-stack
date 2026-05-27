#!/usr/bin/env python3
"""
Clean presentation materials for PDF conversion by removing Unicode characters
that cause LaTeX issues and replacing emojis with text equivalents.
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

    # Clean up any remaining non-ASCII characters
    content = content.encode('ascii', errors='ignore').decode('ascii')

    return content

def process_file(input_file, output_file):
    """Process a markdown file to clean it for PDF conversion"""

    print(f"Cleaning {input_file} -> {output_file}")

    # Read the file
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()

    # Clean Unicode characters
    cleaned_content = clean_unicode_for_pdf(content)

    # Write the cleaned version
    with open(output_file, 'w', encoding='ascii') as f:
        f.write(cleaned_content)

def main():
    """Clean all presentation materials for PDF conversion"""

    print("Cleaning presentation materials for PDF conversion...")

    # Create clean versions directory
    clean_dir = Path("pdf-clean")
    clean_dir.mkdir(exist_ok=True)

    # Files to clean
    files_to_clean = [
        ("01-user-guide-features.md", "pdf-clean/01-user-guide-clean.md"),
        ("02-management-health.md", "pdf-clean/02-management-clean.md"),
        ("03-architecture-simple.md", "pdf-clean/03-architecture-clean.md")
    ]

    for input_file, output_file in files_to_clean:
        if os.path.exists(input_file):
            process_file(input_file, output_file)
        else:
            print(f"Warning: {input_file} not found")

    print(f"\nCleaned files created in {clean_dir}/ directory")
    print("Ready for PDF conversion without Unicode issues")

if __name__ == "__main__":
    main()