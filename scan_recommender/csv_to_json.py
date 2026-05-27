#!/usr/bin/env python3
"""
Convert ExploitDB CSV to searchsploit-compatible JSON format.
Used for RAG ingestion when searchsploit -j doesn't work for bulk export.
"""

import csv
import json
import sys
from pathlib import Path


def csv_to_json(csv_path: str, output_path: str, limit: int = 0) -> dict:
    """
    Convert ExploitDB files_exploits.csv to JSON format.

    Args:
        csv_path: Path to files_exploits.csv
        output_path: Path for output JSON file
        limit: Max records to process (0 = all)

    Returns:
        Stats about conversion
    """
    exploits = []

    with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if limit > 0 and i >= limit:
                break

            # Map CSV columns to searchsploit JSON format
            exploits.append({
                'EDB-ID': row.get('id', ''),
                'Title': row.get('description', ''),
                'Path': row.get('file', ''),
                'Platform': row.get('platform', ''),
                'Type': row.get('type', ''),
                'Date_Published': row.get('date_published', ''),
                'Date_Added': row.get('date_added', ''),
                'Author': row.get('author', ''),
                'Verified': row.get('verified', '0'),
                'Codes': row.get('codes', ''),  # CVEs, OSVDB, etc.
                'Tags': row.get('tags', ''),
                'Port': row.get('port', ''),
            })

    output = {
        'SEARCH': '*',
        'DB_PATH_EXPLOIT': '/opt/exploitdb',
        'RESULTS_EXPLOIT': exploits
    }

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(output, f)

    return {
        'csv_path': csv_path,
        'output_path': output_path,
        'total_records': len(exploits),
        'bytes': Path(output_path).stat().st_size
    }


if __name__ == '__main__':
    csv_path = sys.argv[1] if len(sys.argv) > 1 else '/opt/exploitdb/files_exploits.csv'
    output_path = sys.argv[2] if len(sys.argv) > 2 else '/var/lib/searchsploit/searchsploit.json'
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    result = csv_to_json(csv_path, output_path, limit)
    print(f"Converted {result['total_records']} exploits to {output_path} ({result['bytes']} bytes)")
