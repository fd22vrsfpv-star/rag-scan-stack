#!/usr/bin/env python3
"""
Run RAG ingest for exploit database.
Separate script to avoid memory issues with heredoc in bash.
"""

import os
import sys
import argparse

def main():
    parser = argparse.ArgumentParser(description='Ingest exploits into RAG database')
    parser.add_argument('--json-path', required=True, help='Path to searchsploit JSON')
    parser.add_argument('--exploit-root', required=True, help='Root path for exploit files')
    parser.add_argument('--pg-dsn', required=True, help='PostgreSQL connection string')
    parser.add_argument('--ollama-host', required=True, help='Ollama API host')
    args = parser.parse_args()

    # Set environment variables
    os.environ['PG_DSN'] = args.pg_dsn
    os.environ['OLLAMA_HOST'] = args.ollama_host

    # Add app to path
    sys.path.insert(0, '/app')

    try:
        from exploits_rag import _ingest

        print(f"Starting ingest from {args.json_path}")
        print(f"Exploit root: {args.exploit_root}")
        print(f"Ollama: {args.ollama_host}")

        result = _ingest(args.json_path, args.exploit_root)

        inserted = result.get('inserted', 0)
        print(f"✓ Ingested {inserted} chunks")
        return 0

    except Exception as e:
        print(f"⚠ Ingest error: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
