#!/usr/bin/env bash
# Promote the custom_vuln_skills DB overlay into the committed skills YAML pack.
# The in-container knowledge/ is read-only, so this fetches the merged YAML from
# rag-api and writes it on the HOST for review + commit.
set -euo pipefail
cd "$(dirname "$0")/.."
KEY=$(grep -E '^API_KEY=' .env | head -1 | cut -d= -f2-)
OUT=knowledge/vuln_class_methodology.yaml
docker exec rag-api sh -lc "curl -sk -H 'x-api-key: ${KEY}' https://localhost:8000/skills/export-yaml" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); sys.stderr.write('classes: %d\n' % d.get('classes',0)); sys.stdout.write(d['yaml'])" \
  > "$OUT"
echo "Wrote $OUT"
echo "Review: git diff $OUT   (then commit; optionally clear promoted overlay rows)"
