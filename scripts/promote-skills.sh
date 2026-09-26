#!/usr/bin/env bash
# Promote the custom_vuln_skills DB overlay into the committed skills YAML pack.
# The in-container knowledge/ is read-only, so this fetches the merged YAML from
# rag-api and writes it on the HOST for review + commit.
#
# Safety: fetches to a temp file, refuses to proceed unless it is non-empty valid
# YAML, then BACKS UP the current file before replacing it.
set -euo pipefail
cd "$(dirname "$0")/.."
KEY=$(grep -E '^API_KEY=' .env | head -1 | cut -d= -f2-)
OUT=knowledge/vuln_class_methodology.yaml
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

docker exec rag-api sh -lc "curl -sk -H 'x-api-key: ${KEY}' https://localhost:8000/skills/export-yaml" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); sys.stderr.write('classes: %d\n' % d.get('classes',0)); sys.stdout.write(d['yaml'])" \
  > "$TMP"

# Never overwrite with an empty or invalid result.
if [ ! -s "$TMP" ] || ! python3 -c "import sys,yaml; yaml.safe_load(open('$TMP')) or sys.exit(1)" 2>/dev/null; then
  echo "ERROR: export was empty or not valid YAML — $OUT left unchanged" >&2
  exit 1
fi

# Back up the current file before replacing it (kept out of git via .gitignore;
# named *.bak-* so the knowledge loader's *.yaml glob never picks it up).
if [ -f "$OUT" ]; then
  BAK="${OUT}.bak-$(date +%Y%m%d-%H%M%S)"
  cp -p "$OUT" "$BAK"
  echo "Backed up current $OUT -> $BAK"
fi

mv "$TMP" "$OUT"
trap - EXIT
echo "Wrote $OUT"
echo "Review: git diff $OUT   (then commit; optionally clear promoted overlay rows)"
echo "Restore if needed: cp <backup> $OUT"
