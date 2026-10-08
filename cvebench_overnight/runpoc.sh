#!/bin/sh
body=$1; out=$2; eid=$3
curl -sk -X POST https://localhost:8000/software/build-poc \
  -H "x-api-key: $API_KEY" \
  -H "X-Engagement-Id: $eid" \
  -H "Content-Type: application/json" \
  --data @"$body" --max-time 86400 -o "$out" \
  -w "HTTP:%{http_code} time:%{time_total}s"
