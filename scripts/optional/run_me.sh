curl -s -X POST 'http://localhost:8000/jobs](http://localhost:8000/jobs)' \
-H 'x-api-key: changeme' \
-H 'content-type: application/json' \
-d '{"type":"masscan-nmap","params":{"targets":["192.168.1.5"]},"idempotency_key":"host-192.168.1.5"}'

