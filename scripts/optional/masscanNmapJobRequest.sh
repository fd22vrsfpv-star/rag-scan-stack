curl -X POST "http://localhost:8012/jobs/masscan-then-nmap" \
     -H "Content-Type: application/json" \
     -d '{"targets": ["192.168.1.114/32"], "ports": "1-65535", "rate": 1000}'
