 curl -s -X POST "http://localhost:8012/jobs/masscan-then-nmap" \
-H "content-type: application/json" \
-d '{"targets":["127.0.0.1/32"],"ports":"22,80,443,139,445,135,3389,8000-8020,9000","rate":200}'

