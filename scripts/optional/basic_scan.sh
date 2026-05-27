
curl -s -X POST '[http://localhost:8012/jobs/masscan-then-nmap' -H 'content-type: application/json' -d '{"targets":["192.168.1.5"],"ports":"1-1000","rate":5000}'
