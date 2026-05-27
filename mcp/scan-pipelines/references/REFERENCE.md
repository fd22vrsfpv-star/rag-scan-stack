# Scan Pipelines — Tool Reference

## start_full_port_scan
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target | string | Yes | IP address or CIDR range (e.g., '192.168.1.0/24') |
| rate | int | No | Packets per second for Masscan (default: 1000) |

### Pipeline Stages
1. Masscan ports 1-1000
2. Nmap service detection on discovered ports
3. Masscan ports 1001-65535
4. Nmap service detection on high ports
5. SMB vulnerability scan (if port 445 found)

## start_web_pipeline
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target_url | string | Yes | Target URL (e.g., 'http://192.168.1.150') |
| max_paths | int | No | Max paths for Playwright to visit (default: 50) |

### Pipeline Stages
1. Gobuster directory brute-force
2. Playwright browser crawling of discovered paths
3. ZAP proxy scanning
4. Nuclei vulnerability templates on discovered URLs

## get_pipeline_status
| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| job_id | string | Yes | Job UUID from start_full_port_scan or start_web_pipeline |
| pipeline_type | string | No | 'port' for full port scan, 'web' for web pipeline (default: 'port') |
