# Lab: "Sentinel" — Walkthrough

Target: 10.10.10.42 (sentinel.lab.local)

## Enumeration

Started with a full TCP scan. Open: 21/ftp, 161/udp (snmp), 8080/http.

## FTP (21)

vsftpd 3.0.3. Anonymous login was enabled, which let me list the share without
credentials. Inside `pub/` there was a `backup.cfg` containing the line
`svc_backup:Summer2023!` — those creds worked for SSH later.

Anonymous FTP is worth checking before any brute force: it costs one request and
frequently exposes configuration or backup files that contain credentials for
other services. Always list recursively, and pull anything named backup, config,
or .bak.

## SNMP (161/udp)

Community string `public` worked with SNMPv2c — the vendor default was never
changed. Walking the tree gave me a lot:

- `1.3.6.1.2.1.1.1.0` — sysDescr, exact OS build
- `1.3.6.1.2.1.25.4.2.1.2` — running processes, which showed a Tomcat instance
- `1.3.6.1.2.1.4.22.1.2` — the ARP cache, revealing 10.10.10.0/24 neighbours

The ARP cache is the useful part: it maps internal hosts you have no other route
to. Read access is usually enough — try the standard defaults (public, private,
community) before spending time on writes, and remember SNMPv3 is authenticated
so username enumeration replaces community guessing there.

## Tomcat (8080)

Apache Tomcat 9.0.30. `/manager/html` was reachable and accepted `tomcat:tomcat`.
From there I deployed a WAR shell.

Tomcat's manager interface is the standard route in: check `/manager/html` and
`/host-manager/html`, try the shipped default accounts, and if you get in, WAR
deployment gives code execution directly. Version matters — 9.0.30 predates
several fixes.

## Root

Found the flag at /root/root.txt: `HTB{s3nt1n3l_pwn3d_2024}`

Privilege escalation was via a cron job running as root, hash
`5f4dcc3b5aa765d61d8327deb882cf99` recovered from /etc/shadow.
