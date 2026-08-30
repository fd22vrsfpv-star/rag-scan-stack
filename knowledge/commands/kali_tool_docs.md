# Kali Tool Documentation

Fetched from https://www.kali.org/tools/ by `scripts/fetch_tool_docs.py`
via `scan_recommender/url_fetch.fetch_guide` (scheme allowlist, SSRF
guard, size and redirect caps, HTML→markdown).

- Generated: 2026-08-23 23:32 UTC
- Tools documented: 38
- No kali.org page: 0
- Fetch failed: 64

**What this source can and cannot tell you.** These pages carry the
description, version, SUBCOMMANDS and GLOBAL options — they show
`<tool> --help`. They do **not** carry per-subcommand flags: gobuster's
`-w` lives under `gobuster dir --help`, not on this page. So use this to
decide whether a tool belongs in the catalogue and which modes exist,
and use `tool_invocations.md` — captured from the installed build — for
what a specific invocation actually accepts.

**Binary → package**. kali.org is indexed by package name, so
these were resolved through the index rather than guessed:

- `nmap-smb-vuln` → `nmap (binary of nmap)`

### crackmapexec

Source: https://www.kali.org/tools/crackmapexec/

#### crackmapexec

Swiss army knife for pentesting networks This package is a swiss army knife for pentesting Windows/Active Directory
environments.
From enumerating logged on users and spidering SMB shares to executing psexec
style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using
Powershell, dumping the NTDS.dit and more.
The biggest improvements over the above tools are:
- Pure Python script, no external tools required
- Fully concurrent threading
- Uses ONLY native WinAPI calls for discovering sessions, users, dumping
SAM hashes etc…
- Opsec safe (no binaries are uploaded to dump clear-text credentials, inject
shellcode etc…)
Additionally, a database is used to store used/dumped credentals. It also
automatically correlates Admin credentials to hosts and vice-versa allowing you
to easily keep track of credential sets and gain additional situational
awareness in large environments.
Installed size: 2.29 MB How to install: sudo apt install crackmapexec
- python3
- python3-aardwolf
- python3-aioconsole
- python3-bs4
- python3-dsinternals
- python3-impacket
- python3-lsassy
- python3-masky
- python3-msgpack
- python3-neo4j
- python3-paramiko
- python3-pylnk3
- python3-pypsrp
- python3-pywerview
- python3-requests
- python3-termcolor
- python3-terminaltables3
- python3-unicrypto
- python3-xmltodict

##### cmedb

```
root@kali:~# cmedb -h
[-] Unable to find config file
```

##### crackmapexec

```
root@kali:~# crackmapexec -h
usage: crackmapexec [-h] [-t THREADS] [--timeout TIMEOUT] [--jitter INTERVAL]
                    [--darrell] [--verbose]
                    {smb,winrm,mssql,ftp,ssh,rdp,ldap} ...

      ______ .______           ___        ______  __  ___ .___  ___.      ___      .______    _______ ___   ___  _______   ______
     /      ||   _  \         /   \      /      ||  |/  / |   \/   |     /   \     |   _  \  |   ____|\  \ /  / |   ____| /      |
    |  ,----'|  |_)  |       /  ^  \    |  ,----'|  '  /  |  \  /  |    /  ^  \    |  |_)  | |  |__    \  V  /  |  |__   |  ,----'
    |  |     |      /       /  /_\  \   |  |     |    <   |  |\/|  |   /  /_\  \   |   ___/  |   __|    >   <   |   __|  |  |
    |  `----.|  |\  \----. /  _____  \  |  `----.|  .  \  |  |  |  |  /  _____  \  |  |      |  |____  /  .  \  |  |____ |  `----.
     \______|| _| `._____|/__/     \__\  \______||__|\__\ |__|  |__| /__/     \__\ | _|      |_______|/__/ \__\ |_______| \______|

                                                A swiss army knife for pentesting networks
                                    Forged by @byt3bl33d3r and @mpgn_x64 using the powah of dank memes

                                           Exclusive release for Porchetta Industries users
                                                       https://porchetta.industries/

                                                   Version : 5.4.0
                                                   Codename: Indestructible G0thm0g

options:
  -h, --help            show this help message and exit
  -t THREADS            set how many concurrent threads to use (default: 100)
  --timeout TIMEOUT     max timeout in seconds of each thread (default: None)
  --jitter INTERVAL     sets a random delay between each connection (default: None)
  --darrell             give Darrell a hand
  --verbose             enable verbose output

protocols:
  available protocols

  {smb,winrm,mssql,ftp,ssh,rdp,ldap}
    smb                 own stuff using SMB
    winrm               own stuff using WINRM
    mssql               own stuff using MSSQL
    ftp                 own stuff using FTP
    ssh                 own stuff using SSH
    rdp                 own stuff using RDP
    ldap                own stuff using LDAP
```

#### Learn more with OffSec

Want to learn more about crackmapexec? get access to in-depth training and hands-on labs:
- PEN-200: 23.2.1. Attacking Active Directory Authentication: Password Attacks
PEN-200 course
Updated on: 2026-Jun-17

### crowbar

Source: https://www.kali.org/tools/crowbar/

#### Tool Documentation:



#### Tool Documentation:

#### crowbar Usage Examples

Brute force the RDP service on a single host with a specified username and wordlist, using 1 thread.

```
root@kali:~# crowbar -b rdp -s 192.168.86.61/32 -u victim -C /root/words.txt -n 1
2017-10-10 14:59:55 START
2017-10-10 14:59:55 Crowbar v0.3.5-dev
2017-10-10 14:59:55 Trying 192.168.86.61:3389
2017-10-10 15:00:08 RDP-SUCCESS : 192.168.86.61:3389 - victim:s3cr3t
2017-10-10 15:00:08 STOP
```


#### crowbar

Brute forcing tool This package contains Crowbar (formally known as Levye). It is a brute forcing
tool that can be used during penetration tests. It was developed to brute force
some protocols in a different manner according to other popular brute forcing
tools. As an example, while most brute forcing tools use username and password
for SSH brute force, Crowbar uses SSH key(s). This allows for any private keys
that have been obtained during penetration tests, to be used to attack other
SSH servers.
Currently Crowbar supports:
* OpenVPN (-b openvpn)
* Remote Desktop Protocol (RDP) with NLA support (-b rdp)
* SSH private key authentication (-b sshkey)
* VNC key authentication (-b vpn)
Installed size: 450 KB How to install: sudo apt install crowbar
- freerdp3-x11
- openvpn
- python3
- python3-nmap
- python3-paramiko
- vncviewer

##### crowbar

```
root@kali:~# crowbar -h
usage: Usage: use --help for further information

Crowbar is a brute force tool which supports OpenVPN, Remote Desktop Protocol,
SSH Private Keys and VNC Keys.

positional arguments:
  options

options:
  -h, --help            show this help message and exit
  -b, --brute {openvpn,rdp,sshkey,vnckey}
                        Target service
  -s, --server SERVER   Static target
  -S, --serverfile SERVER_FILE
                        Multiple targets stored in a file
  -u, --username USERNAME [USERNAME ...]
                        Static name to login with
  -U, --usernamefile USERNAME_FILE
                        Multiple names to login with, stored in a file
  -n, --number THREAD   Number of threads to be active at once
  -l, --log FILE        Log file (only write attempts)
  -o, --output FILE     Output file (write everything else)
  -c, --passwd PASSWD   Static password to login with
  -C, --passwdfile FILE
                        Multiple passwords to login with, stored in a file
  -t, --timeout TIMEOUT
                        [SSH] How long to wait for each thread (seconds)
  -p, --port PORT       Alter the port if the service is not using the default
                        value
  -k, --keyfile KEY_FILE
                        [SSH/VNC] (Private) Key file or folder containing
                        multiple files
  -m, --config CONFIG   [OpenVPN] Configuration file
  -d, --discover        Port scan before attacking open ports
  -v, --verbose         Enable verbose output (-vv for more)
  -D, --debug           Enable debug mode
  -q, --quiet           Only display successful logins
```

Updated on: 2025-Dec-09

### curl

Source: https://www.kali.org/tools/curl/

#### curl

Command line tool for transferring data with URL syntax curl is a command line tool for transferring data with URL syntax, supporting
DICT, FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3,
POP3S, RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
curl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP form
based upload, proxies, cookies, user+password authentication (Basic, Digest,
NTLM, Negotiate, kerberos…), file transfer resume, proxy tunneling and a
busload of other useful tricks.
Installed size: 507 KB How to install: sudo apt install curl
- libc6
- libcurl4t64
- zlib1g

##### curl

Transfer a URL

```
root@kali:~# curl -h
Usage: curl [options...] <url>
 -d, --data <data>            HTTP POST data
 -f, --fail                   Fail fast with no output on HTTP errors
 -I, --head                   Show document info only
 -H, --header <header/@file>  Pass custom header(s) to server
 -h, --help <subject>         Get help for commands
 -o, --output <file>          Write to file instead of stdout
 -O, --remote-name            Write output to file named as remote file
 -i, --show-headers           Show response headers in output
 -s, --silent                 Silent mode
 -T, --upload-file <file>     Transfer local FILE to destination
 -u, --user <user:password>   Server user and password
 -A, --user-agent <name>      Send User-Agent <name> to server
 -v, --verbose                Make the operation more talkative
 -V, --version                Show version number and quit

This is not the full help; this menu is split into categories.
Use "--help category" to get an overview of all categories, which are:
auth, connection, curl, deprecated, dns, file, ftp, global, http, imap, ldap, 
output, pop3, post, proxy, scp, sftp, smtp, ssh, telnet, tftp, timeout, tls, 
upload, verbose.
Use "--help all" to list all options
Use "--help [option]" to view documentation for a given option
```

##### wcurl

A simple wrapper around curl to easily download files.

```
root@kali:~# wcurl -h
wcurl -- a simple wrapper around curl to easily download files.

Usage: wcurl <URL>...
       wcurl [--curl-options <CURL_OPTIONS>]... [--no-decode-filename] [-o|-O|--output <PATH>] [--dry-run] [--] <URL>...
       wcurl [--curl-options=<CURL_OPTIONS>]... [--no-decode-filename] [--output=<PATH>] [--dry-run] [--] <URL>...
       wcurl -h|--help
       wcurl -V|--version

Options:

  --curl-options <CURL_OPTIONS>: Specify extra options to be passed when invoking curl. May be
                                 specified more than once.

  -o, -O, --output <PATH>: Use the provided output path instead of getting it from the URL. If
                           multiple URLs are provided, resulting files share the same name with a
                           number appended to the end (curl >= 7.83.0). If this option is provided
                           multiple times, only the last value is considered.

  --no-decode-filename: Do not percent-decode the output filename, even if the percent-encoding in
                        the URL was done by wcurl, e.g.: The URL contained whitespace.

  --dry-run: Do not actually execute curl, just print what would be invoked.

  -V, --version: Print version information.

  -h, --help: Print this usage message.

  <CURL_OPTIONS>: Any option supported by curl can be set here. This is not used by wcurl; it is
                 instead forwarded to the curl invocation.

  <URL>: URL to be downloaded. Anything that is not a parameter is considered
         an URL. Whitespace is percent-encoded and the URL is passed to curl, which
         then performs the parsing. May be specified more than once.
```

#### libcurl3t64-gnutls

Transitional package for libcurl4-gnutls This is a transitional package. It can be safely removed.
Installed size: 36 KB How to install: sudo apt install libcurl3t64-gnutls
- libcurl4-gnutls

#### libcurl4-doc

Documentation for libcurl libcurl is an easy-to-use client-side URL transfer library, supporting DICT,
FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S,
RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP
form based upload, proxies, cookies, user+password authentication (Basic,
Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling
and more!
libcurl is free, thread-safe, IPv6 compatible, feature rich, well supported,
fast, thoroughly documented and is already used by many known, big and
successful companies and numerous applications.
This package provides the documentation files for libcurl.
Installed size: 1.70 MB How to install: sudo apt install libcurl4-doc

#### libcurl4-gnutls

Easy-to-use client-side URL transfer library (GnuTLS flavour) libcurl is an easy-to-use client-side URL transfer library, supporting DICT,
FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S,
RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP
form based upload, proxies, cookies, user+password authentication (Basic,
Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling
and more!
libcurl is free, thread-safe, IPv6 compatible, feature rich, well supported,
fast, thoroughly documented and is already used by many known, big and
successful companies and numerous applications.
SSL support is provided by GnuTLS.
Installed size: 1.01 MB How to install: sudo apt install libcurl4-gnutls
- libbrotli1
- libc6
- libgnutls30t64
- libgssapi-krb5-2
- libidn2-0
- libldap2
- libnettle8t64
- libnghttp2-14
- libnghttp3-9
- libngtcp2-16
- libngtcp2-crypto-gnutls8
- libpsl5t64
- libssh2-1t64
- libzstd1
- zlib1g

#### libcurl4-gnutls-dev

Development files and documentation for libcurl (GnuTLS flavour) libcurl is an easy-to-use client-side URL transfer library, supporting DICT,
FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S,
RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP
form based upload, proxies, cookies, user+password authentication (Basic,
Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling
and more!
libcurl is free, thread-safe, IPv6 compatible, feature rich, well supported,
fast, thoroughly documented and is already used by many known, big and
successful companies and numerous applications.
This package provides the development files (ie. includes, static library,
manual pages) that allow one to build software which uses libcurl.
SSL support is provided by GnuTLS.
Installed size: 2.27 MB How to install: sudo apt install libcurl4-gnutls-dev
- libbrotli-dev
- libcurl4-gnutls
- libgnutls28-dev
- libidn2-dev
- libkrb5-dev
- libldap-dev
- libnghttp2-dev
- libnghttp3-dev
- libngtcp2-crypto-gnutls-dev
- libngtcp2-dev
- libpsl-dev
- librtmp-dev
- libssh2-1-dev
- libzstd-dev
- zlib1g-dev

##### curl-config

Get information about a libcurl installation

```
root@kali:~# curl-config --help
Usage: curl-config [OPTION]

Available values for OPTION include:

  --built-shared        says 'yes' if libcurl was built shared
  --ca                  CA bundle install path
  --cc                  compiler
  --cflags              preprocessor and compiler flags
  --checkfor [version]  check for (lib)curl of the specified version
  --configure           the arguments given to configure when building curl
  --features            newline separated list of enabled features
  --help                display this help and exit
  --libs                library linking information
  --prefix              curl install prefix
  --protocols           newline separated list of enabled protocols
  --ssl-backends        output the SSL backends libcurl was built to support
  --static-libs         static libcurl library linking information
  --version             output version information
  --vernum              output version as a hexadecimal number
```

#### libcurl4-openssl-dev

Development files and documentation for libcurl (OpenSSL flavour) libcurl is an easy-to-use client-side URL transfer library, supporting DICT,
FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S,
RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP
form based upload, proxies, cookies, user+password authentication (Basic,
Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling
and more!
libcurl is free, thread-safe, IPv6 compatible, feature rich, well supported,
fast, thoroughly documented and is already used by many known, big and
successful companies and numerous applications.
This package provides the development files (ie. includes, static library,
manual pages) that allow one to build software which uses libcurl.
SSL support is provided by OpenSSL.
Installed size: 2.27 MB How to install: sudo apt install libcurl4-openssl-dev
- libbrotli-dev
- libcurl4t64
- libidn2-dev
- libkrb5-dev
- libldap-dev
- libnghttp2-dev
- libnghttp3-dev
- libngtcp2-crypto-ossl-dev
- libngtcp2-dev
- libpsl-dev
- librtmp-dev
- libssh2-1-dev
- libssl-dev
- libzstd-dev
- zlib1g-dev

##### curl-config

Get information about a libcurl installation

```
root@kali:~# curl-config --help
Usage: curl-config [OPTION]

Available values for OPTION include:

  --built-shared        says 'yes' if libcurl was built shared
  --ca                  CA bundle install path
  --cc                  compiler
  --cflags              preprocessor and compiler flags
  --checkfor [version]  check for (lib)curl of the specified version
  --configure           the arguments given to configure when building curl
  --features            newline separated list of enabled features
  --help                display this help and exit
  --libs                library linking information
  --prefix              curl install prefix
  --protocols           newline separated list of enabled protocols
  --ssl-backends        output the SSL backends libcurl was built to support
  --static-libs         static libcurl library linking information
  --version             output version information
  --vernum              output version as a hexadecimal number
```

#### libcurl4t64

Easy-to-use client-side URL transfer library (OpenSSL flavour) libcurl is an easy-to-use client-side URL transfer library, supporting DICT,
FILE, FTP, FTPS, GOPHER, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S,
RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, TELNET and TFTP.
libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP
form based upload, proxies, cookies, user+password authentication (Basic,
Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling
and more!
libcurl is free, thread-safe, IPv6 compatible, feature rich, well supported,
fast, thoroughly documented and is already used by many known, big and
successful companies and numerous applications.
SSL support is provided by OpenSSL.
Installed size: 1.03 MB How to install: sudo apt install libcurl4t64
- libbrotli1
- libc6
- libgssapi-krb5-2
- libidn2-0
- libldap2
- libnghttp2-14
- libnghttp3-9
- libngtcp2-16
- libngtcp2-crypto-ossl0
- libpsl5t64
- libssh2-1t64
- libssl3t64
- libzstd1
- zlib1g

#### Learn more with OffSec

Want to learn more about curl? get access to in-depth training and hands-on labs:
- WEB-200: 2.2.3. Web Application Enumeration Methodology: Banner Grabbing
- Business Logic Vulnerabilities Skill Path: 1.1. File Upload Attacksx
- Introduction to Secure Software Development: 19. Introduction to Web Services
- Secure Software Development Essentials: 5. Introduction to Web Services
- Web Application Assessment Essentials: 17. Introduction to Web Services
WEB-200 course
Updated on: 2026-Jun-17

### dirsearch

Source: https://www.kali.org/tools/dirsearch/

#### dirsearch

Web path scanner This package contains is a command-line tool designed to brute force
directories and files in webservers.
As a feature-rich tool, dirsearch gives users the opportunity to perform a
complex web content discovering, with many vectors for the wordlist, high
accuracy, impressive performance, advanced connection/request settings, modern
brute-force techniques and nice output.
Installed size: 447 KB How to install: sudo apt install dirsearch
- python3
- python3-bs4
- python3-certifi
- python3-cffi
- python3-chardet
- python3-charset-normalizer
- python3-colorama
- python3-cryptography
- python3-defusedxml
- python3-idna
- python3-jinja2
- python3-markupsafe
- python3-ntlm-auth
- python3-openssl
- python3-pyparsing
- python3-requests
- python3-requests-ntlm
- python3-socks
- python3-urllib3

##### dirsearch

An advanced command-line tool designed to brute force directories and files in webservers

```
root@kali:~# dirsearch -h
Usage: dirsearch.py [-u|--url] target [-e|--extensions] extensions [options]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit

  Mandatory:
    -u URL, --url=URL   Target URL(s), can use multiple flags
    -l PATH, --url-file=PATH
                        URL list file
    --stdin             Read URL(s) from STDIN
    --cidr=CIDR         Target CIDR
    --raw=PATH          Load raw HTTP request from file (use `--scheme` flag
                        to set the scheme)
    -s SESSION_FILE, --session=SESSION_FILE
                        Session file
    --config=PATH       Full path to config file, see 'config.ini' for example
                        (Default: config.ini)

  Dictionary Settings:
    -w WORDLISTS, --wordlists=WORDLISTS
                        Customize wordlists (separated by commas)
    -e EXTENSIONS, --extensions=EXTENSIONS
                        Extension list separated by commas (e.g. php,asp)
    -f, --force-extensions
                        Add extensions to the end of every wordlist entry. By
                        default dirsearch only replaces the %EXT% keyword with
                        extensions
    -O, --overwrite-extensions
                        Overwrite other extensions in the wordlist with your
                        extensions (selected via `-e`)
    --exclude-extensions=EXTENSIONS
                        Exclude extension list separated by commas (e.g.
                        asp,jsp)
    --remove-extensions
                        Remove extensions in all paths (e.g. admin.php ->
                        admin)
    --prefixes=PREFIXES
                        Add custom prefixes to all wordlist entries (separated
                        by commas)
    --suffixes=SUFFIXES
                        Add custom suffixes to all wordlist entries, ignore
                        directories (separated by commas)
    -U, --uppercase     Uppercase wordlist
    -L, --lowercase     Lowercase wordlist
    -C, --capital       Capital wordlist

  General Settings:
    -t THREADS, --threads=THREADS
                        Number of threads
    -r, --recursive     Brute-force recursively
    --deep-recursive    Perform recursive scan on every directory depth (e.g.
                        api/users -> api/)
    --force-recursive   Do recursive brute-force for every found path, not
                        only directories
    -R DEPTH, --max-recursion-depth=DEPTH
                        Maximum recursion depth
    --recursion-status=CODES
                        Valid status codes to perform recursive scan, support
                        ranges (separated by commas)
    --subdirs=SUBDIRS   Scan sub-directories of the given URL[s] (separated by
                        commas)
    --exclude-subdirs=SUBDIRS
                        Exclude the following subdirectories during recursive
                        scan (separated by commas)
    -i CODES, --include-status=CODES
                        Include status codes, separated by commas, support
                        ranges (e.g. 200,300-399)
    -x CODES, --exclude-status=CODES
                        Exclude status codes, separated by commas, support
                        ranges (e.g. 301,500-599)
    --exclude-sizes=SIZES
                        Exclude responses by sizes, separated by commas (e.g.
                        0B,4KB)
    --exclude-text=TEXTS
                        Exclude responses by text, can use multiple flags
    --exclude-regex=REGEX
                        Exclude responses by regular expression
    --exclude-redirect=STRING
                        Exclude responses if this regex (or text) matches
                        redirect URL (e.g. '/index.html')
    --exclude-response=PATH
                        Exclude responses similar to response of this page,
                        path as input (e.g. 404.html)
    --skip-on-status=CODES
                        Skip target whenever hit one of these status codes,
                        separated by commas, support ranges
    --min-response-size=LENGTH
                        Minimum response length
    --max-response-size=LENGTH
                        Maximum response length
    --max-time=SECONDS  Maximum runtime for the scan
    --exit-on-error     Exit whenever an error occurs

  Request Settings:
    -m METHOD, --http-method=METHOD
                        HTTP method (default: GET)
    -d DATA, --data=DATA
                        HTTP request data
    --data-file=PATH    File contains HTTP request data
    -H HEADERS, --header=HEADERS
                        HTTP request header, can use multiple flags
    --header-file=PATH  File contains HTTP request headers
    -F, --follow-redirects
                        Follow HTTP redirects
    --random-agent      Choose a random User-Agent for each request
    --auth=CREDENTIAL   Authentication credential (e.g. user:password or
                        bearer token)
    --auth-type=TYPE    Authentication type (basic, digest, bearer, ntlm, jwt,
                        oauth2)
    --cert-file=PATH    File contains client-side certificate
    --key-file=PATH     File contains client-side certificate private key
                        (unencrypted)
    --user-agent=USER_AGENT
    --cookie=COOKIE     

  Connection Settings:
    --timeout=TIMEOUT   Connection timeout
    --delay=DELAY       Delay between requests
    --proxy=PROXY       Proxy URL (HTTP/SOCKS), can use multiple flags
    --proxy-file=PATH   File contains proxy servers
    --proxy-auth=CREDENTIAL
                        Proxy authentication credential
    --replay-proxy=PROXY
                        Proxy to replay with found paths
    --tor               Use Tor network as proxy
    --scheme=SCHEME     Scheme for raw request or if there is no scheme in the
                        URL (Default: auto-detect)
    --max-rate=RATE     Max requests per second
    --retries=RETRIES   Number of retries for failed requests
    --ip=IP             Server IP address

  Advanced Settings:
    --crawl             Crawl for new paths in responses

  View Settings:
    --full-url          Full URLs in the output (enabled automatically in
                        quiet mode)
    --redirects-history
                        Show redirects history
    --no-color          No colored output
    -q, --quiet-mode    Quiet mode

  Output Settings:
    -o PATH, --output=PATH
                        Output file
    --format=FORMAT     Report format (Available: simple, plain, json, xml,
                        md, csv, html, sqlite)
    --log=PATH          Log file
```

Updated on: 2025-Dec-09

### dnsenum

Source: https://www.kali.org/tools/dnsenum/

#### Tool Documentation:



#### Tool Documentation:

#### dnsenum Usage Example

Don’t do a reverse lookup ( –noreverse ) and save the output to a file ( -o mydomain.xml ) for the domain example.com :

```
root@kali:~# dnsenum --noreverse -o mydomain.xml example.com
dnsenum VERSION:1.2.4

-----   example.com   -----

Host's addresses:
__________________

example.com.                             392      IN    A        93.184.216.119

Name Servers:
______________

b.iana-servers.net.                      122      IN    A        199.43.133.53
a.iana-servers.net.                      122      IN    A        199.43.132.53

Mail (MX) Servers:
___________________
```


#### dnsenum

Tool to enumerate domain DNS information Dnsenum is a multithreaded perl script to enumerate DNS information of a
domain and to discover non-contiguous ip blocks. The main purpose of Dnsenum
is to gather as much information as possible about a domain. The program
currently performs the following operations:
- Get the host’s addresses (A record).
- Get the namservers (threaded).
- Get the MX record (threaded).
- Perform axfr queries on nameservers and get BIND versions(threaded).
- Get extra names and subdomains via google scraping (google query =
“allinurl: -www site:domain”).
- Brute force subdomains from file, can also perform recursion on subdomain
that have NS records (all threaded).
- Calculate C class domain network ranges and perform whois queries on them
(threaded).
- Perform reverse lookups on netranges (C class or/and whois netranges)
(threaded).
- Write to domain_ips.txt file ip-blocks.
This program is useful for pentesters, ethical hackers and forensics experts.
It also can be used for security tests.
Installed size: 87 KB How to install: sudo apt install dnsenum
- libhtml-parser-perl
- libnet-dns-perl
- libnet-ip-perl
- libnet-netmask-perl
- libnet-whois-ip-perl
- libstring-random-perl
- libwww-mechanize-perl
- libxml-writer-perl
- perl

##### dnsenum

- multithread script to enumerate information on a domain and to discover non-contiguous IP blocks

```
root@kali:~# dnsenum -h
dnsenum VERSION:1.3.1
Usage: dnsenum [Options] <domain>
[Options]:
Note: If no -f tag supplied will default to /usr/share/dnsenum/dns.txt or
the dns.txt file in the same directory as dnsenum
GENERAL OPTIONS:
  --dnsserver 	<server>
			Use this DNS server for A, NS and MX queries.
  --enum		Shortcut option equivalent to --threads 5 -s 15 -w.
  -h, --help		Print this help message.
  --noreverse		Skip the reverse lookup operations.
  --nocolor		Disable ANSIColor output.
  --private		Show and save private ips at the end of the file domain_ips.txt.
  --subfile <file>	Write all valid subdomains to this file.
  -t, --timeout <value>	The tcp and udp timeout values in seconds (default: 10s).
  --threads <value>	The number of threads that will perform different queries.
  -v, --verbose		Be verbose: show all the progress and all the error messages.
GOOGLE SCRAPING OPTIONS:
  -p, --pages <value>	The number of google search pages to process when scraping names,
			the default is 5 pages, the -s switch must be specified.
  -s, --scrap <value>	The maximum number of subdomains that will be scraped from Google (default 15).
BRUTE FORCE OPTIONS:
  -f, --file <file>	Read subdomains from this file to perform brute force. (Takes priority over default dns.txt)
  -u, --update	<a|g|r|z>
			Update the file specified with the -f switch with valid subdomains.
	a (all)		Update using all results.
	g		Update using only google scraping results.
	r		Update using only reverse lookup results.
	z		Update using only zonetransfer results.
  -r, --recursion	Recursion on subdomains, brute force all discovered subdomains that have an NS record.
WHOIS NETRANGE OPTIONS:
  -d, --delay <value>	The maximum value of seconds to wait between whois queries, the value is defined randomly, default: 3s.
  -w, --whois		Perform the whois queries on c class network ranges.
			 **Warning**: this can generate very large netranges and it will take lot of time to perform reverse lookups.
REVERSE LOOKUP OPTIONS:
  -e, --exclude	<regexp>
			Exclude PTR records that match the regexp expression from reverse lookup results, useful on invalid hostnames.
OUTPUT OPTIONS:
  -o --output <file>	Output in XML format. Can be imported in MagicTree (www.gremwell.com)
```

#### Learn more with OffSec

Want to learn more about dnsenum? get access to in-depth training and hands-on labs:
- PEN-200: 6.4.1. Information Gathering: DNS Enumeration
- PEN-200: 25.2.2. Enumerating AWS Cloud Infrastructure: Domain and Subdomain Reconnaissance
PEN-200 course
Updated on: 2025-Dec-09

### dnsrecon

Source: https://www.kali.org/tools/dnsrecon/

#### Tool Documentation:



#### Tool Documentation:

#### Video

#### dnsrecon Usage Example

Scan a domain ( -d example.com ), use a dictionary to brute force hostnames ( -D /usr/share/wordlists/dnsmap.txt) , do a standard scan ( -t std ), and save the output to a file ( –xml dnsrecon.xml ):

```
root@kali:~# dnsrecon -d example.com -D /usr/share/wordlists/dnsmap.txt -t std --xml dnsrecon.xml
[*] Performing General Enumeration of Domain:example.com
[*] DNSSEC is configured for example.com
[*] DNSKEYs:
```


#### dnsrecon

Powerful DNS enumeration script DNSRecon is a Python script that provides the ability to perform:
- Check all NS Records for Zone Transfers.
- Enumerate General DNS Records for a given Domain
(MX, SOA, NS, A, AAAA, SPF and TXT).
- Perform common SRV Record Enumeration.
- Top Level Domain (TLD) Expansion.
- Check for Wildcard Resolution.
- Brute Force subdomain and host A and AAAA records
given a domain and a wordlist.
- Perform a PTR Record lookup for a given IP Range or CIDR.
- Check a DNS Server Cached records for A, AAAA and CNAME
- Records provided a list of host records in a text file to check.
- Enumerate Hosts and Subdomains using Google
Installed size: 1.45 MB How to install: sudo apt install dnsrecon
- python3
- python3-dnspython
- python3-loguru
- python3-lxml
- python3-netaddr
- python3-requests

##### dnsrecon

DNS Enumeration and Scanning Tool

```
root@kali:~# dnsrecon -h
usage: dnsrecon [-h] [-d DOMAIN] [-iL INPUT_LIST] [-n NS_SERVER] [-r RANGE]
                [-D DICTIONARY] [-f] [-a] [-s] [-b] [-y] [-k] [-w] [-z]
                [--threads THREADS] [--lifetime LIFETIME]
                [--loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}] [--tcp]
                [--db DB] [-x XML] [-c CSV] [-j JSON] [--iw]
                [--disable_check_nxdomain] [--disable_check_recursion]
                [--disable_check_bindversion] [-V] [-v] [-t TYPE]

options:
  -h, --help            show this help message and exit
  -d, --domain DOMAIN   Target domain.
  -iL, --input-list INPUT_LIST
                        File containing a list of domains to perform DNS enumeration on, one per line.
  -n, --name_server NS_SERVER
                        Domain server to use. If none is given, the SOA of the target will be used. Multiple servers can be specified using a comma separated list.
  -r, --range RANGE     IP range for reverse lookup brute force in formats (first-last) or in (range/bitmask).
  -D, --dictionary DICTIONARY
                        Dictionary file of subdomain and hostnames to use for brute force.
  -f                    Filter out of brute force domain lookup, records that resolve to the wildcard defined IP address when saving records.
  -a                    Perform AXFR with standard enumeration.
  -s                    Perform a reverse lookup of IPv4 ranges in the SPF record with standard enumeration.
  -b                    Perform Bing enumeration with standard enumeration.
  -y                    Perform Yandex enumeration with standard enumeration.
  -k                    Perform crt.sh enumeration with standard enumeration.
  -w                    Perform deep whois record analysis and reverse lookup of IP ranges found through Whois when doing a standard enumeration.
  -z                    Performs a DNSSEC zone walk with standard enumeration.
  --threads THREADS     Number of threads to use in reverse lookups, forward lookups, brute force and SRV record enumeration.
  --lifetime LIFETIME   Time to wait for a server to respond to a query. default is 3.0
  --loglevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Log level to use. default is INFO
  --tcp                 Use TCP protocol to make queries.
  --db DB               SQLite 3 file to save found records.
  -x, --xml XML         XML file to save found records.
  -c, --csv CSV         Save output to a comma separated value file.
  -j, --json JSON       save output to a JSON file.
  --iw                  Continue brute forcing a domain even if a wildcard record is discovered.
  --disable_check_nxdomain
                        Disables check for NXDOMAIN hijacking on name servers.
  --disable_check_recursion
                        Disables check for recursion on name servers
  --disable_check_bindversion
                        Disables check for BIND version on name servers
  -V, --version         DNSrecon version
  -v, --verbose         Enable verbosity
  -t, --type TYPE       Type of enumeration to perform.
                        Possible types:
                            std:      SOA, NS, A, AAAA, MX and SRV.
                            rvl:      Reverse lookup of a given CIDR or IP range.
                            brt:      Brute force domains and hosts using a given dictionary.
                            srv:      SRV records.
                            axfr:     Test all NS servers for a zone transfer.
                            bing:     Perform Bing search for subdomains and hosts.
                            yand:     Perform Yandex search for subdomains and hosts.
                            crt:      Perform crt.sh search for subdomains and hosts.
                            snoop:    Perform cache snooping against all NS servers for a given domain, testing
                                      all with file containing the domains, file given with -D option.
                        
                            tld:      Remove the TLD of given domain and test against all TLDs registered in IANA.
                            zonewalk: Perform a DNSSEC zone walk using NSEC records.
```

#### Learn more with OffSec

Want to learn more about dnsrecon? get access to in-depth training and hands-on labs:
- PEN-200: 6.4.1. Information Gathering: DNS Enumeration
PEN-200 course
Updated on: 2025-Dec-09

### dnsx

Source: https://www.kali.org/tools/dnsx/

#### dnsx

Perform multiple dns queries This package contains a fast and multi-purpose DNS toolkit allow to run
multiple probes using retryabledns library, that allows you to perform
multiple DNS queries of your choice with a list of user supplied resolvers,
additionally supports DNS wildcard filtering like shuffledns
( https://github.com/projectdiscovery/shuffledns) .
Features
- Simple and Handy utility to query DNS records
- Supports A, AAAA, CNAME, PTR, NS, MX, TXT, SOA
- Supports DNS Status Code probing
- Supports DNS Tracing
- Handles wildcard subdomains in automated way.
- Stdin and stdout support to work with other tools.
Installed size: 30.50 MB How to install: sudo apt install dnsx
- libc6

##### dnsx

```
root@kali:~# dnsx -h
dnsx is a fast and multi-purpose DNS toolkit allow to run multiple probes using retryabledns library.

Usage:
  dnsx [flags]

Flags:
INPUT:
   -l, -list string      list of sub(domains)/hosts to resolve (file or stdin)
   -d, -domain string    list of domain to bruteforce (file or comma separated or stdin)
   -w, -wordlist string  list of words to bruteforce (file or comma separated or stdin)

QUERY:
   -a                       query A record (default)
   -aaaa                    query AAAA record
   -cname                   query CNAME record
   -ns                      query NS record
   -txt                     query TXT record
   -srv                     query SRV record
   -ptr                     query PTR record
   -mx                      query MX record
   -soa                     query SOA record
   -any                     query ANY record
   -axfr                    query AXFR
   -caa                     query CAA record
   -all, -recon             query all the dns records (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa)
   -e, -exclude-type value  dns query type to exclude (a,aaaa,cname,ns,txt,srv,ptr,mx,soa,axfr,caa) (default none)

FILTER:
   -re, -resp                          display dns response
   -ro, -resp-only                     display dns response only
   -rc, -rcode string                  filter result by dns status code (eg. -rcode noerror,servfail,refused)
   -rtf, -response-type-filter string  return entries with no records for the specified query types (e.g., a, cname)

PROBE:
   -cdn  display cdn name
   -asn  display host asn information

RATE-LIMIT:
   -t, -threads int      number of concurrent threads to use (default 100)
   -rl, -rate-limit int  number of dns request/second to make (disabled as default) (default -1)

UPDATE:
   -up, -update                 update dnsx to latest version
   -duc, -disable-update-check  disable automatic dnsx update check

OUTPUT:
   -o, -output string  file to write output
   -j, -json           write output in JSONL(ines) format
   -omit-raw, -or      omit raw dns response from jsonl output

DEBUG:
   -hc, -health-check  run diagnostic check up
   -silent             display only results in the output
   -v, -verbose        display verbose output
   -raw, -debug        display raw dns response
   -stats              display stats of the running scan
   -version            display version of dnsx
   -nc, -no-color      disable color in output

OPTIMIZATION:
   -retry int                number of dns attempts to make (must be at least 1) (default 2)
   -hf, -hostsfile           use system host file
   -trace                    perform dns tracing
   -trace-max-recursion int  Max recursion for dns trace (default 255)
   -resume                   resume existing scan
   -stream                   stream mode (wordlist, wildcard, stats and stop/resume will be disabled)
   -timeout value            maximum time to wait for a DNS query to complete (default 3s)

CONFIGURATIONS:
   -auth                         configure ProjectDiscovery Cloud Platform (PDCP) api key (default true)
   -r, -resolver string          list of resolvers to use (file or comma separated)
   -wt, -wildcard-threshold int  wildcard filter threshold (default 5)
   -wd, -wildcard-domain string  domain name for wildcard filtering (other flags will be ignored - only json output is supported)
   -proxy string                 proxy to use (eg socks5://127.0.0.1:8080)
```

Updated on: 2026-Mar-02

### enum4linux

Source: https://www.kali.org/tools/enum4linux/

#### Tool Documentation:



#### Tool Documentation:

#### enum4linux Usage Example

Attempt to get the userlist ( -U ) and OS information ( -o ) from the target ( 192.168.1.200 ):

```
root@kali:~# enum4linux -U -o 192.168.1.200
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Aug 17 12:17:32 2014

 ==========================
|    Target Information    |
 ==========================
Target ........... 192.168.1.200
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ======================================================
|    Enumerating Workgroup/Domain on 192.168.1.200   |
 ======================================================
[+] Got domain/workgroup name: KALI
```


#### enum4linux

Enumerates info from Windows and Samba systems Enum4linux is a tool for enumerating information from Windows and Samba
systems. It attempts to offer similar functionality to enum.exe formerly
available from www.bindview.com .
It is written in PERL and is basically a wrapper around the Samba tools
smbclient, rpclient, net and nmblookup. The samba package is therefore a
dependency.
Features include:

```
RID Cycling (When RestrictAnonymous is set to 1 on Windows 2000)
 User Listing (When RestrictAnonymous is set to 0 on Windows 2000)
 Listing of Group Membership Information
 Share Enumeration
 Detecting if host is in a Workgroup or a Domain
 Identifying the remote Operating System
 Password Policy Retrieval (using polenum)
```

Installed size: 58 KB How to install: sudo apt install enum4linux
- ldap-utils
- perl
- polenum
- samba
- smbclient

##### enum4linux

```
root@kali:~# enum4linux -h
enum4linux v0.9.1 (http://labs.portcullis.co.uk/application/enum4linux/)
Copyright (C) 2011 Mark Lowe (
[email protected]
)

Simple wrapper around the tools in the samba package to provide similar 
functionality to enum.exe (formerly from www.bindview.com).  Some additional 
features such as RID cycling have also been added for convenience.

Usage: ./enum4linux.pl [options] ip

Options are (like "enum"):
    -U        get userlist
    -M        get machine list*
    -S        get sharelist
    -P        get password policy information
    -G        get group and member list
    -d        be detailed, applies to -U and -S
    -u user   specify username to use (default "")  
    -p pass   specify password to use (default "")   

The following options from enum.exe aren't implemented: -L, -N, -D, -f

Additional options:
    -a        Do all simple enumeration (-U -S -G -P -r -o -n -i).
              This option is enabled if you don't provide any other options.
    -h        Display this help message and exit
    -r        enumerate users via RID cycling
    -R range  RID ranges to enumerate (default: 500-550,1000-1050, implies -r)
    -K n      Keep searching RIDs until n consective RIDs don't correspond to
              a username.  Impies RID range ends at 999999. Useful 
	      against DCs.
    -l        Get some (limited) info via LDAP 389/TCP (for DCs only)
    -s file   brute force guessing for share names
    -k user   User(s) that exists on remote system (default: administrator,guest,krbtgt,domain admins,root,bin,none)
              Used to get sid with "lookupsid known_username"
    	      Use commas to try several users: "-k admin,user1,user2"
    -o        Get OS information
    -i        Get printer information
    -w wrkg   Specify workgroup manually (usually found automatically)
    -n        Do an nmblookup (similar to nbtstat)
    -v        Verbose.  Shows full commands being run (net, rpcclient, etc.)
    -A        Aggressive. Do write checks on shares etc

RID cycling should extract a list of users from Windows (or Samba) hosts 
which have RestrictAnonymous set to 1 (Windows NT and 2000), or "Network 
access: Allow anonymous SID/Name translation" enabled (XP, 2003).

NB: Samba servers often seem to have RIDs in the range 3000-3050.

Dependancy info: You will need to have the samba package installed as this 
script is basically just a wrapper around rpcclient, net, nmblookup and 
smbclient.  Polenum from http://labs.portcullis.co.uk/application/polenum/ 
is required to get Password Policy info.
```

Updated on: 2025-Dec-09

### enum4linux-ng

Source: https://www.kali.org/tools/enum4linux-ng/

#### enum4linux-ng

Next generation version of enum4linux Next generation version of enum4linux (a Windows/Samba enumeration tool) with
additional features like JSON/YAML export. Aimed for security professionals and
CTF players.
Installed size: 193 KB How to install: sudo apt install enum4linux-ng
- python3
- python3-impacket
- python3-ldap3
- python3-yaml
- samba-common-bin
- smbclient

##### enum4linux-ng

```
root@kali:~# enum4linux-ng -h
ENUM4LINUX - next generation (v1.3.10)

usage: enum4linux-ng [-h] [-A] [-As] [-U] [-G] [-Gm] [-S] [-C] [-P] [-O] [-L]
                     [-I] [-R [BULK_SIZE]] [-N] [-w DOMAIN] [-u USER] [-p PW |
                     -K TICKET_FILE | -H NTHASH] [--local-auth] [-d]
                     [-k USERS] [-r RANGES] [-s SHARES_FILE] [-t TIMEOUT] [-v]
                     [--keep] [-oJ OUT_JSON_FILE | -oY OUT_YAML_FILE |
                     -oA OUT_FILE]
                     host

This tool is a rewrite of Mark Lowe's enum4linux.pl, a tool for enumerating
information from Windows and Samba systems. It is mainly a wrapper around the
Samba tools nmblookup, net, rpcclient and smbclient. Other than the original
tool it allows to export enumeration results as YAML or JSON file, so that it
can be further processed with other tools. The tool tries to do a 'smart'
enumeration. It first checks whether SMB or LDAP is accessible on the target.
Depending on the result of this check, it will dynamically skip checks (e.g.
LDAP checks if LDAP is not running). If SMB is accessible, it will always
check whether a session can be set up or not. If no session can be set up, the
tool will stop enumeration. The enumeration process can be interupted with
CTRL+C. If the options -oJ or -oY are provided, the tool will write out the
current enumeration state to the JSON or YAML file, once it receives SIGINT
triggered by CTRL+C. The tool was made for security professionals and CTF
players. Illegal use is prohibited.

positional arguments:
  host

options:
  -h, --help         show this help message and exit
  -A                 Do all simple enumeration including nmblookup (-U -G -S
                     -P -O -N -I -L). This option is enabled if you don't
                     provide any other option.
  -As                Do all simple short enumeration without NetBIOS names
                     lookup (-U -G -S -P -O -I -L)
  -U                 Get users via RPC
  -G                 Get groups via RPC
  -Gm                Get groups with group members via RPC
  -S                 Get shares via RPC
  -C                 Get services via RPC
  -P                 Get password policy information via RPC
  -O                 Get OS information via RPC
  -L                 Get additional domain info via LDAP/LDAPS (for DCs only)
  -I                 Get printer information via RPC
  -R [BULK_SIZE]     Enumerate users via RID cycling. Optionally specify the
                     lookup request size (BULK_SIZE).
  -N                 Do an NetBIOS names lookup (similar to nbtstat) and try
                     to retrieve workgroup from output
  -w DOMAIN          Specify workgroup/domain manually (usually found
                     automatically)
  -u USER            Specify username to use (default "")
  -p PW              Specify password to use (default "")
  -K TICKET_FILE     Try to authenticate with Kerberos, only useful in Active
                     Directory environment (Note: DNS must be setup correctly
                     for this option to work
  -H NTHASH          Try to authenticate with hash
  --local-auth       Authenticate locally to target
  -d                 Get detailed information for users and groups, applies to
                     -U, -G and -R
  -k USERS           User(s) that exists on remote system (default:
                     administrator,guest,krbtgt,domain admins,root,bin,none).
                     Used to get sid with "lookupsids"
  -r RANGES          RID ranges to enumerate (default: 500-550,1000-1050)
  -s SHARES_FILE     Brute force guessing for shares
  -t TIMEOUT         Sets connection timeout in seconds (default: 10s)
  -v                 Verbose, show full samba tools commands being run (net,
                     rpcclient, etc.)
  --keep             Don't delete the Samba configuration file created during
                     tool run after enumeration (useful with -v)
  -oJ OUT_JSON_FILE  Writes output to JSON file (extension is added
                     automatically)
  -oY OUT_YAML_FILE  Writes output to YAML file (extension is added
                     automatically)
  -oA OUT_FILE       Writes output to YAML and JSON file (extensions are added
                     automatically)
```

Updated on: 2026-Mar-02

### evil-winrm

Source: https://www.kali.org/tools/evil-winrm/

#### evil-winrm

Ultimate WinRM shell for hacking/pentesting This package contains the ultimate WinRM shell for hacking/pentesting.
WinRM (Windows Remote Management) is the Microsoft implementation of
WS-Management Protocol. A standard SOAP based protocol that allows hardware
and operating systems from different vendors to interoperate. Microsoft
included it in their Operating Systems in order to make life easier to system
administrators.
This program can be used on any Microsoft Windows Servers with this feature
enabled (usually at port 5985), of course only if you have credentials and
permissions to use it. So it could be used in a post-exploitation
hacking/pentesting phase. The purpose of this program is to provide nice and
easy-to-use features for hacking. It can be used with legitimate purposes by
system administrators as well but the most of its features are focused on
hacking/pentesting stuff.
It is using PSRP (Powershell Remoting Protocol) for initializing runspace
pools as well as creating and processing pipelines.
Installed size: 172 KB How to install: sudo apt install evil-winrm
- ruby
- ruby-benchmark
- ruby-csv
- ruby-fileutils
- ruby-logger
- ruby-stringio
- ruby-syslog
- ruby-winrm
- ruby-winrm-fs

##### evil-winrm

```
root@kali:~# evil-winrm -h
                                        
Evil-WinRM shell v3.9

Usage: evil-winrm -i IP -u USER [-s SCRIPTS_PATH] [-e EXES_PATH] [-P PORT] [-a USERAGENT] [-p PASS] [-H HASH] [-U URL] [-S] [-c PUBLIC_KEY_PATH ] [-k PRIVATE_KEY_PATH ] [-r REALM] [--spn SPN_PREFIX] [-l]
    -S, --ssl                        Enable ssl
    -a, --user-agent USERAGENT       Specify connection user-agent (default Microsoft WinRM Client)
    -c, --pub-key PUBLIC_KEY_PATH    Local path to public key certificate
    -k, --priv-key PRIVATE_KEY_PATH  Local path to private key certificate
    -r, --realm DOMAIN               Kerberos auth, it has to be set also in /etc/krb5.conf file using this format -> CONTOSO.COM = { kdc = fooserver.contoso.com }
    -s, --scripts PS_SCRIPTS_PATH    Powershell scripts local path
        --spn SPN_PREFIX             SPN prefix for Kerberos auth (default HTTP)
    -e, --executables EXES_PATH      C# executables local path
    -i, --ip IP                      Remote host IP or hostname. FQDN for Kerberos auth (required)
    -U, --url URL                    Remote url endpoint (default /wsman)
    -u, --user USER                  Username (required if not using kerberos)
    -p, --password PASS              Password
    -H, --hash HASH                  NTHash
    -P, --port PORT                  Remote host port (default 5985)
    -V, --version                    Show version
    -n, --no-colors                  Disable colors
    -N, --no-rpath-completion        Disable remote path completion
    -l, --log                        Log the WinRM session
    -h, --help                       Display this help message
```

#### Learn more with OffSec

Want to learn more about evil-winrm? get access to in-depth training and hands-on labs:
- PEN-200: 17.1.4. Windows Privilege Escalation: Information Goldmine PowerShell
- SOC-200: 5. Windows Client-Side Attacks
PEN-200 course
SOC-200 course
Updated on: 2026-May-25

### feroxbuster

Source: https://www.kali.org/tools/feroxbuster/

#### feroxbuster

Fast, simple, recursive content discovery tool written in Rust feroxbuster is a tool designed to perform Forced Browsing.
Forced browsing is an attack where the aim is to enumerate and
access resources that are not referenced by the web application,
but are still accessible by an attacker.
feroxbuster uses brute force combined with a wordlist to search
for unlinked content in target directories. These resources may
store sensitive information about web applications and operational
systems, such as source code, credentials, internal network
addressing, etc…
This attack is also known as Predictable Resource Location, File
Enumeration, Directory Enumeration, and Resource Enumeration.
Installed size: 12.27 MB How to install: sudo apt install feroxbuster
- fonts-noto-color-emoji
- libc6
- libgcc-s1

##### feroxbuster

Manual page for feroxbuster 2.13.1

```
root@kali:~# feroxbuster --help
A fast, simple, recursive content discovery tool.

Usage: feroxbuster [OPTIONS]

Options:
  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version

Target selection:
  -u, --url <URL>
          The target URL (required, unless [--stdin || --resume-from ||
          --request-file] used)

      --stdin
          Read url(s) from STDIN

      --resume-from <STATE_FILE>
          State file from which to resume a partially complete scan (ex.
          --resume-from ferox-1606586780.state)

      --request-file <REQUEST_FILE>
          Raw HTTP request file to use as a template for all requests

Composite settings:
      --burp
          Set --proxy to http://127.0.0.1:8080 and set --insecure to true

      --burp-replay
          Set --replay-proxy to http://127.0.0.1:8080 and set --insecure to true

      --data-urlencoded <DATA>
          Set -H 'Content-Type: application/x-www-form-urlencoded', --data to
          <data-urlencoded> (supports @file) and -m to POST

      --data-json <DATA>
          Set -H 'Content-Type: application/json', --data to <data-json>
          (supports @file) and -m to POST

      --smart
          Set --auto-tune, --collect-words, and --collect-backups to true

      --thorough
          Use the same settings as --smart and set --collect-extensions and
          --scan-dir-listings to true

Proxy settings:
  -p, --proxy <PROXY>
          Proxy to use for requests (ex: http(s)://host:port,
          socks5(h)://host:port)

  -P, --replay-proxy <REPLAY_PROXY>
          Send only unfiltered requests through a Replay Proxy, instead of all
          requests

  -R, --replay-codes <REPLAY_CODE>...
          Status Codes to send through a Replay Proxy when found (default:
          --status-codes value)

Request settings:
  -a, --user-agent <USER_AGENT>
          Sets the User-Agent (default: feroxbuster/2.13.1)

  -A, --random-agent
          Use a random User-Agent

  -x, --extensions <FILE_EXTENSION>...
          File extension(s) to search for (ex: -x php -x pdf js); reads values
          (newline-separated) from file if input starts with an @ (ex: @ext.txt)

  -m, --methods <HTTP_METHODS>...
          Which HTTP request method(s) should be sent (default: GET)

      --data <DATA>
          Request's Body; can read data from a file if input starts with an @
          (ex: @post.bin)

  -H, --headers <HEADER>...
          Specify HTTP headers to be used in each request (ex: -H Header:val -H
          'stuff: things')

  -b, --cookies <COOKIE>...
          Specify HTTP cookies to be used in each request (ex: -b stuff=things)

  -Q, --query <QUERY>...
          Request's URL query parameters (ex: -Q token=stuff -Q secret=key)

  -f, --add-slash
          Append / to each request's URL

      --protocol <PROTOCOL>
          Specify the protocol to use when targeting via --request-file or --url
          with domain only (default: https)

Request filters:
      --dont-scan <URL>...
          URL(s) or Regex Pattern(s) to exclude from recursion/scans

      --scope <URL>...
          Additional domains/URLs to consider in-scope for scanning (in addition
          to current domain)

Response filters:
  -S, --filter-size <SIZE>...
          Filter out messages of a particular size (ex: -S 5120 -S 4927,1970)

  -X, --filter-regex <REGEX>...
          Filter out messages via regular expression matching on the response's
          body/headers (ex: -X '^ignore me$')

  -W, --filter-words <WORDS>...
          Filter out messages of a particular word count (ex: -W 312 -W 91,82)

  -N, --filter-lines <LINES>...
          Filter out messages of a particular line count (ex: -N 20 -N 31,30)

  -C, --filter-status <STATUS_CODE>...
          Filter out status codes (deny list) (ex: -C 200 -C 401)

      --filter-similar-to <UNWANTED_PAGE>...
          Filter out pages that are similar to the given page (ex.
          --filter-similar-to http://site.xyz/soft404)

  -s, --status-codes <STATUS_CODE>...
          Status Codes to include (allow list) (default: All Status Codes)

      --unique
          Only show unique responses

Client settings:
  -T, --timeout <SECONDS>
          Number of seconds before a client's request times out (default: 7)

  -r, --redirects
          Allow client to follow redirects

  -k, --insecure
          Disables TLS certificate validation in the client

      --server-certs <PEM|DER>...
          Add custom root certificate(s) for servers with unknown certificates

      --client-cert <PEM>
          Add a PEM encoded certificate for mutual authentication (mTLS)

      --client-key <PEM>
          Add a PEM encoded private key for mutual authentication (mTLS)

Scan settings:
  -t, --threads <THREADS>
          Number of concurrent threads (default: 50)

  -n, --no-recursion
          Do not scan recursively

  -d, --depth <RECURSION_DEPTH>
          Maximum recursion depth, a depth of 0 is infinite recursion (default:
          4)

      --force-recursion
          Force recursion attempts on all 'found' endpoints (still respects
          recursion depth)

      --dont-extract-links
          Don't extract links from response body (html, javascript, etc...)

  -L, --scan-limit <SCAN_LIMIT>
          Limit total number of concurrent scans (default: 0, i.e. no limit)

      --parallel <PARALLEL_SCANS>
          Run parallel feroxbuster instances (one child process per url passed
          via stdin)

      --rate-limit <RATE_LIMIT>
          Limit number of requests per second (per directory) (default: 0, i.e.
          no limit)

      --response-size-limit <BYTES>
          Limit size of response body to read in bytes (default: 4MB)

      --time-limit <TIME_SPEC>
          Limit total run time of all scans (ex: --time-limit 10m)

  -w, --wordlist <FILE>
          Path or URL of the wordlist

      --auto-tune
          Automatically lower scan rate when an excessive amount of errors are
          encountered

      --auto-bail
          Automatically stop scanning when an excessive amount of errors are
          encountered

  -D, --dont-filter
          Don't auto-filter wildcard responses

      --scan-dir-listings
          Force scans to recurse into directory listings

Dynamic collection settings:
  -E, --collect-extensions
          Automatically discover extensions and add them to --extensions (unless
          they're in --dont-collect)

  -B, --collect-backups [<collect_backups>...]
          Automatically request likely backup extensions for "found" urls
          (default: ~, .bak, .bak2, .old, .1)

  -g, --collect-words
          Automatically discover important words from within responses and add
          them to the wordlist

  -I, --dont-collect <FILE_EXTENSION>...
          File extension(s) to Ignore while collecting extensions (only used
          with --collect-extensions)

Output settings:
  -v, --verbosity...
          Increase verbosity level (use -vv or more for greater effect.
          [CAUTION] 4 -v's is probably too much)

      --silent
          Only print URLs (or JSON w/ --json) + turn off logging (good for
          piping a list of urls to other commands)

  -q, --quiet
          Hide progress bars and banner (good for tmux windows w/ notifications)

      --json
          Emit JSON logs to --output and --debug-log instead of normal text

  -o, --output <FILE>
          Output file to write results to (use w/ --json for JSON entries)

      --debug-log <FILE>
          Output file to write log entries (use w/ --json for JSON entries)

      --no-state
          Disable state output file (*.state)

      --limit-bars <NUM_BARS_TO_SHOW>
          Number of directory scan bars to show at any given time (default: no
          limit)

Update settings:
  -U, --update
          Update feroxbuster to the latest version

NOTE:
    Options that take multiple values are very flexible.  Consider the following
    ways of specifying
    extensions:
        feroxbuster -u http://127.1 -x pdf -x js,html -x php txt json,docx

    The command above adds .pdf, .js, .html, .php, .txt, .json, and .docx to
    each url

    All of the methods above (multiple flags, space separated, comma separated,
    etc...) are valid
    and interchangeable.  The same goes for urls, headers, status codes,
    queries, and size filters.

EXAMPLES:
    Multiple headers:
        feroxbuster -u http://127.1 -H Accept:application/json "Authorization:
        Bearer {token}"

    IPv6, non-recursive scan with INFO-level logging enabled:
        feroxbuster -u http://[::1] --no-recursion -vv

    Read urls from STDIN; pipe only resulting urls out to another tool
        cat targets | feroxbuster --stdin --silent -s 200 301 302 --redirects -x
        js | fff -s 200 -o js-files

    Proxy traffic through Burp
        feroxbuster -u http://127.1 --burp

    Proxy traffic through a SOCKS proxy
        feroxbuster -u http://127.1 --proxy socks5://127.0.0.1:9050

    Pass auth token via query parameter
        feroxbuster -u http://127.1 --query token=0123456789ABCDEF

    Ludicrous speed... go!
        feroxbuster -u http://127.1 --threads 200
        
    Limit to a total of 60 active requests at any given time (threads * scan
    limit)
        feroxbuster -u http://127.1 --threads 30 --scan-limit 2
    
    Send all 200/302 responses to a proxy (only proxy requests/responses you
    care about)
        feroxbuster -u http://127.1 --replay-proxy http://localhost:8080
        --replay-codes 200 302 --insecure
        
    Abort or reduce scan speed to individual directory scans when too many
    errors have occurred
        feroxbuster -u http://127.1 --auto-bail
        feroxbuster -u http://127.1 --auto-tune
        
    Examples and demonstrations of all features
        https://epi052.github.io/feroxbuster-docs/docs/examples/
```

Updated on: 2026-May-25

### ffuf

Source: https://www.kali.org/tools/ffuf/

#### ffuf

Fast web fuzzer written in Go (program) ffuf is a fast web fuzzer written in Go that allows typical directory
discovery, virtual host discovery (without DNS records) and GET and POST
parameter fuzzing.
This program is useful for pentesters, ethical hackers and forensics experts.
It also can be used for security tests.
Installed size: 9.42 MB How to install: sudo apt install ffuf
- libc6

##### ffuf

Fast web fuzzer written in Go

```
root@kali:~# ffuf -h
Fuzz Faster U Fool - v2.1.0-dev

HTTP OPTIONS:
  -H                  Header `"Name: Value"`, separated by colon. Multiple -H flags are accepted.
  -X                  HTTP method to use
  -b                  Cookie data `"NAME1=VALUE1; NAME2=VALUE2"` for copy as curl functionality.
  -cc                 Client cert for authentication. Client key needs to be defined as well for this to work
  -ck                 Client key for authentication. Client certificate needs to be defined as well for this to work
  -d                  POST data
  -http2              Use HTTP2 protocol (default: false)
  -ignore-body        Do not fetch the response content. (default: false)
  -r                  Follow redirects (default: false)
  -raw                Do not encode URI (default: false)
  -recursion          Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)
  -recursion-depth    Maximum recursion depth. (default: 0)
  -recursion-strategy Recursion strategy: "default" for a redirect based, and "greedy" to recurse on all matches (default: default)
  -replay-proxy       Replay matched requests using this proxy.
  -sni                Target TLS SNI, does not support FUZZ keyword
  -timeout            HTTP request timeout in seconds. (default: 10)
  -u                  Target URL
  -x                  Proxy URL (SOCKS5 or HTTP). For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080

GENERAL OPTIONS:
  -V                  Show version information. (default: false)
  -ac                 Automatically calibrate filtering options (default: false)
  -acc                Custom auto-calibration string. Can be used multiple times. Implies -ac
  -ach                Per host autocalibration (default: false)
  -ack                Autocalibration keyword (default: FUZZ)
  -acs                Custom auto-calibration strategies. Can be used multiple times. Implies -ac
  -c                  Colorize output. (default: false)
  -config             Load configuration from a file
  -json               JSON output, printing newline-delimited JSON records (default: false)
  -maxtime            Maximum running time in seconds for entire process. (default: 0)
  -maxtime-job        Maximum running time in seconds per job. (default: 0)
  -noninteractive     Disable the interactive console functionality (default: false)
  -p                  Seconds of `delay` between requests, or a range of random delay. For example "0.1" or "0.1-2.0"
  -rate               Rate of requests per second (default: 0)
  -s                  Do not print additional information (silent mode) (default: false)
  -sa                 Stop on all error cases. Implies -sf and -se. (default: false)
  -scraperfile        Custom scraper file path
  -scrapers           Active scraper groups (default: all)
  -se                 Stop on spurious errors (default: false)
  -search             Search for a FFUFHASH payload from ffuf history
  -sf                 Stop when > 95% of responses return 403 Forbidden (default: false)
  -t                  Number of concurrent threads. (default: 40)
  -v                  Verbose output, printing full URL and redirect location (if any) with the results. (default: false)

MATCHER OPTIONS:
  -mc                 Match HTTP status codes, or "all" for everything. (default: 200-299,301,302,307,401,403,405,500)
  -ml                 Match amount of lines in response
  -mmode              Matcher set operator. Either of: and, or (default: or)
  -mr                 Match regexp
  -ms                 Match HTTP response size
  -mt                 Match how many milliseconds to the first response byte, either greater or less than. EG: >100 or <100
  -mw                 Match amount of words in response

FILTER OPTIONS:
  -fc                 Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl                 Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fmode              Filter set operator. Either of: and, or (default: or)
  -fr                 Filter regexp
  -fs                 Filter HTTP response size. Comma separated list of sizes and ranges
  -ft                 Filter by number of milliseconds to the first response byte, either greater or less than. EG: >100 or <100
  -fw                 Filter by amount of words in response. Comma separated list of word counts and ranges

INPUT OPTIONS:
  -D                  DirSearch wordlist compatibility mode. Used in conjunction with -e flag. (default: false)
  -e                  Comma separated list of extensions. Extends FUZZ keyword.
  -enc                Encoders for keywords, eg. 'FUZZ:urlencode b64encode'
  -ic                 Ignore wordlist comments (default: false)
  -input-cmd          Command producing the input. --input-num is required when using this input method. Overrides -w.
  -input-num          Number of inputs to test. Used in conjunction with --input-cmd. (default: 100)
  -input-shell        Shell to be used for running command
  -mode               Multi-wordlist operation mode. Available modes: clusterbomb, pitchfork, sniper (default: clusterbomb)
  -request            File containing the raw http request
  -request-proto      Protocol to use along with raw request (default: https)
  -w                  Wordlist file path and (optional) keyword separated by colon. eg. '/path/to/wordlist:KEYWORD'

OUTPUT OPTIONS:
  -debug-log          Write all of the internal logging to the specified file.
  -o                  Write output to file
  -od                 Directory path to store matched results to.
  -of                 Output file format. Available formats: json, ejson, html, md, csv, ecsv (or, 'all' for all formats) (default: json)
  -or                 Don't create the output file if we don't have results (default: false)

EXAMPLE USAGE:
  Fuzz file paths from wordlist.txt, match all responses but filter out those with content-size 42.
  Colored, verbose output.
    ffuf -w wordlist.txt -u https://example.org/FUZZ -mc all -fs 42 -c -v

  Fuzz Host-header, match HTTP 200 responses.
    ffuf -w hosts.txt -u https://example.org/ -H "Host: FUZZ" -mc 200

  Fuzz POST JSON data. Match all responses not containing text "error".
    ffuf -w entries.txt -u https://example.org/ -X POST -H "Content-Type: application/json" \
      -d '{"name": "FUZZ", "anotherkey": "anothervalue"}' -fr "error"

  Fuzz multiple locations. Match only responses reflecting the value of "VAL" keyword. Colored.
    ffuf -w params.txt:PARAM -w values.txt:VAL -u https://example.org/?PARAM=VAL -mr "VAL" -c

  More information and examples: https://github.com/ffuf/ffuf
```

#### Learn more with OffSec

Want to learn more about ffuf? get access to in-depth training and hands-on labs:
- WEB-200: 2.2.6. Web Application Enumeration Methodology: Information Disclosure
WEB-200 course
Updated on: 2026-May-25

### gobuster

Source: https://www.kali.org/tools/gobuster/

**Invocation: subcommand-first.** `gobuster` requires one of these before its flags: dir, dns, fuzz, gcs, s3, tftp, vhost.
So `gobuster <subcommand> [flags]`, never `gobuster [flags]` — its per-subcommand flags do not appear in `gobuster --help`.

#### gobuster

High-performance discovery tool for directories, DNS and cloud storage Gobuster is a high-performance tool used to brute-force and discover:
- URIs (directories and files) in web sites
- DNS subdomains (with wildcard support)
- Virtual Host names on target web servers
- Open Amazon S3 and Google Cloud Storage (GCS) buckets
- Open TFTP servers
- Custom fuzzing with customizable parameters
Gobuster is designed for penetration testers, security professionals,
and forensics experts to perform security assessments and reconnaissance.
Installed size: 9.17 MB How to install: sudo apt install gobuster
- libc6

##### gobuster

Directory/file, DNS and virtual host brute-forcing tool written in Go

```
root@kali:~# gobuster -h
NAME:
   gobuster - the tool you love

USAGE:
   gobuster command [command options]

VERSION:
   3.8.2

AUTHORS:
   Christian Mehlmauer (@firefart)
   OJ Reeves (@TheColonial)

COMMANDS:
   dir      Uses directory/file enumeration mode
   vhost    Uses VHOST enumeration mode (you most probably want to use the IP address as the URL parameter)
   dns      Uses DNS subdomain enumeration mode
   fuzz     Uses fuzzing mode. Replaces the keyword FUZZ in the URL, Headers and the request body
   tftp     Uses TFTP enumeration mode
   s3       Uses aws bucket enumeration mode
   gcs      Uses gcs bucket enumeration mode
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```

#### Learn more with OffSec

Want to learn more about gobuster? get access to in-depth training and hands-on labs:
- PEN-200: 8. Introduction to Web Application Attacks
- PEN-200: 6.5.1. Information Gathering: Active LLM-Aided enumeration
PEN-200 course
WEB-200 course
Updated on: 2026-Mar-02

### hydra

Source: https://www.kali.org/tools/hydra/

#### Tool Documentation:



#### Tool Documentation:

#### hydra Usage Example

Attempt to login as the root user ( -l root ) using a password list ( -P /usr/share/wordlists/metasploit/unix_passwords.txt ) with 6 threads ( -t 6 ) on the given SSH server ( ssh://192.168.1.123 ):

```
root@kali:~# hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt -t 6 ssh://192.168.1.123
Hydra v7.6 (c)2013 by van Hauser/THC & David Maciejak - for legal purposes only

Hydra (http://www.thc.org/thc-hydra) starting at 2014-05-19 07:53:33
[DATA] 6 tasks, 1 server, 1003 login tries (l:1/p:1003), ~167 tries per task
[DATA] attacking service ssh on port 22
```

#### pw-inspector Usage Example

Read in a list of passwords ( -i /usr/share/wordlists/nmap.lst ) and save to a file ( -o /root/passes.txt ), selecting passwords of a minimum length of 6 ( -m 6 ) and a maximum length of 10 ( -M 10 ):

```
root@kali:~# pw-inspector -i /usr/share/wordlists/nmap.lst -o /root/passes.txt -m 6 -M 10
root@kali:~# wc -l /usr/share/wordlists/nmap.lst
5086 /usr/share/wordlists/nmap.lst
root@kali:~# wc -l /root/passes.txt
4490 /root/passes.txt
```


#### hydra

Very fast network logon cracker Hydra is a parallelized login cracker which supports numerous protocols
to attack. It is very fast and flexible, and new modules are easy to add.
This tool makes it possible for researchers and security consultants to
show how easy it would be to gain unauthorized access to a system
remotely.
It supports: Cisco AAA, Cisco auth, Cisco enable, CVS, FTP, HTTP(S)-FORM-GET,
HTTP(S)-FORM-POST, HTTP(S)-GET, HTTP(S)-HEAD, HTTP-Proxy, ICQ, IMAP, IRC,
LDAP, MS-SQL, MySQL, NNTP, Oracle Listener, Oracle SID, PC-Anywhere, PC-NFS,
POP3, PostgreSQL, RDP, Rexec, Rlogin, Rsh, SIP, SMB(NT), SMTP, SMTP Enum,
SNMP v1+v2+v3, SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, Teamspeak (TS2),
Telnet, VMware-Auth, VNC and XMPP.
Installed size: 978 KB How to install: sudo apt install hydra
- libapr1t64
- libbson2-2
- libc6
- libfbclient2
- libfreerdp3-3
- libgcrypt20
- libidn12
- libmariadb3
- libmemcached11t64
- libmongoc2-2
- libpcre2-8-0
- libpq5
- libsmbclient0
- libssh-4
- libssl3t64
- libsvn1
- libsybdb5
- libtinfo6
- libwinpr3-3
- zlib1g

##### dpl4hydra

Generates a (d)efault (p)assword (l)ist as input for THC hydra

```
root@kali:~# dpl4hydra -h
dpl4hydra v0.9.9 (c) 2012 by Roland Kessler (@rokessler)

Syntax: dpl4hydra [help] | [refresh] | [BRAND] | [all]

This script depends on a local (d)efault (p)assword (l)ist called
/root/.dpl4hydra/dpl4hydra_full.csv. If it is not available, regenerate it with
'dpl4hydra refresh'. Source of the default password list is
http://open-sez.me

Options:
  help        Help: Show this message
  refresh     Refresh list: Download the full (d)efault (p)assword (l)ist
              and generate a new local /root/.dpl4hydra/dpl4hydra_full.csv file. Takes time!
  BRAND       Generates a (d)efault (p)assword (l)ist from the local file
              /root/.dpl4hydra/dpl4hydra_full.csv, limiting the output to BRAND systems, using
              the format username:password (as required by THC hydra).
              The output file is called dpl4hydra_BRAND.lst.
  all         Dump list of all systems credentials into dpl4hydra_all.lst.

Example:
#### dpl4hydra linksys
File dpl4hydra_linksys.lst was created with 20 entries.
#### hydra -C ./dpl4hydra_linksys.lst -t 1 192.168.1.1 http-get /index.asp
```

##### hydra

A very fast network logon cracker which supports many different services

```
root@kali:~# hydra -h
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Syntax: hydra [[[-l LOGIN|-L FILE] [-p PASS|-P FILE]] | [-C FILE]] [-e nsr] [-o FILE] [-t TASKS] [-M FILE [-T TASKS]] [-w TIME] [-W TIME] [-f] [-s PORT] [-x MIN:MAX:CHARSET] [-c TIME] [-ISOuvVd46] [-m MODULE_OPT] [service://server[:PORT][/OPT]]

Options:
  -R        restore a previous aborted/crashed session
  -I        ignore an existing restore file (don't wait 10 seconds)
  -S        perform an SSL connect
  -s PORT   if the service is on a different default port, define it here
  -l LOGIN or -L FILE  login with LOGIN name, or load several logins from FILE
  -p PASS  or -P FILE  try password PASS, or load several passwords from FILE
  -x MIN:MAX:CHARSET  password bruteforce generation, type "-x -h" to get help
  -y        disable use of symbols in bruteforce, see above
  -r        use a non-random shuffling method for option -x
  -e nsr    try "n" null password, "s" login as pass and/or "r" reversed login
  -u        loop around users, not passwords (effective! implied with -x)
  -C FILE   colon separated "login:pass" format, instead of -L/-P options
  -M FILE   list of servers to attack, one entry per line, ':' to specify port
  -D XofY   Divide wordlist into Y segments and use the Xth segment.
  -o FILE   write found login/password pairs to FILE instead of stdout
  -b FORMAT specify the format for the -o FILE: text(default), json, jsonv1
  -f / -F   exit when a login/pass pair is found (-M: -f per host, -F global)
  -t TASKS  run TASKS number of connects in parallel per target (default: 16)
  -T TASKS  run TASKS connects in parallel overall (for -M, default: 64)
  -w / -W TIME  wait time for a response (32) / between connects per thread (0)
  -c TIME   wait time per login attempt over all threads (enforces -t 1)
  -4 / -6   use IPv4 (default) / IPv6 addresses (put always in [] also in -M)
  -v / -V / -d  verbose mode / show login+pass for each attempt / debug mode 
  -O        use old SSL v2 and v3
  -K        do not redo failed attempts (good for -M mass scanning)
  -q        do not print messages about connection errors
  -U        service module usage details
  -m OPT    options specific for a module, see -U output for information
  -h        more command line options (COMPLETE HELP)
  server    the target: DNS, IP or 192.168.0.0/24 (this OR the -M option)
  service   the service to crack (see below for supported protocols)
  OPT       some service modules support additional input (-U for module help)

Supported services: adam6500 asterisk cisco cisco-enable cobaltstrike cvs firebird ftp[s] http[s]-{head|get|post} http[s]-{get|post}-form http-proxy http-proxy-urlenum icq imap[s] irc ldap2[s] ldap3[-{cram|digest}md5][s] memcached mongodb mssql mysql nntp oracle-listener oracle-sid pcanywhere pcnfs pop3[s] postgres radmin2 rdp redis rexec rlogin rpcap rsh rtsp s7-300 sip smb smb2 smtp[s] smtp-enum snmp socks5 ssh sshkey svn teamspeak telnet[s] vmauthd vnc xmpp

Hydra is a tool to guess/crack valid login/password pairs.
Licensed under AGPL v3.0. The newest version is always available at;
https://github.com/vanhauser-thc/thc-hydra
Please don't use in military or secret service organizations, or for illegal
purposes. (This is a wish and non-binding - most such people do not care about
laws and ethics anyway - and tell themselves they are one of the good ones.)
These services were not compiled in: afp ncp oracle sapr3.

Use HYDRA_PROXY_HTTP or HYDRA_PROXY environment variables for a proxy setup.
E.g. % export HYDRA_PROXY=socks5://l:
[email protected]
:9150 (or: socks4:// connect://)
     % export HYDRA_PROXY=connect_and_socks_proxylist.txt  (up to 64 entries)
     % export HYDRA_PROXY_HTTP=http://login:pass@proxy:8080
     % export HYDRA_PROXY_HTTP=proxylist.txt  (up to 64 entries)

Examples:
  hydra -l user -P passlist.txt ftp://192.168.0.1
  hydra -L userlist.txt -p defaultpw imap://192.168.0.1/PLAIN
  hydra -C defaults.txt -6 pop3s://[2001:db8::1]:143/TLS:DIGEST-MD5
  hydra -l admin -p password ftp://[192.168.0.0/24]/
  hydra -L logins.txt -P pws.txt -M targets.txt ssh
```

##### hydra-wizard

Wizard to use hydra from command line

```
root@kali:~# man hydra-wizard
HYDRA-WIZARD(1)             General Commands Manual             HYDRA-WIZARD(1)

NAME
     HYDRA-WIZARD - Wizard to use hydra from command line

DESCRIPTION
     This  script guide users to use hydra, with a simple wizard that will make
     the necessary questions to launch hydra from command line a fast and  eas-
     ily
     1. The wizard ask for the service to attack
     2. The target to attack
     3. The username o file with the username what use to attack
     4. The password o file with the passwords what use to attack
     5. The wizard ask if you want to test for passwords same as login, null or
     reverse login
     6. The wizard ask for the port number to attack
     Finally,  the wizard show the resume information of attack, and ask if you
     want launch attack

SEE ALSO
     hydra(1), dpl4hydra(1),

AUTHOR
     hydra-wizard was written by Shivang Desai <
[email protected]
>.

     This manual page was written by  Daniel  Echeverry  <
[email protected]
>,
     for the Debian project (and may be used by others).

                                   19/01/2014                   HYDRA-WIZARD(1)
```

##### pw-inspector

A tool to reduce the password list

```
root@kali:~# pw-inspector -h
PW-Inspector v0.2 (c) 2005 by van Hauser / THC
[email protected]
[https://github.com/vanhauser-thc/thc-hydra]

Syntax: pw-inspector [-i FILE] [-o FILE] [-m MINLEN] [-M MAXLEN] [-c MINSETS] -l -u -n -p -s

Options:
  -i FILE    file to read passwords from (default: stdin)
  -o FILE    file to write valid passwords to (default: stdout)
  -m MINLEN  minimum length of a valid password
  -M MAXLEN  maximum length of a valid password
  -c MINSETS the minimum number of sets required (default: all given)
Sets:
  -l         lowcase characters (a,b,c,d, etc.)
  -u         upcase characters (A,B,C,D, etc.)
  -n         numbers (1,2,3,4, etc.)
  -p         printable characters (which are not -l/-u/-n, e.g. $,!,/,(,*, etc.)
  -s         special characters - all others not within the sets above

PW-Inspector reads passwords in and prints those which meet the requirements.
The return code is the number of valid passwords found, 0 if none was found.
Use for security: check passwords, if 0 is returned, reject password choice.
Use for hacking: trim your dictionary file to the pw requirements of the target.
Usage only allowed for legal purposes.
```

#### hydra-gtk

Very fast network logon cracker - GTK+ based GUI Hydra is a parallelized login cracker which supports numerous protocols
to attack. It is very fast and flexible, and new modules are easy to add.
This tool makes it possible for researchers and security consultants to
show how easy it would be to gain unauthorized access to a system
remotely.
It supports: Cisco AAA, Cisco auth, Cisco enable, CVS, FTP, HTTP(S)-FORM-GET,
HTTP(S)-FORM-POST, HTTP(S)-GET, HTTP(S)-HEAD, HTTP-Proxy, ICQ, IMAP, IRC,
LDAP, MS-SQL, MySQL, NNTP, Oracle Listener, Oracle SID, PC-Anywhere, PC-NFS,
POP3, PostgreSQL, RDP, Rexec, Rlogin, Rsh, SIP, SMB(NT), SMTP, SMTP Enum,
SNMP v1+v2+v3, SOCKS5, SSH (v1 and v2), SSHKEY, Subversion, Teamspeak (TS2),
Telnet, VMware-Auth, VNC and XMPP.
This package provides the GTK based GUI for hydra.
Installed size: 104 KB How to install: sudo apt install hydra-gtk
- hydra
- libatk1.0-0t64
- libc6
- libgdk-pixbuf-2.0-0
- libglib2.0-0t64
- libgtk-3-0t64

##### xhydra

Gtk+3 frontend for thc-hydra

```
root@kali:~# man xhydra
XHYDRA(1)                   General Commands Manual                   XHYDRA(1)

NAME
     xhydra - Gtk+3 frontend for thc-hydra

SYNOPSIS
     Execute xhydra in a terminal to start the application.

DESCRIPTION
     Hydra is a parallelized login cracker which supports numerous protocols to
     attack.  New modules are easy to add, beside that, it is flexible and very
     fast.

     xhydra is the graphical fronend for the hydra(1) tool.

SEE ALSO
     hydra(1), pw-inspector(1).

AUTHOR
     hydra was written by van Hauser <
[email protected]
>

     This manual page was written by  Daniel  Echeverry  <
[email protected]
>,
     for the Debian project (and may be used by others).

                                   02/02/2012                         XHYDRA(1)
```

#### Learn more with OffSec

Want to learn more about hydra? get access to in-depth training and hands-on labs:
- PEN-200: 16. Password Attacks
- Intermediate Secure Software Development II: 8. Credential Attacks for Developers
- Monitoring, Intrusion Detection and Analysis Skill Path: 3.2.2. Introduction to Splunk: Detect an SSH Password Guessing Attack
- Linux Admin Skill Path: 3.2.1. Linux Privilege Escalation: Inspecting User Trails
- Password Attacks Skill Path
- SOC Analyst Tools Skill Path: 2.2.2. Introduction to Splunk: Detect an SSH Password Guessing Attack
- MITRE D3FEND - Detect: 6.1.3. Windows Server Side Attacks: Brute Force Logins
- MITRE D3FEND - Harden: 10. Credential Attacks for Developers
- MITRE ATT&CK - Credential Access (TA0006): 1.1. Password Attacks: Attacking Network Services Logins
PEN-200 course
Updated on: 2026-Jun-17

### medusa

Source: https://www.kali.org/tools/medusa/

#### medusa

Fast, parallel, modular, login brute-forcer for network services Medusa is intended to be a speedy, massively parallel, modular, login
brute-forcer. The goal is to support as many services which allow remote
authentication as possible. The author considers following items as some of
the key features of this application:
* Thread-based parallel testing. Brute-force testing can be
performed against multiple hosts, users or passwords
concurrently.
* Flexible user input. Target information (host/user/password) can
be specified in a variety of ways. For example, each item can be
either a single entry or a file containing multiple entries.
Additionally, a combination file format allows the user to
refine their target listing.
* Modular design. Each service module exists as an
independent .mod file. This means that no modifications are
necessary to the core application in order to extend the
supported list of services for brute-forcing.
Installed size: 843 KB How to install: sudo apt install medusa
- libc6
- libfreerdp-client3-3
- libfreerdp3-3
- libpq5
- libsmb2-6
- libssh2-1t64
- libssl3t64
- libsvn1

##### medusa

Parallel Network Login Auditor

```
root@kali:~# medusa -h
Medusa v2.3 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <
[email protected]
>

Syntax: Medusa [-h host|-H file] [-u username|-U file] [-p password|-P file] [-C file] -M module [OPT]
  -h [TEXT]    : Target hostname or IP address
  -H [FILE]    : File containing target hostnames or IP addresses
  -u [TEXT]    : Username to test
  -U [FILE]    : File containing usernames to test
  -p [TEXT]    : Password to test
  -P [FILE]    : File containing passwords to test
  -C [FILE]    : File containing combo entries. See README for more information.
  -O [FILE]    : File to append log information to
  -e [n/s/ns]  : Additional password checks ([n] No Password, [s] Password = Username)
  -M [TEXT]    : Name of the module to execute (without the .mod extension)
  -m [TEXT]    : Parameter to pass to the module. This can be passed multiple times with a
                 different parameter each time and they will all be sent to the module (i.e.
                 -m Param1 -m Param2, etc.)
  -d           : Dump all known modules
  -n [NUM]     : Use for non-default TCP port number
  -s           : Enable SSL
  -g [NUM]     : Give up after trying to connect for NUM seconds (default 3)
  -r [NUM]     : Sleep NUM seconds between retry attempts (default 3)
  -R [NUM]     : Attempt NUM retries before giving up. The total number of attempts will be NUM + 1.
  -c [NUM]     : Time to wait in usec to verify socket is available (default 500 usec).
  -t [NUM]     : Total number of logins to be tested concurrently
  -T [NUM]     : Total number of hosts to be tested concurrently
  -L           : Parallelize logins using one username per thread. The default is to process 
                 the entire username before proceeding.
  -f           : Stop scanning host after first valid username/password found.
  -F           : Stop audit after first valid username/password found on any host.
  -b           : Suppress startup banner
  -q           : Display module's usage information
  -v [NUM]     : Verbose level [0 - 6 (more)]
  -w [NUM]     : Error debug level [0 - 10 (more)]
  -V           : Display version
  -Z [TEXT]    : Resume scan based on map of previous scan
```

Updated on: 2025-Dec-09

### ncrack

Source: https://www.kali.org/tools/ncrack/

#### Tool Documentation:



#### Tool Documentation:

#### ncrack Usage Example

Use verbose mode ( -v ), read a list of IP addresses ( -iL win.txt ), and attempt to login with the username victim ( –user victim ) along with the passwords in a dictionary ( -P passes.txt ) using the RDP protocol ( -p rdp ) with a one connection at a time ( CL=1 ):

```
root@kali:~# ncrack -v -iL win.txt --user victim -P passes.txt -p rdp CL=1

Starting Ncrack 0.6 ( http://ncrack.org ) at 2018-12-01 09:54 EDT

rdp://192.168.1.220:3389 finished.
Discovered credentials on rdp://192.168.1.200:3389 'victim' 's3cr3t'
```


#### ncrack

High-speed network authentication cracking tool Ncrack is a high-speed network authentication cracking tool.
It was built to help companies secure their networks by
proactively testing all their hosts and networking devices
for poor passwords. Security professionals also rely on
Ncrack when auditing their clients. Ncrack was designed
using a modular approach, a command-line syntax similar to
Nmap and a dynamic engine that can adapt its behaviour
based on network feedback. It allows for rapid, yet
reliable large-scale auditing of multiple hosts.
Ncrack’s features include a very flexible interface granting
the user full control of network operations, allowing for
very sophisticated bruteforcing attacks, timing templates
for ease of use, runtime interaction similar to Nmap’s and
many more. Protocols supported include RDP, SSH, http(s),
SMB, pop3(s), VNC, FTP, and telnet.
Be sure to read the Ncrack man page ( https://nmap.org/ncrack/man.html )
to fully understand Ncrack usage.
Installed size: 1.66 MB How to install: sudo apt install ncrack
- libc6
- libgcc-s1
- libssl3t64
- libstdc++6

##### ncrack

Network authentication cracking tool

```
root@kali:~# ncrack -h
Ncrack 0.7 ( http://ncrack.org )
Usage: ncrack [Options] {target and service specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iX <inputfilename>: Input from Nmap's -oX XML output format
  -iN <inputfilename>: Input from Nmap's -oN Normal output format
  -iL <inputfilename>: Input from list of hosts/networks
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
  --excludefile <exclude_file>: Exclude list from file
SERVICE SPECIFICATION:
  Can pass target specific services in <service>://target (standard) notation or
  using -p which will be applied to all hosts in non-standard notation.
  Service arguments can be specified to be host-specific, type of service-specific
  (-m) or global (-g). Ex: ssh://10.0.0.10,at=10,cl=30 -m ssh:at=50 -g cd=3000
  Ex2: ncrack -p ssh,ftp:3500,25 10.0.0.10 scanme.nmap.org google.com:80,ssl
  -p <service-list>: services will be applied to all non-standard notation hosts
  -m <service>:<options>: options will be applied to all services of this type
  -g <options>: options will be applied to every service globally
  Misc options:
    ssl: enable SSL over this service
    path <name>: used in modules like HTTP ('=' needs escaping if used)
    db <name>: used in modules like MongoDB to specify the database
    domain <name>: used in modules like WinRM to specify the domain
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, unless you append 'ms'
  (milliseconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  Service-specific options:
    cl (min connection limit): minimum number of concurrent parallel connections
    CL (max connection limit): maximum number of concurrent parallel connections
    at (authentication tries): authentication attempts per connection
    cd (connection delay): delay <time> between each connection initiation
    cr (connection retries): caps number of service connection attempts
    to (time-out): maximum cracking <time> for service, regardless of success so far
  -T<0-5>: Set timing template (higher is faster)
  --connection-limit <number>: threshold for total concurrent connections
  --stealthy-linear: try credentials using only one connection against each specified host 
    until you hit the same host again. Overrides all other timing options.
AUTHENTICATION:
  -U <filename>: username file
  -P <filename>: password file
  --user <username_list>: comma-separated username list
  --pass <password_list>: comma-separated password list
  --passwords-first: Iterate password list for each username. Default is opposite.
  --pairwise: Choose usernames and passwords in pairs.
OUTPUT:
  -oN/-oX <file>: Output scan in normal and XML format, respectively, to the given filename.
  -oA <basename>: Output in the two major formats at once
  -v: Increase verbosity level (use twice or more for greater effect)
  -d[level]: Set or increase debugging level (Up to 10 is meaningful)
  --nsock-trace <level>: Set nsock trace level (Valid range: 0 - 10)
  --log-errors: Log errors/warnings to the normal-format output file
  --append-output: Append to rather than clobber specified output files
MISC:
  --resume <file>: Continue previously saved session
  --save <file>: Save restoration file with specific filename
  -f: quit cracking service after one found credential
  -6: Enable IPv6 cracking
  -sL or --list: only list hosts and services
  --datadir <dirname>: Specify custom Ncrack data file location
  --proxy <type://proxy:port>: Make connections via socks4, 4a, http.
  -V: Print version number
  -h: Print this help summary page.
MODULES:
  SSH, RDP, FTP, Telnet, HTTP(S), Wordpress, POP3(S), IMAP, CVS, SMB, VNC, SIP, Redis, PostgreSQL, MQTT, MySQL, MSSQL, MongoDB, Cassandra, WinRM, OWA, DICOM
EXAMPLES:
  ncrack -v --user root localhost:22
  ncrack -v -T5 https://192.168.0.1
  ncrack -v -iX ~/nmap.xml -g CL=5,to=1h
SEE THE MAN PAGE (http://nmap.org/ncrack/man.html) FOR MORE OPTIONS AND EXAMPLES
```

Updated on: 2025-Dec-09

### netcat

Source: https://www.kali.org/tools/netcat/

#### netcat-traditional

TCP/IP swiss army knife A simple Unix utility which reads and writes data across network
connections using TCP or UDP protocol. It is designed to be a reliable
“back-end” tool that can be used directly or easily driven by other
programs and scripts. At the same time it is a feature-rich network
debugging and exploration tool, since it can create almost any kind
of connection you would need and has several interesting built-in
capabilities.
This is the “classic” netcat, written by Hobbit . It lacks many
features found in netcat-openbsd.
Installed size: 139 KB How to install: sudo apt install netcat-traditional
- libc6

##### nc.traditional

TCP/IP swiss army knife

```
root@kali:~# nc.traditional -h
[v1.10-50.1]
connect to somewhere:	nc [-options] hostname port[s] [ports] ... 
listen for inbound:	nc -l -p port [-options] [hostname] [port]
options:
	-c shell commands	as `-e'; use /bin/sh to exec [dangerous!!]
	-e filename		program to exec after connect [dangerous!!]
	-b			allow broadcasts
	-g gateway		source-routing hop point[s], up to 8
	-G num			source-routing pointer: 4, 8, 12, ...
	-h			this cruft
	-i secs			delay interval for lines sent, ports scanned
        -k                      set keepalive option on socket
	-l			listen mode, for inbound connects
	-n			numeric-only IP addresses, no DNS
	-o file			hex dump of traffic
	-p port			local port number
	-r			randomize local and remote ports
	-q secs			quit after EOF on stdin and delay of secs
	-s addr			local source address
	-T tos			set Type Of Service
	-t			answer TELNET negotiation
	-u			UDP mode
	-v			verbose [use twice to be more verbose]
	-w secs			timeout for connects and final net reads
	-C			Send CRLF as line-ending
	-z			zero-I/O mode [used for scanning]
port numbers can be individual or ranges: lo-hi [inclusive];
hyphens in port names must be backslash escaped (e.g. 'ftp\-data').
```

#### Learn more with OffSec

Want to learn more about netcat? get access to in-depth training and hands-on labs:
- PEN-200: 6.4.2. Information Gathering: TCP/UDP Port Scanning Theory
- Network Penetration Testing Essentials: 19.2.2. File Transfers: Netcat
- Network Penetration Testing Essentials: 10.6. Linux Networking and Services I: Netcat (nc)
- Security Operations Essentials: 8.6. Linux Networking and Services I: Netcat (nc)
- Network Penetration Testing Essentials: 14.2.1. Working with Shells
- Network Penetration Testing Essentials: 14.2.1. Working with Shells: Netcat Shells
PEN-200 course
Updated on: 2025-Dec-09

### nikto

Source: https://www.kali.org/tools/nikto/

#### Tool Documentation:



#### Tool Documentation:

#### Nikto Usage Example

```
root@kali:~# nikto -Display 1234EP -o report.html -Format htm -Tuning 123bde -host 192.168.0.102
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.0.102
+ Target Hostname:    192.168.0.102
+ Target Port:        80
+ Start Time:         2018-03-23 10:49:04 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, inode: 287, size: 11832, mtime: Fri Feb  2 15:27:56 2018
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ "robots.txt" contains 1 entry which should be manually viewed.
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.12). Apache 2.0.65 (final release) and 2.2.29 are also current.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS
+ 371 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2018-03-23 10:50:44 (GMT0) (100 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
root@kali:~#
root@kali:~# firefox report.html
```


#### nikto

Web server security scanner Nikto is a pluggable web server and CGI scanner written in Perl, using
rfp’s LibWhisker to perform fast security or informational checks.
Features:
- Easily updatable CSV-format checks database
- Output reports in plain text or HTML
- Available HTTP versions automatic switching
- Generic as well as specific server software checks
- SSL support (through libnet-ssleay-perl)
- Proxy support (with authentication)
- Cookies support
Installed size: 2.12 MB How to install: sudo apt install nikto
- libdigest-perl-md5-perl
- libio-socket-ssl-perl
- libjson-perl
- libjson-pp-perl
- libnet-ssleay-perl
- libwhisker2-perl
- libxml-libxml-perl
- libxml-writer-perl
- perl

##### nikto

Scan web server for known vulnerabilities

```
root@kali:~# nikto -h

   Options:
       -Add-header         Add HTTP headers (can be used multiple times, one per header pair)
       -ask+               Whether to ask about submitting updates
                               yes   Ask about each (default)
                               no    Don't ask, don't send
                               auto  Don't ask, just send
       -check6             Check if IPv6 is working (connects to ipv6.google.com or value set in nikto.conf)
       -Cgidirs+           Scan these CGI dirs: "none", "all", or values like "/cgi/ /cgi-a/"
       -config+            Use this config file
       -Display+           Turn on/off display outputs:
                               1     Show redirects
                               2     Show cookies received
                               3     Show all 200/OK responses
                               4     Show URLs which require authentication
                               D     Debug output
                               E     Display all HTTP errors
                               P     Print progress to STDOUT
                               S     Scrub output of IPs and hostnames
                               V     Verbose output
       -dbcheck           Check database and other key files for syntax errors
       -evasion+          Encoding technique:
                               1     Random URI encoding (non-UTF8)
                               2     Directory self-reference (/./)
                               3     Premature URL ending
                               4     Prepend long random string
                               5     Fake parameter
                               6     TAB as request spacer
                               7     Change the case of the URL
                               8     Use Windows directory separator (\)
                               A     Use a carriage return (0x0d) as a request spacer
                               B     Use binary value 0x0b as a request spacer
        -followredirects   Follow 3xx redirects to new location
        -Format+           Save file (-o) format:
                               csv   Comma-separated-value
                               json  JSON Format
                               htm   HTML Format
                               sql   Generic SQL (see docs for schema)
                               txt   Plain text
                               xml   XML Format
                               (if not specified the format will be taken from the file extension passed to -output)
       -Help              This help information
       -host+             Target host/URL
       -id+               Host authentication to use, format is id:pass or id:pass:realm
       -ipv4                 IPv4 Only
       -ipv6                 IPv6 Only
       -key+              Client certificate key file
       -list-plugins      List all available plugins, perform no testing
       -maxtime+          Maximum testing time per host (e.g., 1h, 60m, 3600s)
       -mutate+           Guess additional file names:
                               1     Test all files with all root directories
                               2     Guess for password file names
                               3     Enumerate user names via Apache (/~user type requests)
                               4     Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user type requests)
                               6     Attempt to guess directory names from the supplied dictionary file
       -mutate-options    Provide information for mutates
       -nocheck           Don't check for updates on startup
       -nocookies         Do not use cookies from responses in requests
       -nointeractive     Disables interactive features
       -nolookup          Disables DNS lookups
       -nossl             Disables the use of SSL
       -noslash           Strip trailing slash from URL (e.g., '/admin/' to '/admin')
       -no404             Disables nikto attempting to guess a 404 page
       -Option            Over-ride an option in nikto.conf, can be issued multiple times
       -output+           Write output to this file ('.' for auto-name)
       -Pause+            Pause between tests (seconds)
       -Platform+         Platform of target (nix, win, all)
       -Plugins+          List of plugins to run (default: ALL)
       -port+             Port to use (default 80)
       -RSAcert+          Client certificate file
       -root+             Prepend root value to all requests, format is /directory
       -Save              Save positive responses to this directory ('.' for auto-name)
       -ssl               Force ssl mode on port
       -Tuning+           Scan tuning:
                               1     Interesting File / Seen in logs
                               2     Misconfiguration / Default File
                               3     Information Disclosure
                               4     Injection (XSS/Script/HTML)
                               5     Remote File Retrieval - Inside Web Root
                               6     Denial of Service
                               7     Remote File Retrieval - Server Wide
                               8     Command Execution / Remote Shell
                               9     SQL Injection
                               0     File Upload
                               a     Authentication Bypass
                               b     Software Identification
                               c     Remote Source Inclusion
                               d     WebService
                               e     Administrative Console
                               x     Reverse Tuning Options (i.e., include all except specified)
       -timeout+          Timeout for requests (default 10 seconds)
       -Userdbs           Load only user databases, not the standard databases
                               all   Disable standard dbs and load only user dbs
                               tests Disable only db_tests and load udb_tests
       -useragent         Force User-Agent instead of pulling from database
       -url+              Target host/URL (alias of -host)
       -useproxy          Use the proxy defined in nikto.conf, or argument http://server:port
       -Version           Print plugin and database versions
       -vhost+            Virtual host (for Host header)
       -404code           Ignore these HTTP codes as negative responses (always). Format is "302,301".
       -404string         Ignore this string in response body content as negative response (always). Can be a regular expression.
   		+ requires a value
```

##### replay

```
root@kali:~# replay -h
replay.pl -- Replay a saved scan result
     -file 		Parse request from this file
     -proxy		Send request through this proxy (format: host:port)
     -help		Help output
```

#### Learn more with OffSec

Want to learn more about nikto? get access to in-depth training and hands-on labs:
- WEB-200: 2. Web Application Enumeration Methodology
- MITRE ATT&CK - Command and Control (TA0011): 1.4. Introduction to Proxies: Proxychains
- MITRE ATT&CK - Initial Access (TA0001): 8.2.4. Common Attack Techniques: Automated Network Attacks
WEB-200 course
Updated on: 2026-Jun-17

### nmap

Source: https://www.kali.org/tools/nmap/

#### Tool Documentation:



#### Tool Documentation:

#### nmap Usage Example

Scan in verbose mode ( -v ), enable OS detection, version detection, script scanning, and traceroute ( -A ), with version detection ( -sV ) against the target IP ( 192.168.1.1 ):

```
root@kali:~# nmap -v -A -sV 192.168.1.1

Starting Nmap 6.45 ( http://nmap.org ) at 2014-05-13 18:40 MDT
NSE: Loaded 118 scripts for scanning.
NSE: Script Pre-scanning.
Initiating ARP Ping Scan at 18:40
Scanning 192.168.1.1 [1 port]
Completed ARP Ping Scan at 18:40, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:40
Completed Parallel DNS resolution of 1 host. at 18:40, 0.00s elapsed
Initiating SYN Stealth Scan at 18:40
Scanning router.localdomain (192.168.1.1) [1000 ports]
Discovered open port 53/tcp on 192.168.1.1
Discovered open port 22/tcp on 192.168.1.1
Discovered open port 80/tcp on 192.168.1.1
Discovered open port 3001/tcp on 192.168.1.1
```

#### nping Usage Example

Using TCP mode ( –tcp ) to probe port 22 ( -p 22 ) using the SYN flag ( –flags syn ) with a TTL of 2 ( –ttl 2 ) on the remote host ( 192.168.1.1 ):

```
root@kali:~# nping --tcp -p 22 --flags syn --ttl 2 192.168.1.1

Starting Nping 0.6.45 ( http://nmap.org/nping ) at 2014-05-13 18:43 MDT
SENT (0.0673s) TCP 192.168.1.15:60125 > 192.168.1.1:22 S ttl=2 id=54240 iplen=40  seq=1720523417 win=1480
RCVD (0.0677s) TCP 192.168.1.1:22 > 192.168.1.15:60125 SA ttl=64 id=0 iplen=44  seq=3377886789 win=5840 <mss 1460>
SENT (1.0678s) TCP 192.168.1.15:60125 > 192.168.1.1:22 S ttl=2 id=54240 iplen=40  seq=1720523417 win=1480
RCVD (1.0682s) TCP 192.168.1.1:22 > 192.168.1.15:60125 SA ttl=64 id=0 iplen=44  seq=3393519366 win=5840 <mss 1460>
SENT (2.0693s) TCP 192.168.1.15:60125 > 192.168.1.1:22 S ttl=2 id=54240 iplen=40  seq=1720523417 win=1480
RCVD (2.0696s) TCP 192.168.1.1:22 > 192.168.1.15:60125 SA ttl=64 id=0 iplen=44  seq=3409166569 win=5840 <mss 1460>
SENT (3.0707s) TCP 192.168.1.15:60125 > 192.168.1.1:22 S ttl=2 id=54240 iplen=40  seq=1720523417 win=1480
RCVD (3.0710s) TCP 192.168.1.1:22 > 192.168.1.15:60125 SA ttl=64 id=0 iplen=44  seq=3424813300 win=5840 <mss 1460>
SENT (4.0721s) TCP 192.168.1.15:60125 > 192.168.1.1:22 S ttl=2 id=54240 iplen=40  seq=1720523417 win=1480
RCVD (4.0724s) TCP 192.168.1.1:22 > 192.168.1.15:60125 SA ttl=64 id=0 iplen=44  seq=3440460772 win=5840 <mss 1460>

Max rtt: 0.337ms | Min rtt: 0.282ms | Avg rtt: 0.296ms
Raw packets sent: 5 (200B) | Rcvd: 5 (230B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 4.13 seconds
```

#### ndiff Usage Example

Compare yesterday’s port scan ( yesterday.xml ) with the scan from today ( today.xml ):

```
root@kali:~# ndiff yesterday.xml today.xml
-Nmap 6.45 scan initiated Tue May 13 18:46:43 2014 as: nmap -v -F -oX yesterday.xml 192.168.1.1
+Nmap 6.45 scan initiated Tue May 13 18:47:58 2014 as: nmap -v -F -oX today.xml 192.168.1.1

 endian.localdomain (192.168.1.1, 00:01:6C:6F:DD:D1):
-Not shown: 96 filtered ports
+Not shown: 97 filtered ports
 PORT   STATE SERVICE VERSION
-22/tcp open  ssh
```

#### ncat Usage Example

Be verbose ( -v ), running /bin/bash on connect ( –exec “/bin/bash” ), only allowing 1 IP address ( –allow 192.168.1.123 ), listen on TCP port 4444 ( -l 4444 ), and keep the listener open on disconnect ( –keep-open ):

```
root@kali:~# ncat -v --exec "/bin/bash" --allow 192.168.1.123 -l 4444 --keep-open
Ncat: Version 6.45 ( http://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.1.123.
Ncat: Connection from 192.168.1.123:39501.
Ncat: Connection from 192.168.1.15.
Ncat: Connection from 192.168.1.15:60393.
Ncat: New connection denied: not allowed
```


#### ncat

NMAP netcat reimplementation ncat is a reimplementation of Netcat by the NMAP project, providing
most of the features present in the original implementations, along
with some new features such as IPv6 and SSL support. Port scanning
support has been removed.
Installed size: 807 KB How to install: sudo apt install ncat
- libc6
- liblua5.4-0
- libpcap0.8t64
- libssl3t64

##### ncat

Concatenate and redirect sockets

```
root@kali:~# ncat -h
Ncat 7.99 ( https://nmap.org/ncat )
Usage: ncat [options] [hostname] [port]

Options taking a time assume seconds. Append 'ms' for milliseconds,
's' for seconds, 'm' for minutes, or 'h' for hours (e.g. 500ms).
  -4                         Use IPv4 only
  -6                         Use IPv6 only
  -U, --unixsock             Use Unix domain sockets only
      --vsock                Use vsock sockets only
  -C, --crlf                 Use CRLF for EOL sequence
  -c, --sh-exec <command>    Executes the given command via /bin/sh
  -e, --exec <command>       Executes the given command
      --lua-exec <filename>  Executes the given Lua script
  -g hop1[,hop2,...]         Loose source routing hop points (8 max)
  -G <n>                     Loose source routing hop pointer (4, 8, 12, ...)
  -m, --max-conns <n>        Maximum <n> simultaneous connections
  -h, --help                 Display this help screen
  -d, --delay <time>         Wait between read/writes
  -o, --output <filename>    Dump session data to a file
  -x, --hex-dump <filename>  Dump session data as hex to a file
  -i, --idle-timeout <time>  Idle read/write timeout
  -p, --source-port port     Specify source port to use
  -s, --source addr          Specify source address to use (doesn't affect -l)
  -l, --listen               Bind and listen for incoming connections
  -k, --keep-open            Accept multiple connections in listen mode
  -n, --nodns                Do not resolve hostnames via DNS
  -t, --telnet               Answer Telnet negotiations
  -u, --udp                  Use UDP instead of default TCP
      --sctp                 Use SCTP instead of default TCP
  -v, --verbose              Set verbosity level (can be used several times)
  -w, --wait <time>          Connect timeout
  -z                         Zero-I/O mode, report connection status only
      --append-output        Append rather than clobber specified output files
      --send-only            Only send data, ignoring received; quit on EOF
      --recv-only            Only receive data, never send anything
      --no-shutdown          Continue half-duplex when receiving EOF on stdin
  -q <time>                  After EOF on stdin, wait <time> then quit.
      --allow                Allow only given hosts to connect to Ncat
      --allowfile            A file of hosts allowed to connect to Ncat
      --deny                 Deny given hosts from connecting to Ncat
      --denyfile             A file of hosts denied from connecting to Ncat
      --broker               Enable Ncat's connection brokering mode
      --chat                 Start a simple Ncat chat server
      --proxy <addr[:port]>  Specify address of host to proxy through
      --proxy-type <type>    Specify proxy type ("http", "socks4", "socks5")
      --proxy-auth <auth>    Authenticate with HTTP or SOCKS proxy server
      --proxy-dns <type>     Specify where to resolve proxy destination
      --ssl                  Connect or listen with SSL
      --ssl-cert             Specify SSL certificate file (PEM) for listening
      --ssl-key              Specify SSL private key (PEM) for listening
      --ssl-verify           Verify trust and domain name of certificates
      --ssl-trustfile        PEM file containing trusted SSL certificates
      --ssl-ciphers          Cipherlist containing SSL ciphers to use
      --ssl-servername       Request distinct server name (SNI)
      --ssl-alpn             ALPN protocol list to use
      --version              Display Ncat's version information and exit

See the ncat(1) manpage for full options, descriptions and usage examples
```

#### ndiff

The Network Mapper - result compare utility Ndiff is a tool to aid in the comparison of Nmap scans. It takes two
Nmap XML output files and prints the differences between them them:
hosts coming up and down, ports becoming open or closed, and things like that.
It can produce output in human-readable text or machine-readable XML formats.
Installed size: 432 KB How to install: sudo apt install ndiff
- python3
- python3-lxml

##### ndiff

```
root@kali:~# ndiff -h
Usage: /usr/bin/ndiff [option] FILE1 FILE2
Compare two Nmap XML files and display a list of their differences.
Differences include host state changes, port state changes, and changes to
service and OS detection.

  -h, --help     display this help
  -v, --verbose  also show hosts and ports that haven't changed.
  --text         display output in text format (default)
  --xml          display output in XML format
```

#### nmap

The Network Mapper Nmap is a utility for network exploration or security auditing. It
supports ping scanning (determine which hosts are up), many port
scanning techniques, version detection (determine service protocols
and application versions listening behind ports), and TCP/IP
fingerprinting (remote host OS or device identification). Nmap also
offers flexible target and port specification, decoy/stealth scanning,
sunRPC scanning, and more. Most Unix and Windows platforms are
supported in both GUI and commandline modes. Several popular handheld
devices are also supported, including the Sharp Zaurus and the iPAQ.
Installed size: 4.70 MB How to install: sudo apt install nmap
- libc6
- libgcc-s1
- liblinear4
- liblua5.4-0
- libpcap0.8t64
- libpcre2-8-0
- libssh2-1t64
- libssl3t64
- libstdc++6
- nmap-common
- zlib1g

##### nmap

Network exploration tool and security / port scanner

```
root@kali:~# nmap -h
Nmap 7.99 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
  --excludefile <exclude_file>: Exclude list from file
HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
  -PS/PA/PU/PY[portlist]: TCP SYN, TCP ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS's DNS resolver
  --traceroute: Trace hop path to each host
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  --exclude-ports <port ranges>: Exclude the specified ports from scanning
  -F: Fast mode - Scan fewer ports than the default scan
  -r: Scan ports sequentially - don't randomize
  --top-ports <number>: Scan <number> most common ports
  --port-ratio <ratio>: Scan ports more common than <ratio>
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
  --version-light: Limit to most likely probes (intensity 2)
  --version-all: Try every single probe (intensity 9)
  --version-trace: Show detailed version scan activity (for debugging)
SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of
           directories, script-files or script-categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-args-file=filename: provide NSE script args in a file
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
  --script-help=<Lua scripts>: Show help about scripts.
           <Lua scripts> is a comma-separated list of script-files or
           script-categories.
OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
      probe round trip time.
  --max-retries <tries>: Caps number of port scan probe retransmissions.
  --host-timeout <time>: Give up on target after this long
  --scan-delay/--max-scan-delay <time>: Adjust delay between probes
  --min-rate <number>: Send packets no slower than <number> per second
  --max-rate <number>: Send packets no faster than <number> per second
FIREWALL/IDS EVASION AND SPOOFING:
  -f; --mtu <val>: fragment packets (optionally w/given MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  -S <IP_Address>: Spoof source address
  -e <iface>: Use specified interface
  -g/--source-port <portnum>: Use given port number
  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
  --data <hex string>: Append a custom payload to sent packets
  --data-string <string>: Append a custom ASCII string to sent packets
  --data-length <num>: Append random data to sent packets
  --ip-options <options>: Send packets with specified ip options
  --ttl <val>: Set IP time-to-live field
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
     and Grepable format, respectively, to the given filename.
  -oA <basename>: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level (use -dd or more for greater effect)
  --reason: Display the reason a port is in a particular state
  --open: Only show open (or possibly open) ports
  --packet-trace: Show all packets sent and received
  --iflist: Print host interfaces and routes (for debugging)
  --append-output: Append to rather than clobber specified output files
  --resume <filename>: Resume an aborted scan
  --noninteractive: Disable runtime interactions via keyboard
  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
  --webxml: Reference stylesheet from Nmap.Org for more portable XML
  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
MISC:
  -6: Enable IPv6 scanning
  -A: Enable OS detection, version detection, script scanning, and traceroute
  --datadir <dirname>: Specify custom Nmap data file location
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
  --privileged: Assume that the user is fully privileged
  --unprivileged: Assume the user lacks raw socket privileges
  -V: Print version number
  -h: Print this help summary page.
EXAMPLES:
  nmap -v -A scanme.nmap.org
  nmap -v -sn 192.168.0.0/16 10.0.0.0/8
  nmap -v -iR 10000 -Pn -p 80
SEE THE MAN PAGE (https://nmap.org/book/man.html) FOR MORE OPTIONS AND EXAMPLES
```

##### nping

Network packet generation tool / ping utility

```
root@kali:~# nping -h
Nping 0.7.99 ( https://nmap.org/nping )
Usage: nping [Probe mode] [Options] {target specification}

TARGET SPECIFICATION:
  Targets may be specified as hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.*.1-24
PROBE MODES:
  --tcp-connect                    : Unprivileged TCP connect probe mode.
  --tcp                            : TCP probe mode.
  --udp                            : UDP probe mode.
  --icmp                           : ICMP probe mode.
  --arp                            : ARP/RARP probe mode.
  --tr, --traceroute               : Traceroute mode (can only be used with 
                                     TCP/UDP/ICMP modes).
TCP CONNECT MODE:
   -p, --dest-port <port spec>     : Set destination port(s).
   -g, --source-port <portnumber>  : Try to use a custom source port.
TCP PROBE MODE:
   -g, --source-port <portnumber>  : Set source port.
   -p, --dest-port <port spec>     : Set destination port(s).
   --seq <seqnumber>               : Set sequence number.
   --flags <flag list>             : Set TCP flags (ACK,PSH,RST,SYN,FIN...)
   --ack <acknumber>               : Set ACK number.
   --win <size>                    : Set window size.
   --badsum                        : Use a random invalid checksum. 
UDP PROBE MODE:
   -g, --source-port <portnumber>  : Set source port.
   -p, --dest-port <port spec>     : Set destination port(s).
   --badsum                        : Use a random invalid checksum. 
ICMP PROBE MODE:
  --icmp-type <type>               : ICMP type.
  --icmp-code <code>               : ICMP code.
  --icmp-id <id>                   : Set identifier.
  --icmp-seq <n>                   : Set sequence number.
  --icmp-redirect-addr <addr>      : Set redirect address.
  --icmp-param-pointer <pnt>       : Set parameter problem pointer.
  --icmp-advert-lifetime <time>    : Set router advertisement lifetime.
  --icmp-advert-entry <IP,pref>    : Add router advertisement entry.
  --icmp-orig-time  <timestamp>    : Set originate timestamp.
  --icmp-recv-time  <timestamp>    : Set receive timestamp.
  --icmp-trans-time <timestamp>    : Set transmit timestamp.
ARP/RARP PROBE MODE:
  --arp-type <type>                : Type: ARP, ARP-reply, RARP, RARP-reply.
  --arp-sender-mac <mac>           : Set sender MAC address.
  --arp-sender-ip  <addr>          : Set sender IP address.
  --arp-target-mac <mac>           : Set target MAC address.
  --arp-target-ip  <addr>          : Set target IP address.
IPv4 OPTIONS:
  -S, --source-ip                  : Set source IP address.
  --dest-ip <addr>                 : Set destination IP address (used as an 
                                     alternative to {target specification} ). 
  --tos <tos>                      : Set type of service field (8bits).
  --id  <id>                       : Set identification field (16 bits).
  --df                             : Set Don't Fragment flag.
  --mf                             : Set More Fragments flag.
  --evil                           : Set Reserved / Evil flag.
  --ttl <hops>                     : Set time to live [0-255].
  --badsum-ip                      : Use a random invalid checksum. 
  --ip-options <R|S [route]|L [route]|T|U ...> : Set IP options
  --ip-options <hex string>                    : Set IP options
  --mtu <size>                     : Set MTU. Packets get fragmented if MTU is
                                     small enough.
IPv6 OPTIONS:
  -6, --IPv6                       : Use IP version 6.
  --dest-ip                        : Set destination IP address (used as an
                                     alternative to {target specification}).
  --hop-limit                      : Set hop limit (same as IPv4 TTL).
  --traffic-class <class> :        : Set traffic class.
  --flow <label>                   : Set flow label.
ETHERNET OPTIONS:
  --dest-mac <mac>                 : Set destination mac address. (Disables
                                     ARP resolution)
  --source-mac <mac>               : Set source MAC address.
  --ether-type <type>              : Set EtherType value.
PAYLOAD OPTIONS:
  --data <hex string>              : Include a custom payload.
  --data-string <text>             : Include a custom ASCII text.
  --data-length <len>              : Include len random bytes as payload.
ECHO CLIENT/SERVER:
  --echo-client <passphrase>       : Run Nping in client mode.
  --echo-server <passphrase>       : Run Nping in server mode.
  --echo-port <port>               : Use custom <port> to listen or connect.
  --no-crypto                      : Disable encryption and authentication.
  --once                           : Stop the server after one connection.
  --safe-payloads                  : Erase application data in echoed packets.
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m, 0.25h).
  --delay <time>                   : Adjust delay between probes.
  --rate  <rate>                   : Send num packets per second.
MISC:
  -h, --help                       : Display help information.
  -V, --version                    : Display current version number. 
  -c, --count <n>                  : Stop after <n> rounds.
  -e, --interface <name>           : Use supplied network interface.
  -H, --hide-sent                  : Do not display sent packets.
  -N, --no-capture                 : Do not try to capture replies.
  --privileged                     : Assume user is fully privileged.
  --unprivileged                   : Assume user lacks raw socket privileges.
  --send-eth                       : Send packets at the raw Ethernet layer.
  --send-ip                        : Send packets using raw IP sockets.
  --bpf-filter <filter spec>       : Specify custom BPF filter.
OUTPUT:
  -v                               : Increment verbosity level by one.
  -v[level]                        : Set verbosity level. E.g: -v4
  -d                               : Increment debugging level by one.
  -d[level]                        : Set debugging level. E.g: -d3
  -q                               : Decrease verbosity level by one.
  -q[N]                            : Decrease verbosity level N times
  --quiet                          : Set verbosity and debug level to minimum.
  --debug                          : Set verbosity and debug to the max level.
EXAMPLES:
  nping scanme.nmap.org
  nping --tcp -p 80 --flags rst --ttl 2 192.168.1.1
  nping --icmp --icmp-type time --delay 500ms 192.168.254.254
  nping --echo-server "public" -e wlan0 -vvv 
  nping --echo-client "public" echo.nmap.org --tcp -p1-1024 --flags ack

SEE THE MAN PAGE FOR MANY MORE OPTIONS, DESCRIPTIONS, AND EXAMPLES
```

#### nmap-common

Architecture independent files for nmap Nmap is a utility for network exploration or security auditing. It
supports ping scanning (determine which hosts are up), many port
scanning techniques, version detection (determine service protocols
and application versions listening behind ports), and TCP/IP
fingerprinting (remote host OS or device identification). Nmap also
offers flexible target and port specification, decoy/stealth scanning,
sunRPC scanning, and more. Most Unix and Windows platforms are
supported in both GUI and commandline modes. Several popular handheld
devices are also supported, including the Sharp Zaurus and the iPAQ.
This package contains the nmap files shared by all architectures.
Installed size: 22.74 MB How to install: sudo apt install nmap-common

#### zenmap

The Network Mapper Front End Zenmap is an Nmap frontend. It is meant to be useful for advanced users
and to make Nmap easy to use by beginners. It was originally derived
from Umit, an Nmap GUI created as part of the Google Summer of Code.
Installed size: 1.76 MB How to install: sudo apt install zenmap
- gir1.2-gdkpixbuf-2.0
- gir1.2-glib-2.0
- gir1.2-gtk-3.0
- gir1.2-pango-1.0
- ndiff
- nmap
- python3
- python3-gi
- python3-gi-cairo

##### zenmap

Graphical Nmap frontend and results viewer

```
root@kali:~# zenmap -h
Usage: zenmap [options] [result files]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  --confdir=DIR         Use DIR as the user configuration directory. Default:
                        /root/.zenmap
  -f RESULT_FILES, --file=RESULT_FILES
                        Specify a scan result file in Nmap XML output format.
                        Can be used more than once to specify several scan
                        result files.
  -n, --nmap            Run Nmap with the specified args.
  -p PROFILE, --profile=PROFILE
                        Begin with the specified profile selected. If combined
                        with the -t (--target) option, automatically run the
                        profile against the specified target.
  -t TARGET, --target=TARGET
                        Specify a target to be used along with other options.
                        If specified alone, open with the target field filled
                        with the specified target
  -v, --verbose         Increase verbosity of the output. May be used more
                        than once to get even more verbosity
```

#### Learn more with OffSec

Want to learn more about nmap? get access to in-depth training and hands-on labs:
- PEN-200: 6.4.3. Port Scanning with Nmap
- WEB-200: 2.2.2. Web Application Enumeration Methodology: Discovering Running Services
- SEC-100: 19.2.3. Information Gathering and Enumeration: Port Scanning with Nmap
- Network Penetration Tester Tools Skill Path: 1. Introduction to Nmap
- PEN-200: 20. Tunneling Through Deep Packet Inspection
PEN-200 course
WEB-200 course
SEC-100 course
Updated on: 2026-May-25

### nmap-smb-vuln

Source: https://www.kali.org/tools/nmap/

#### Tool Documentation:



#### Tool Documentation:

#### nmap Usage Example

Scan in verbose mode ( -v ), enable OS detection, version detection, script scanning, and traceroute ( -A ), with version detection ( -sV ) against the target IP ( 192.168.1.1 ):

```
root@kali:~# nmap -v -A -sV 192.168.1.1

Starting Nmap 6.45 ( http://nmap.org ) at 2014-05-13 18:40 MDT
NSE: Loaded 118 scripts for scanning.
NSE: Script Pre-scanning.
Initiating ARP Ping Scan at 18:40
Scanning 192.168.1.1 [1 port]
Completed ARP Ping Scan at 18:40, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:40
Completed Parallel DNS resolution of 1 host. at 18:40, 0.00s elapsed
Initiating SYN Stealth Scan at 18:40
Scanning router.localdomain (192.168.1.1) [1000 ports]
Discovered open port 53/tcp on 192.168.1.1
Discovered open port 22/tcp on 192.168.1.1
Discovered open port 80/tcp on 192.168.1.1
Discovered open port 3001/tcp on 192.168.1.1
```

#### nping Usage Example

Using TCP mode ( –tcp ) to probe port 22 ( -p 22 ) using the SYN flag ( –flags syn ) with a TTL of 2 ( –ttl 2 ) on the remote host ( 192.168.1.1 ):

```
root@kali:~# nping --tcp -p 22 --flags syn --ttl 2 192.168.1.1

Starting Nping 0.6.45 ( http://nmap.org/nping ) at 2014-05-13 18:43 MDT
SENT (0.0673s) TCP 192.168.1.15:60125 > 192.168.1.1:22 S ttl=2 id=54240 iplen=40  seq=1720523417 win=1480
RCVD (0.0677s) TCP 192.168.1.1:22 > 192.168.1.15:60125 SA ttl=64 id=0 iplen=44  seq=3377886789 win=5840 <mss 1460>
SENT (1.0678s) TCP 192.168.1.15:60125 > 192.168.1.1:22 S ttl=2 id=54240 iplen=40  seq=1720523417 win=1480
RCVD (1.0682s) TCP 192.168.1.1:22 > 192.168.1.15:60125 SA ttl=64 id=0 iplen=44  seq=3393519366 win=5840 <mss 1460>
SENT (2.0693s) TCP 192.168.1.15:60125 > 192.168.1.1:22 S ttl=2 id=54240 iplen=40  seq=1720523417 win=1480
RCVD (2.0696s) TCP 192.168.1.1:22 > 192.168.1.15:60125 SA ttl=64 id=0 iplen=44  seq=3409166569 win=5840 <mss 1460>
SENT (3.0707s) TCP 192.168.1.15:60125 > 192.168.1.1:22 S ttl=2 id=54240 iplen=40  seq=1720523417 win=1480
RCVD (3.0710s) TCP 192.168.1.1:22 > 192.168.1.15:60125 SA ttl=64 id=0 iplen=44  seq=3424813300 win=5840 <mss 1460>
SENT (4.0721s) TCP 192.168.1.15:60125 > 192.168.1.1:22 S ttl=2 id=54240 iplen=40  seq=1720523417 win=1480
RCVD (4.0724s) TCP 192.168.1.1:22 > 192.168.1.15:60125 SA ttl=64 id=0 iplen=44  seq=3440460772 win=5840 <mss 1460>

Max rtt: 0.337ms | Min rtt: 0.282ms | Avg rtt: 0.296ms
Raw packets sent: 5 (200B) | Rcvd: 5 (230B) | Lost: 0 (0.00%)
Nping done: 1 IP address pinged in 4.13 seconds
```

#### ndiff Usage Example

Compare yesterday’s port scan ( yesterday.xml ) with the scan from today ( today.xml ):

```
root@kali:~# ndiff yesterday.xml today.xml
-Nmap 6.45 scan initiated Tue May 13 18:46:43 2014 as: nmap -v -F -oX yesterday.xml 192.168.1.1
+Nmap 6.45 scan initiated Tue May 13 18:47:58 2014 as: nmap -v -F -oX today.xml 192.168.1.1

 endian.localdomain (192.168.1.1, 00:01:6C:6F:DD:D1):
-Not shown: 96 filtered ports
+Not shown: 97 filtered ports
 PORT   STATE SERVICE VERSION
-22/tcp open  ssh
```

#### ncat Usage Example

Be verbose ( -v ), running /bin/bash on connect ( –exec “/bin/bash” ), only allowing 1 IP address ( –allow 192.168.1.123 ), listen on TCP port 4444 ( -l 4444 ), and keep the listener open on disconnect ( –keep-open ):

```
root@kali:~# ncat -v --exec "/bin/bash" --allow 192.168.1.123 -l 4444 --keep-open
Ncat: Version 6.45 ( http://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.1.123.
Ncat: Connection from 192.168.1.123:39501.
Ncat: Connection from 192.168.1.15.
Ncat: Connection from 192.168.1.15:60393.
Ncat: New connection denied: not allowed
```


#### ncat

NMAP netcat reimplementation ncat is a reimplementation of Netcat by the NMAP project, providing
most of the features present in the original implementations, along
with some new features such as IPv6 and SSL support. Port scanning
support has been removed.
Installed size: 807 KB How to install: sudo apt install ncat
- libc6
- liblua5.4-0
- libpcap0.8t64
- libssl3t64

##### ncat

Concatenate and redirect sockets

```
root@kali:~# ncat -h
Ncat 7.99 ( https://nmap.org/ncat )
Usage: ncat [options] [hostname] [port]

Options taking a time assume seconds. Append 'ms' for milliseconds,
's' for seconds, 'm' for minutes, or 'h' for hours (e.g. 500ms).
  -4                         Use IPv4 only
  -6                         Use IPv6 only
  -U, --unixsock             Use Unix domain sockets only
      --vsock                Use vsock sockets only
  -C, --crlf                 Use CRLF for EOL sequence
  -c, --sh-exec <command>    Executes the given command via /bin/sh
  -e, --exec <command>       Executes the given command
      --lua-exec <filename>  Executes the given Lua script
  -g hop1[,hop2,...]         Loose source routing hop points (8 max)
  -G <n>                     Loose source routing hop pointer (4, 8, 12, ...)
  -m, --max-conns <n>        Maximum <n> simultaneous connections
  -h, --help                 Display this help screen
  -d, --delay <time>         Wait between read/writes
  -o, --output <filename>    Dump session data to a file
  -x, --hex-dump <filename>  Dump session data as hex to a file
  -i, --idle-timeout <time>  Idle read/write timeout
  -p, --source-port port     Specify source port to use
  -s, --source addr          Specify source address to use (doesn't affect -l)
  -l, --listen               Bind and listen for incoming connections
  -k, --keep-open            Accept multiple connections in listen mode
  -n, --nodns                Do not resolve hostnames via DNS
  -t, --telnet               Answer Telnet negotiations
  -u, --udp                  Use UDP instead of default TCP
      --sctp                 Use SCTP instead of default TCP
  -v, --verbose              Set verbosity level (can be used several times)
  -w, --wait <time>          Connect timeout
  -z                         Zero-I/O mode, report connection status only
      --append-output        Append rather than clobber specified output files
      --send-only            Only send data, ignoring received; quit on EOF
      --recv-only            Only receive data, never send anything
      --no-shutdown          Continue half-duplex when receiving EOF on stdin
  -q <time>                  After EOF on stdin, wait <time> then quit.
      --allow                Allow only given hosts to connect to Ncat
      --allowfile            A file of hosts allowed to connect to Ncat
      --deny                 Deny given hosts from connecting to Ncat
      --denyfile             A file of hosts denied from connecting to Ncat
      --broker               Enable Ncat's connection brokering mode
      --chat                 Start a simple Ncat chat server
      --proxy <addr[:port]>  Specify address of host to proxy through
      --proxy-type <type>    Specify proxy type ("http", "socks4", "socks5")
      --proxy-auth <auth>    Authenticate with HTTP or SOCKS proxy server
      --proxy-dns <type>     Specify where to resolve proxy destination
      --ssl                  Connect or listen with SSL
      --ssl-cert             Specify SSL certificate file (PEM) for listening
      --ssl-key              Specify SSL private key (PEM) for listening
      --ssl-verify           Verify trust and domain name of certificates
      --ssl-trustfile        PEM file containing trusted SSL certificates
      --ssl-ciphers          Cipherlist containing SSL ciphers to use
      --ssl-servername       Request distinct server name (SNI)
      --ssl-alpn             ALPN protocol list to use
      --version              Display Ncat's version information and exit

See the ncat(1) manpage for full options, descriptions and usage examples
```

#### ndiff

The Network Mapper - result compare utility Ndiff is a tool to aid in the comparison of Nmap scans. It takes two
Nmap XML output files and prints the differences between them them:
hosts coming up and down, ports becoming open or closed, and things like that.
It can produce output in human-readable text or machine-readable XML formats.
Installed size: 432 KB How to install: sudo apt install ndiff
- python3
- python3-lxml

##### ndiff

```
root@kali:~# ndiff -h
Usage: /usr/bin/ndiff [option] FILE1 FILE2
Compare two Nmap XML files and display a list of their differences.
Differences include host state changes, port state changes, and changes to
service and OS detection.

  -h, --help     display this help
  -v, --verbose  also show hosts and ports that haven't changed.
  --text         display output in text format (default)
  --xml          display output in XML format
```

#### nmap

The Network Mapper Nmap is a utility for network exploration or security auditing. It
supports ping scanning (determine which hosts are up), many port
scanning techniques, version detection (determine service protocols
and application versions listening behind ports), and TCP/IP
fingerprinting (remote host OS or device identification). Nmap also
offers flexible target and port specification, decoy/stealth scanning,
sunRPC scanning, and more. Most Unix and Windows platforms are
supported in both GUI and commandline modes. Several popular handheld
devices are also supported, including the Sharp Zaurus and the iPAQ.
Installed size: 4.70 MB How to install: sudo apt install nmap
- libc6
- libgcc-s1
- liblinear4
- liblua5.4-0
- libpcap0.8t64
- libpcre2-8-0
- libssh2-1t64
- libssl3t64
- libstdc++6
- nmap-common
- zlib1g

##### nmap

Network exploration tool and security / port scanner

```
root@kali:~# nmap -h
Nmap 7.99 ( https://nmap.org )
Usage: nmap [Scan Type(s)] [Options] {target specification}
TARGET SPECIFICATION:
  Can pass hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254
  -iL <inputfilename>: Input from list of hosts/networks
  -iR <num hosts>: Choose random targets
  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks
  --excludefile <exclude_file>: Exclude list from file
HOST DISCOVERY:
  -sL: List Scan - simply list targets to scan
  -sn: Ping Scan - disable port scan
  -Pn: Treat all hosts as online -- skip host discovery
  -PS/PA/PU/PY[portlist]: TCP SYN, TCP ACK, UDP or SCTP discovery to given ports
  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes
  -PO[protocol list]: IP Protocol Ping
  -n/-R: Never do DNS resolution/Always resolve [default: sometimes]
  --dns-servers <serv1[,serv2],...>: Specify custom DNS servers
  --system-dns: Use OS's DNS resolver
  --traceroute: Trace hop path to each host
SCAN TECHNIQUES:
  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans
  -sU: UDP Scan
  -sN/sF/sX: TCP Null, FIN, and Xmas scans
  --scanflags <flags>: Customize TCP scan flags
  -sI <zombie host[:probeport]>: Idle scan
  -sY/sZ: SCTP INIT/COOKIE-ECHO scans
  -sO: IP protocol scan
  -b <FTP relay host>: FTP bounce scan
PORT SPECIFICATION AND SCAN ORDER:
  -p <port ranges>: Only scan specified ports
    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9
  --exclude-ports <port ranges>: Exclude the specified ports from scanning
  -F: Fast mode - Scan fewer ports than the default scan
  -r: Scan ports sequentially - don't randomize
  --top-ports <number>: Scan <number> most common ports
  --port-ratio <ratio>: Scan ports more common than <ratio>
SERVICE/VERSION DETECTION:
  -sV: Probe open ports to determine service/version info
  --version-intensity <level>: Set from 0 (light) to 9 (try all probes)
  --version-light: Limit to most likely probes (intensity 2)
  --version-all: Try every single probe (intensity 9)
  --version-trace: Show detailed version scan activity (for debugging)
SCRIPT SCAN:
  -sC: equivalent to --script=default
  --script=<Lua scripts>: <Lua scripts> is a comma separated list of
           directories, script-files or script-categories
  --script-args=<n1=v1,[n2=v2,...]>: provide arguments to scripts
  --script-args-file=filename: provide NSE script args in a file
  --script-trace: Show all data sent and received
  --script-updatedb: Update the script database.
  --script-help=<Lua scripts>: Show help about scripts.
           <Lua scripts> is a comma-separated list of script-files or
           script-categories.
OS DETECTION:
  -O: Enable OS detection
  --osscan-limit: Limit OS detection to promising targets
  --osscan-guess: Guess OS more aggressively
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m).
  -T<0-5>: Set timing template (higher is faster)
  --min-hostgroup/max-hostgroup <size>: Parallel host scan group sizes
  --min-parallelism/max-parallelism <numprobes>: Probe parallelization
  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>: Specifies
      probe round trip time.
  --max-retries <tries>: Caps number of port scan probe retransmissions.
  --host-timeout <time>: Give up on target after this long
  --scan-delay/--max-scan-delay <time>: Adjust delay between probes
  --min-rate <number>: Send packets no slower than <number> per second
  --max-rate <number>: Send packets no faster than <number> per second
FIREWALL/IDS EVASION AND SPOOFING:
  -f; --mtu <val>: fragment packets (optionally w/given MTU)
  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys
  -S <IP_Address>: Spoof source address
  -e <iface>: Use specified interface
  -g/--source-port <portnum>: Use given port number
  --proxies <url1,[url2],...>: Relay connections through HTTP/SOCKS4 proxies
  --data <hex string>: Append a custom payload to sent packets
  --data-string <string>: Append a custom ASCII string to sent packets
  --data-length <num>: Append random data to sent packets
  --ip-options <options>: Send packets with specified ip options
  --ttl <val>: Set IP time-to-live field
  --spoof-mac <mac address/prefix/vendor name>: Spoof your MAC address
  --badsum: Send packets with a bogus TCP/UDP/SCTP checksum
OUTPUT:
  -oN/-oX/-oS/-oG <file>: Output scan in normal, XML, s|<rIpt kIddi3,
     and Grepable format, respectively, to the given filename.
  -oA <basename>: Output in the three major formats at once
  -v: Increase verbosity level (use -vv or more for greater effect)
  -d: Increase debugging level (use -dd or more for greater effect)
  --reason: Display the reason a port is in a particular state
  --open: Only show open (or possibly open) ports
  --packet-trace: Show all packets sent and received
  --iflist: Print host interfaces and routes (for debugging)
  --append-output: Append to rather than clobber specified output files
  --resume <filename>: Resume an aborted scan
  --noninteractive: Disable runtime interactions via keyboard
  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML
  --webxml: Reference stylesheet from Nmap.Org for more portable XML
  --no-stylesheet: Prevent associating of XSL stylesheet w/XML output
MISC:
  -6: Enable IPv6 scanning
  -A: Enable OS detection, version detection, script scanning, and traceroute
  --datadir <dirname>: Specify custom Nmap data file location
  --send-eth/--send-ip: Send using raw ethernet frames or IP packets
  --privileged: Assume that the user is fully privileged
  --unprivileged: Assume the user lacks raw socket privileges
  -V: Print version number
  -h: Print this help summary page.
EXAMPLES:
  nmap -v -A scanme.nmap.org
  nmap -v -sn 192.168.0.0/16 10.0.0.0/8
  nmap -v -iR 10000 -Pn -p 80
SEE THE MAN PAGE (https://nmap.org/book/man.html) FOR MORE OPTIONS AND EXAMPLES
```

##### nping

Network packet generation tool / ping utility

```
root@kali:~# nping -h
Nping 0.7.99 ( https://nmap.org/nping )
Usage: nping [Probe mode] [Options] {target specification}

TARGET SPECIFICATION:
  Targets may be specified as hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.*.1-24
PROBE MODES:
  --tcp-connect                    : Unprivileged TCP connect probe mode.
  --tcp                            : TCP probe mode.
  --udp                            : UDP probe mode.
  --icmp                           : ICMP probe mode.
  --arp                            : ARP/RARP probe mode.
  --tr, --traceroute               : Traceroute mode (can only be used with 
                                     TCP/UDP/ICMP modes).
TCP CONNECT MODE:
   -p, --dest-port <port spec>     : Set destination port(s).
   -g, --source-port <portnumber>  : Try to use a custom source port.
TCP PROBE MODE:
   -g, --source-port <portnumber>  : Set source port.
   -p, --dest-port <port spec>     : Set destination port(s).
   --seq <seqnumber>               : Set sequence number.
   --flags <flag list>             : Set TCP flags (ACK,PSH,RST,SYN,FIN...)
   --ack <acknumber>               : Set ACK number.
   --win <size>                    : Set window size.
   --badsum                        : Use a random invalid checksum. 
UDP PROBE MODE:
   -g, --source-port <portnumber>  : Set source port.
   -p, --dest-port <port spec>     : Set destination port(s).
   --badsum                        : Use a random invalid checksum. 
ICMP PROBE MODE:
  --icmp-type <type>               : ICMP type.
  --icmp-code <code>               : ICMP code.
  --icmp-id <id>                   : Set identifier.
  --icmp-seq <n>                   : Set sequence number.
  --icmp-redirect-addr <addr>      : Set redirect address.
  --icmp-param-pointer <pnt>       : Set parameter problem pointer.
  --icmp-advert-lifetime <time>    : Set router advertisement lifetime.
  --icmp-advert-entry <IP,pref>    : Add router advertisement entry.
  --icmp-orig-time  <timestamp>    : Set originate timestamp.
  --icmp-recv-time  <timestamp>    : Set receive timestamp.
  --icmp-trans-time <timestamp>    : Set transmit timestamp.
ARP/RARP PROBE MODE:
  --arp-type <type>                : Type: ARP, ARP-reply, RARP, RARP-reply.
  --arp-sender-mac <mac>           : Set sender MAC address.
  --arp-sender-ip  <addr>          : Set sender IP address.
  --arp-target-mac <mac>           : Set target MAC address.
  --arp-target-ip  <addr>          : Set target IP address.
IPv4 OPTIONS:
  -S, --source-ip                  : Set source IP address.
  --dest-ip <addr>                 : Set destination IP address (used as an 
                                     alternative to {target specification} ). 
  --tos <tos>                      : Set type of service field (8bits).
  --id  <id>                       : Set identification field (16 bits).
  --df                             : Set Don't Fragment flag.
  --mf                             : Set More Fragments flag.
  --evil                           : Set Reserved / Evil flag.
  --ttl <hops>                     : Set time to live [0-255].
  --badsum-ip                      : Use a random invalid checksum. 
  --ip-options <R|S [route]|L [route]|T|U ...> : Set IP options
  --ip-options <hex string>                    : Set IP options
  --mtu <size>                     : Set MTU. Packets get fragmented if MTU is
                                     small enough.
IPv6 OPTIONS:
  -6, --IPv6                       : Use IP version 6.
  --dest-ip                        : Set destination IP address (used as an
                                     alternative to {target specification}).
  --hop-limit                      : Set hop limit (same as IPv4 TTL).
  --traffic-class <class> :        : Set traffic class.
  --flow <label>                   : Set flow label.
ETHERNET OPTIONS:
  --dest-mac <mac>                 : Set destination mac address. (Disables
                                     ARP resolution)
  --source-mac <mac>               : Set source MAC address.
  --ether-type <type>              : Set EtherType value.
PAYLOAD OPTIONS:
  --data <hex string>              : Include a custom payload.
  --data-string <text>             : Include a custom ASCII text.
  --data-length <len>              : Include len random bytes as payload.
ECHO CLIENT/SERVER:
  --echo-client <passphrase>       : Run Nping in client mode.
  --echo-server <passphrase>       : Run Nping in server mode.
  --echo-port <port>               : Use custom <port> to listen or connect.
  --no-crypto                      : Disable encryption and authentication.
  --once                           : Stop the server after one connection.
  --safe-payloads                  : Erase application data in echoed packets.
TIMING AND PERFORMANCE:
  Options which take <time> are in seconds, or append 'ms' (milliseconds),
  's' (seconds), 'm' (minutes), or 'h' (hours) to the value (e.g. 30m, 0.25h).
  --delay <time>                   : Adjust delay between probes.
  --rate  <rate>                   : Send num packets per second.
MISC:
  -h, --help                       : Display help information.
  -V, --version                    : Display current version number. 
  -c, --count <n>                  : Stop after <n> rounds.
  -e, --interface <name>           : Use supplied network interface.
  -H, --hide-sent                  : Do not display sent packets.
  -N, --no-capture                 : Do not try to capture replies.
  --privileged                     : Assume user is fully privileged.
  --unprivileged                   : Assume user lacks raw socket privileges.
  --send-eth                       : Send packets at the raw Ethernet layer.
  --send-ip                        : Send packets using raw IP sockets.
  --bpf-filter <filter spec>       : Specify custom BPF filter.
OUTPUT:
  -v                               : Increment verbosity level by one.
  -v[level]                        : Set verbosity level. E.g: -v4
  -d                               : Increment debugging level by one.
  -d[level]                        : Set debugging level. E.g: -d3
  -q                               : Decrease verbosity level by one.
  -q[N]                            : Decrease verbosity level N times
  --quiet                          : Set verbosity and debug level to minimum.
  --debug                          : Set verbosity and debug to the max level.
EXAMPLES:
  nping scanme.nmap.org
  nping --tcp -p 80 --flags rst --ttl 2 192.168.1.1
  nping --icmp --icmp-type time --delay 500ms 192.168.254.254
  nping --echo-server "public" -e wlan0 -vvv 
  nping --echo-client "public" echo.nmap.org --tcp -p1-1024 --flags ack

SEE THE MAN PAGE FOR MANY MORE OPTIONS, DESCRIPTIONS, AND EXAMPLES
```

#### nmap-common

Architecture independent files for nmap Nmap is a utility for network exploration or security auditing. It
supports ping scanning (determine which hosts are up), many port
scanning techniques, version detection (determine service protocols
and application versions listening behind ports), and TCP/IP
fingerprinting (remote host OS or device identification). Nmap also
offers flexible target and port specification, decoy/stealth scanning,
sunRPC scanning, and more. Most Unix and Windows platforms are
supported in both GUI and commandline modes. Several popular handheld
devices are also supported, including the Sharp Zaurus and the iPAQ.
This package contains the nmap files shared by all architectures.
Installed size: 22.74 MB How to install: sudo apt install nmap-common

#### zenmap

The Network Mapper Front End Zenmap is an Nmap frontend. It is meant to be useful for advanced users
and to make Nmap easy to use by beginners. It was originally derived
from Umit, an Nmap GUI created as part of the Google Summer of Code.
Installed size: 1.76 MB How to install: sudo apt install zenmap
- gir1.2-gdkpixbuf-2.0
- gir1.2-glib-2.0
- gir1.2-gtk-3.0
- gir1.2-pango-1.0
- ndiff
- nmap
- python3
- python3-gi
- python3-gi-cairo

##### zenmap

Graphical Nmap frontend and results viewer

```
root@kali:~# zenmap -h
Usage: zenmap [options] [result files]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  --confdir=DIR         Use DIR as the user configuration directory. Default:
                        /root/.zenmap
  -f RESULT_FILES, --file=RESULT_FILES
                        Specify a scan result file in Nmap XML output format.
                        Can be used more than once to specify several scan
                        result files.
  -n, --nmap            Run Nmap with the specified args.
  -p PROFILE, --profile=PROFILE
                        Begin with the specified profile selected. If combined
                        with the -t (--target) option, automatically run the
                        profile against the specified target.
  -t TARGET, --target=TARGET
                        Specify a target to be used along with other options.
                        If specified alone, open with the target field filled
                        with the specified target
  -v, --verbose         Increase verbosity of the output. May be used more
                        than once to get even more verbosity
```

#### Learn more with OffSec

Want to learn more about nmap? get access to in-depth training and hands-on labs:
- PEN-200: 6.4.3. Port Scanning with Nmap
- WEB-200: 2.2.2. Web Application Enumeration Methodology: Discovering Running Services
- SEC-100: 19.2.3. Information Gathering and Enumeration: Port Scanning with Nmap
- Network Penetration Tester Tools Skill Path: 1. Introduction to Nmap
- PEN-200: 20. Tunneling Through Deep Packet Inspection
PEN-200 course
WEB-200 course
SEC-100 course
Updated on: 2026-May-25

### nuclei

Source: https://www.kali.org/tools/nuclei/

#### nuclei

Fast and customizable vulnerability scanner based on simple YAML based DSL This package contains a fast tool for configurable targeted scanning based on
templates offering massive extensibility and ease of use.
Nuclei is used to send requests across targets based on a template
leading to zero false positives and providing fast scanning on large
number of hosts. Nuclei offers scanning for a variety of protocols
including TCP, DNS, HTTP, File, etc. With powerful and flexible
templating, all kinds of security checks can be modelled with Nuclei.
Installed size: 119.32 MB How to install: sudo apt install nuclei

##### nuclei

```
root@kali:~# nuclei -h
Nuclei is a fast, template based vulnerability scanner focusing
on extensive configurability, massive extensibility and ease of use.

Usage:
  nuclei [flags]

Flags:
TARGET:
   -u, -target string[]          target URLs/hosts to scan
   -l, -list string              path to file containing a list of target URLs/hosts to scan (one per line)
   -targets-inline string        inline multiline target list (for use in template profiles)
   -eh, -exclude-hosts string[]  hosts to exclude to scan from the input list (ip, cidr, hostname)
   -resume string                resume scan from and save to specified file (clustering will be disabled)
   -sa, -scan-all-ips            scan all the IP's associated with dns record
   -iv, -ip-version string[]     IP version to scan of hostname (4,6) - (default 4)

TARGET-FORMAT:
   -im, -input-mode string         mode of input file (list, burp, jsonl, yaml, openapi, swagger) (default "list")
   -ro, -required-only             use only required fields in input format when generating requests
   -sfv, -skip-format-validation   skip format validation (like missing vars) when parsing input file
   -vtt, -vars-text-templating     enable text templating for vars in input file (only for yaml input mode)
   -vfp, -var-file-paths string[]  list of yaml file contained vars to inject into yaml input

TEMPLATES:
   -nt, -new-templates                    run only new templates added in latest nuclei-templates release
   -ntv, -new-templates-version string[]  run new templates added in specific version
   -as, -automatic-scan                   automatic web scan using wappalyzer technology detection to tags mapping
   -t, -templates string[]                list of template or template directory to run (comma-separated, file)
   -turl, -template-url string[]          template url or list containing template urls to run (comma-separated, file)
   -ai, -prompt string                    generate and run template using ai prompt
   -w, -workflows string[]                list of workflow or workflow directory to run (comma-separated, file)
   -wurl, -workflow-url string[]          workflow url or list containing workflow urls to run (comma-separated, file)
   -validate                              validate the passed templates to nuclei
   -nss, -no-strict-syntax                disable strict syntax check on templates
   -td, -template-display                 displays the templates content
   -tl                                    list all templates matching current filters
   -tgl                                   list all available tags
   -sign                                  signs the templates with the private key defined in NUCLEI_SIGNATURE_PRIVATE_KEY env variable
   -code                                  enable loading code protocol-based templates
   -dut, -disable-unsigned-templates      disable running unsigned templates or templates with mismatched signature
   -esc, -enable-self-contained           enable loading self-contained templates
   -egm, -enable-global-matchers          enable loading global matchers templates
   -file                                  enable loading file templates

FILTERING:
   -a, -author string[]               templates to run based on authors (comma-separated, file)
   -tags string[]                     templates to run based on tags (comma-separated, file)
   -etags, -exclude-tags string[]     templates to exclude based on tags (comma-separated, file)
   -itags, -include-tags string[]     tags to be executed even if they are excluded either by default or configuration
   -id, -template-id string[]         templates to run based on template ids (comma-separated, file, allow-wildcard)
   -eid, -exclude-id string[]         templates to exclude based on template ids (comma-separated, file)
   -it, -include-templates string[]   path to template file or directory to be executed even if they are excluded either by default or configuration
   -et, -exclude-templates string[]   path to template file or directory to exclude (comma-separated, file)
   -em, -exclude-matchers string[]    template matchers to exclude in result
   -s, -severity value[]              templates to run based on severity. Possible values: info, low, medium, high, critical, unknown
   -es, -exclude-severity value[]     templates to exclude based on severity. Possible values: info, low, medium, high, critical, unknown
   -pt, -type value[]                 templates to run based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -ept, -exclude-type value[]        templates to exclude based on protocol type. Possible values: dns, file, http, headless, tcp, workflow, ssl, websocket, whois, code, javascript
   -tc, -template-condition string[]  templates to run based on expression condition

OUTPUT:
   -o, -output string            output file to write found issues/vulnerabilities
   -sresp, -store-resp           store all request/response passed through nuclei to output directory
   -srd, -store-resp-dir string  store all request/response passed through nuclei to custom directory (default "output")
   -silent                       display findings only
   -nc, -no-color                disable output content coloring (ANSI escape codes)
   -j, -jsonl                    write output in JSONL(ines) format
   -irr, -include-rr -omit-raw   include request/response pairs in the JSON, JSONL, and Markdown outputs (for findings only) [DEPRECATED use -omit-raw] (default true)
   -or, -omit-raw                omit request/response pairs in the JSON, JSONL, Markdown, and PDF outputs (for findings only)
   -ot, -omit-template           omit encoded template in the JSON, JSONL output
   -nm, -no-meta                 disable printing result metadata in cli output
   -ts, -timestamp               enables printing timestamp in cli output
   -rdb, -report-db string       nuclei reporting database (always use this to persist report data)
   -ms, -matcher-status          display match failure status
   -me, -markdown-export string  directory to export results in markdown format
   -se, -sarif-export string     file to export results in SARIF format
   -je, -json-export string      file to export results in JSON format
   -jle, -jsonl-export string    file to export results in JSONL(ine) format
   -pe, -pdf-export string       file to export results in PDF format
   -rd, -redact string[]         redact given list of keys from query parameter, request header and body

CONFIGURATIONS:
   -config string                        path to the nuclei configuration file
   -tp, -profile string                  template profile config file to run
   -tpl, -profile-list                   list community template profiles
   -fr, -follow-redirects                enable following redirects for http templates
   -fhr, -follow-host-redirects          follow redirects on the same host
   -mr, -max-redirects int               max number of redirects to follow for http templates (default 10)
   -dr, -disable-redirects               disable redirects for http templates
   -rc, -report-config string            nuclei reporting module configuration file
   -H, -header string[]                  custom header/cookie to include in all http request in header:value format (cli, file)
   -V, -var value                        custom vars in key=value format
   -r, -resolvers string                 file containing resolver list for nuclei
   -sr, -system-resolvers                use system DNS resolving as error fallback
   -dc, -disable-clustering              disable clustering of requests
   -passive                              enable passive HTTP response processing mode
   -fh2, -force-http2                    force http2 connection on requests
   -ev, -env-vars                        enable environment variables to be used in template
   -cc, -client-cert string              client certificate file (PEM-encoded) used for authenticating against scanned hosts
   -ck, -client-key string               client key file (PEM-encoded) used for authenticating against scanned hosts
   -ca, -client-ca string                client certificate authority file (PEM-encoded) used for authenticating against scanned hosts
   -sml, -show-match-line                show match lines for file templates, works with extractors only
   -ztls                                 use ztls library with autofallback to standard one for tls13 [Deprecated] autofallback to ztls is enabled by default
   -sni string                           tls sni hostname to use (default: input domain name)
   -dka, -dialer-keep-alive value        keep-alive duration for network requests.
   -lfa, -allow-local-file-access        allows file (payload) access anywhere on the system
   -lna, -restrict-local-network-access  blocks connections to the local / private network
   -i, -interface string                 network interface to use for network scan
   -at, -attack-type string              type of payload combinations to perform (batteringram,pitchfork,clusterbomb)
   -sip, -source-ip string               source ip address to use for network scan
   -rsr, -response-size-read int         max response size to read in bytes
   -rss, -response-size-save int         max response size to read in bytes (default 1048576)
   -reset                                reset removes all nuclei configuration and data files (including nuclei-templates)
   -tlsi, -tls-impersonate               enable experimental client hello (ja3) tls randomization
   -hae, -http-api-endpoint string       experimental http api endpoint

INTERACTSH:
   -iserver, -interactsh-server string  interactsh server url for self-hosted instance (default: oast.pro,oast.live,oast.site,oast.online,oast.fun,oast.me)
   -itoken, -interactsh-token string    authentication token for self-hosted interactsh server
   -interactions-cache-size int         number of requests to keep in the interactions cache (default 5000)
   -interactions-eviction int           number of seconds to wait before evicting requests from cache (default 60)
   -interactions-poll-duration int      number of seconds to wait before each interaction poll request (default 5)
   -interactions-cooldown-period int    extra time for interaction polling before exiting (default 5)
   -ni, -no-interactsh                  disable interactsh server for OAST testing, exclude OAST based templates

FUZZING:
   -ft, -fuzzing-type string           overrides fuzzing type set in template (replace, prefix, postfix, infix)
   -fm, -fuzzing-mode string           overrides fuzzing mode set in template (multiple, single)
   -fuzz                               enable loading fuzzing templates (Deprecated: use -dast instead)
   -dast                               enable / run dast (fuzz) nuclei templates
   -dts, -dast-server                  enable dast server mode (live fuzzing)
   -dtr, -dast-report                  write dast scan report to file
   -dtst, -dast-server-token string    dast server token (optional)
   -dtsa, -dast-server-address string  dast server address (default "localhost:9055")
   -dfp, -display-fuzz-points          display fuzz points in the output for debugging
   -fuzz-param-frequency int           frequency of uninteresting parameters for fuzzing before skipping (default 10)
   -fa, -fuzz-aggression string        fuzzing aggression level controls payload count for fuzz (low, medium, high) (default "low")
   -cs, -fuzz-scope string[]           in scope url regex to be followed by fuzzer
   -cos, -fuzz-out-scope string[]      out of scope url regex to be excluded by fuzzer

UNCOVER:
   -uc, -uncover                  enable uncover engine
   -uq, -uncover-query string[]   uncover search query
   -ue, -uncover-engine string[]  uncover search engine (shodan,censys,fofa,shodan-idb,quake,hunter,zoomeye,netlas,criminalip,publicwww,hunterhow,google,odin,binaryedge,onyphe,driftnet,greynoise) (default shodan)
   -uf, -uncover-field string     uncover fields to return (ip,port,host) (default "ip:port")
   -ul, -uncover-limit int        uncover results to return (default 100)
   -ur, -uncover-ratelimit int    override ratelimit of engines with unknown ratelimit (default 60 req/min) (default 60)

RATE-LIMIT:
   -rl, -rate-limit int                     maximum number of requests to send per second (default 150)
   -rld, -rate-limit-duration value         maximum number of requests to send per second (default 1s)
   -rlm, -rate-limit-minute int             maximum number of requests to send per minute (DEPRECATED)
   -bs, -bulk-size int                      maximum number of hosts to be analyzed in parallel per template (default 25)
   -c, -concurrency int                     maximum number of templates to be executed in parallel (default 25)
   -hbs, -headless-bulk-size int            maximum number of headless hosts to be analyzed in parallel per template (default 10)
   -headc, -headless-concurrency int        maximum number of headless templates to be executed in parallel (default 10)
   -jsc, -js-concurrency int                maximum number of javascript runtimes to be executed in parallel (default 120)
   -pc, -payload-concurrency int            max payload concurrency for each template (default 25)
   -prc, -probe-concurrency int             http probe concurrency with httpx (default 50)
   -tlc, -template-loading-concurrency int  maximum number of concurrent template loading operations (default 50)

OPTIMIZATIONS:
   -timeout int                     time to wait in seconds before timeout (default 10)
   -retries int                     number of times to retry a failed request (default 1)
   -ldp, -leave-default-ports       leave default HTTP/HTTPS ports (eg. host:80,host:443)
   -mhe, -max-host-error int        max errors for a host before skipping from scan (default 30)
   -te, -track-error string[]       adds given error to max-host-error watchlist (standard, file)
   -nmhe, -no-mhe                   disable skipping host from scan based on errors
   -project                         use a project folder to avoid sending same request multiple times
   -project-path string             set a specific project path (default "/tmp")
   -spm, -stop-at-first-match       stop processing HTTP requests after the first match (may break template/workflow logic)
   -stream                          stream mode - start elaborating without sorting the input
   -ss, -scan-strategy value        strategy to use while scanning(auto/host-spray/template-spray) (default auto)
   -irt, -input-read-timeout value  timeout on input read (default 3m0s)
   -nh, -no-httpx                   disable httpx probing for non-url input
   -no-stdin                        disable stdin processing

HEADLESS:
   -headless                        enable templates that require headless browser support (root user on Linux will disable sandbox)
   -page-timeout int                seconds to wait for each page in headless mode (default 20)
   -sb, -show-browser               show the browser on the screen when running templates with headless mode
   -ho, -headless-options string[]  start headless chrome with additional options
   -sc, -system-chrome              use local installed Chrome browser instead of nuclei installed
   -cdpe, -cdp-endpoint string      use remote browser via Chrome DevTools Protocol (CDP) endpoint
   -lha, -list-headless-action      list available headless actions

DEBUG:
   -debug                     show all requests and responses
   -dreq, -debug-req          show all sent requests
   -dresp, -debug-resp        show all received responses
   -p, -proxy string[]        list of http/socks5 proxy to use (comma separated or file input)
   -pi, -proxy-internal       proxy all internal requests
   -ldf, -list-dsl-function   list all supported DSL function signatures
   -tlog, -trace-log string   file to write sent requests trace log
   -elog, -error-log string   file to write sent requests error log
   -version                   show nuclei version
   -hm, -hang-monitor         enable nuclei hang monitoring
   -v, -verbose               show verbose output
   -profile-mem string        generate memory (heap) profile & trace files
   -vv                        display templates loaded for scan
   -svd, -show-var-dump       show variables dump for debugging
   -vdl, -var-dump-limit int  limit the number of characters displayed in var dump (default 255)
   -ep, -enable-pprof         enable pprof debugging server
   -tv, -templates-version    shows the version of the installed nuclei-templates
   -hc, -health-check         run diagnostic check up

UPDATE:
   -ut, -update-templates            update nuclei-templates to latest released version
   -ud, -update-template-dir string  custom directory to install / update nuclei-templates
   -duc, -disable-update-check       disable automatic nuclei/templates update check

HONEYPOT:
   -hpd, -honeypot-detect         detect potential honeypot hosts based on match concentration
   -hpt, -honeypot-threshold int  number of distinct template IDs required to flag a honeypot host (default 15)
   -shp, -suppress-honeypot       suppress output for flagged honeypot hosts

STATISTICS:
   -stats                    display statistics about the running scan
   -sj, -stats-json          display statistics in JSONL(ines) format
   -si, -stats-interval int  number of seconds to wait between showing a statistics update (default 5)
   -mp, -metrics-port int    port to expose nuclei metrics on (default 9092)
   -hps, -http-stats         enable http status capturing (experimental)

CLOUD:
   -auth                           configure projectdiscovery cloud (pdcp) api key (default true)
   -tid, -team-id string           upload scan results to given team id (optional) (default "none")
   -cup, -cloud-upload             upload scan results to pdcp dashboard [DEPRECATED use -dashboard]
   -sid, -scan-id string           upload scan results to existing scan id (optional)
   -sname, -scan-name string       scan name to set (optional)
   -pd, -dashboard                 upload / view nuclei results in projectdiscovery cloud (pdcp) UI dashboard
   -pdu, -dashboard-upload string  upload / view nuclei results file (jsonl) in projectdiscovery cloud (pdcp) UI dashboard

AUTHENTICATION:
   -sf, -secret-file string[]  path to config file containing secrets for nuclei authenticated scan
   -ps, -prefetch-secrets      prefetch secrets from the secrets file

EXAMPLES:
Run nuclei on single host:
	$ nuclei -target example.com

Run nuclei with specific template directories:
	$ nuclei -target example.com -t http/cves/ -t ssl

Run nuclei against a list of hosts:
	$ nuclei -list hosts.txt

Run nuclei with a JSON output:
	$ nuclei -target example.com -json-export output.json

Run nuclei with sorted Markdown outputs (with environment variables):
	$ MARKDOWN_EXPORT_SORT_MODE=template nuclei -target example.com -markdown-export nuclei_report/

Additional documentation is available at: https://docs.nuclei.sh/getting-started/running
```

Updated on: 2026-May-25

### odat

Source: https://www.kali.org/tools/odat/

#### odat

Oracle Database Attacking Tool This package contains the ODAT (Oracle Database Attacking Tool), an open source
penetration testing tool that tests the security of Oracle Databases remotely.
Usage examples of ODAT:
- You have an Oracle database listening remotely and want to find valid SIDs
and credentials in order to connect to the database
- You have a valid Oracle account on a database and want to escalate your
privileges to become DBA or SYSDBA
- You have a Oracle account and you want to execute system commands (e.g.
reverse shell) in order to move forward on the operating system hosting
the database
Installed size: 511 KB How to install: sudo apt install odat
- oracle-instantclient-basic
- oracle-instantclient-devel
- python3
- python3-argcomplete
- python3-colorlog
- python3-cx-oracle
- python3-libnmap
- python3-passlib
- python3-pyasyncore
- python3-pycryptodome
- python3-scapy
- python3-termcolor

##### odat

```
root@kali:~# odat -h
usage: odat.py [-h] [--version]
               {all,tnscmd,tnspoison,sidguesser,snguesser,passwordguesser,utlhttp,httpuritype,utltcp,ctxsys,externaltable,dbmsxslprocessor,dbmsadvisor,utlfile,dbmsscheduler,java,passwordstealer,oradbg,dbmslob,stealremotepwds,userlikepwd,smb,privesc,cve,search,unwrapper,clean} ...

            _  __   _  ___ 
           / \|  \ / \|_ _|
          ( o ) o ) o || | 
           \_/|__/|_n_||_| 
-------------------------------------------
  _        __           _           ___ 
 / \      |  \         / \         |_ _|
( o )       o )         o |         | | 
 \_/racle |__/atabase |_n_|ttacking |_|ool 
-------------------------------------------

By Quentin Hardy (
[email protected]
or
[email protected]
)

positional arguments:
  {all,tnscmd,tnspoison,sidguesser,snguesser,passwordguesser,utlhttp,httpuritype,utltcp,ctxsys,externaltable,dbmsxslprocessor,dbmsadvisor,utlfile,dbmsscheduler,java,passwordstealer,oradbg,dbmslob,stealremotepwds,userlikepwd,smb,privesc,cve,search,unwrapper,clean}
                      
                      Choose a main command
    all               to run all modules in order to know what it is possible to do
    tnscmd            to communicate with the TNS listener
    tnspoison         to exploit TNS poisoning attack (SID required)
    sidguesser        to know valid SIDs
    snguesser         to know valid Service Name(s)
    passwordguesser   to know valid credentials
    utlhttp           to send HTTP requests or to scan ports
    httpuritype       to send HTTP requests or to scan ports
    utltcp            to scan ports
    ctxsys            to read files
    externaltable     to read files or to execute system commands/scripts
    dbmsxslprocessor  to upload files
    dbmsadvisor       to upload files
    utlfile           to download/upload/delete files
    dbmsscheduler     to execute system commands without a standard output
    java              to execute system commands
    passwordstealer   to get hashed Oracle passwords
    oradbg            to execute a bin or script
    dbmslob           to download files
    stealremotepwds   to steal hashed passwords thanks an authentication sniffing (CVE-2012-3137)
    userlikepwd       to try each Oracle username stored in the DB like the corresponding pwd
    smb               to capture the SMB authentication
    privesc           to gain elevated access
    cve               to exploit a CVE
    search            to search in databases, tables and columns
    unwrapper         to unwrap PL/SQL source code (no for 9i version)
    clean             clean traces and logs

options:
  -h, --help          show this help message and exit
  --version           show program's version number and exit
```

Updated on: 2025-Dec-09

### onesixtyone

Source: https://www.kali.org/tools/onesixtyone/

#### onesixtyone

Fast and simple SNMP scanner onesixtyone is a simple SNMP scanner which sends SNMP requests for the
sysDescr value asynchronously with user-adjustable sending times and
then logs the responses which gives the description of the software
running on the device.
Running onesixtyone on a class B network (switched 100Mbs with 1Gbs
backbone) with -w 10 gives a performance of 3 seconds per class C, with
no dropped packets, and all 65536 IP addresses were scanned in less than
13 minutes.
Installed size: 177 KB How to install: sudo apt install onesixtyone
- libc6

##### onesixtyone

Fast and simple SNMP scanner

```
root@kali:~# onesixtyone -h
onesixtyone 0.3.3 [options] <host> <community>
  -c <communityfile> file with community names to try
  -i <inputfile>     file with target hosts
  -o <outputfile>    output log
  -p                 specify an alternate destination SNMP port
  -d                 debug mode, use twice for more information

  -s                 short mode, only print IP addresses

  -w n               wait n milliseconds (1/1000 of a second) between sending packets (default 10)
  -q                 quiet mode, do not print log to stdout, use with -o
host is either an IPv4 address or an IPv4 address and a netmask
default community names are: public private

Max number of hosts : 		65536
Max community length: 		32
Max number of communities: 	16384

examples: onesixtyone 192.168.4.0/24 public
          onesixtyone -c dict.txt -i hosts -o my.log -w 100
```

#### Learn more with OffSec

Want to learn more about onesixtyone? get access to in-depth training and hands-on labs:
- PEN-200: 6.4.6. Information Gathering: SNMP Enumeration
PEN-200 course
Updated on: 2025-Dec-09

### openssl

Source: https://www.kali.org/tools/openssl/

#### libcrypto3-udeb

#### libssl-dev

Secure Sockets Layer toolkit - development files This package is part of the OpenSSL project’s implementation of the SSL
and TLS cryptographic protocols for secure communication over the
Internet.
It contains development libraries, header files, and manpages for libssl
and libcrypto.
Installed size: 15.88 MB How to install: sudo apt install libssl-dev
- libssl3t64

#### libssl-doc

Secure Sockets Layer toolkit - development documentation This package is part of the OpenSSL project’s implementation of the SSL
and TLS cryptographic protocols for secure communication over the
Internet.
It contains manpages and demo files for libssl and libcrypto.
Installed size: 8.03 MB How to install: sudo apt install libssl-doc

#### libssl3-udeb

#### libssl3t64

Secure Sockets Layer toolkit - shared libraries This package is part of the OpenSSL project’s implementation of the SSL
and TLS cryptographic protocols for secure communication over the
Internet.
It provides the libssl and libcrypto shared libraries.
Installed size: 7.87 MB How to install: sudo apt install libssl3t64
- libc6
- libzstd1
- openssl-provider-legacy
- zlib1g

#### openssl

Secure Sockets Layer toolkit - cryptographic utility This package is part of the OpenSSL project’s implementation of the SSL
and TLS cryptographic protocols for secure communication over the
Internet.
It contains the general-purpose command line binary /usr/bin/openssl,
useful for cryptographic operations such as:
- creating RSA, DH, and DSA key parameters;
- creating X.509 certificates, CSRs, and CRLs;
- calculating message digests;
- encrypting and decrypting with ciphers;
- testing SSL/TLS clients and servers;
- handling S/MIME signed or encrypted mail.
Installed size: 2.46 MB How to install: sudo apt install openssl
- libc6
- libssl3t64

##### openssl

OpenSSL command line program

```
root@kali:~# openssl -h
help:

Standard commands
asn1parse         ca                ciphers           cmp               
cms               configutl         crl               crl2pkcs7         
dgst              dhparam           dsa               dsaparam          
ec                ecparam           enc               engine            
errstr            fipsinstall       gendsa            genpkey           
genrsa            help              info              kdf               
list              mac               nseq              ocsp              
passwd            pkcs12            pkcs7             pkcs8             
pkey              pkeyparam         pkeyutl           prime             
rand              rehash            req               rsa               
rsautl            s_client          s_server          s_time            
sess_id           skeyutl           smime             speed             
spkac             srp               storeutl          ts                
verify            version           x509              

Message Digest commands (see the `dgst' command for more details)
blake2b512        blake2s256        md4               md5               
rmd160            sha1              sha224            sha256            
sha3-224          sha3-256          sha3-384          sha3-512          
sha384            sha512            sha512-224        sha512-256        
shake128          shake256          sm3               

Cipher commands (see the `enc' command for more details)
aes-128-cbc       aes-128-ecb       aes-192-cbc       aes-192-ecb       
aes-256-cbc       aes-256-ecb       aria-128-cbc      aria-128-cfb      
aria-128-cfb1     aria-128-cfb8     aria-128-ctr      aria-128-ecb      
aria-128-ofb      aria-192-cbc      aria-192-cfb      aria-192-cfb1     
aria-192-cfb8     aria-192-ctr      aria-192-ecb      aria-192-ofb      
aria-256-cbc      aria-256-cfb      aria-256-cfb1     aria-256-cfb8     
aria-256-ctr      aria-256-ecb      aria-256-ofb      base64            
bf                bf-cbc            bf-cfb            bf-ecb            
bf-ofb            camellia-128-cbc  camellia-128-ecb  camellia-192-cbc  
camellia-192-ecb  camellia-256-cbc  camellia-256-ecb  cast              
cast-cbc          cast5-cbc         cast5-cfb         cast5-ecb         
cast5-ofb         des               des-cbc           des-cfb           
des-ecb           des-ede           des-ede-cbc       des-ede-cfb       
des-ede-ofb       des-ede3          des-ede3-cbc      des-ede3-cfb      
des-ede3-ofb      des-ofb           des3              desx              
rc2               rc2-40-cbc        rc2-64-cbc        rc2-cbc           
rc2-cfb           rc2-ecb           rc2-ofb           rc4               
rc4-40            seed              seed-cbc          seed-cfb          
seed-ecb          seed-ofb          sm4-cbc           sm4-cfb           
sm4-ctr           sm4-ecb           sm4-ofb           zlib              
zstd
```

#### openssl-provider-fips

Secure Sockets Layer toolkit - cryptographic utility This package is part of the OpenSSL project’s implementation of the SSL
and TLS cryptographic protocols for secure communication over the
Internet.
This package contains the FIPS provider. The OpenSSL FIPS provider is a
special provider that conforms to the Federal Information Processing Standards
(FIPS) specified in FIPS 140-2. This ‘module’ contains an approved set of
cryptographic algorithms that is validated by an accredited testing
laboratory.
For details see OSSL_PROVIDER-fips and fips_module man page.
Installed size: 3.12 MB How to install: sudo apt install openssl-provider-fips
- libc6

#### openssl-provider-legacy

Secure Sockets Layer toolkit - cryptographic utility This package is part of the OpenSSL project’s implementation of the SSL
and TLS cryptographic protocols for secure communication over the
Internet.
This package contains the legacy provider. The OpenSSL legacy provider
supplies OpenSSL implementations of algorithms that have been deemed legacy.
Such algorithms have commonly fallen out of use, have been deemed insecure by
the cryptography community, or something similar.
For details see OSSL_PROVIDER-legacy man page.
Installed size: 424 KB How to install: sudo apt install openssl-provider-legacy
- libc6
- libssl3t64

#### Learn more with OffSec

Want to learn more about openssl? get access to in-depth training and hands-on labs:
- Network Penetration Testing Essentials: 16.7. Cryptography: Asymmetric Encryption
- Cryptography: 7.4. Asymmetric Authentication with SSH
- Introduction to Secure Software Development: 11. Cryptography: 11.7.6. SSL and HTTPS
- Secure Software Development Essentials: 6. Cryptography: 6.7.6. SSL and HTTPS
Updated on: 2026-May-25

### rdesktop

Source: https://www.kali.org/tools/rdesktop/

#### rdesktop

RDP client for Windows NT/2000 Terminal Server and Windows Servers rdesktop is an open source client for Windows NT/2000 Terminal Server and
Windows Server 2003/2008. Capable of natively speaking its Remote Desktop
Protocol (RDP) in order to present the user’s Windows desktop. Unlike Citrix
ICA, no server extensions are required.
Rdesktop is in need of a new upstream maintainter. Please see the home page
for more details.
Installed size: 692 KB How to install: sudo apt install rdesktop
- libasound2t64
- libc6
- libgmp10
- libgnutls30t64
- libgssapi-krb5-2
- libhogweed6t64
- libnettle8t64
- libpcsclite1
- libtasn1-6
- libx11-6
- libxcursor1
- libxrandr2

##### rdesktop

Remote Desktop Protocol client

```
root@kali:~# rdesktop --help
rdesktop: invalid option -- '-'
rdesktop: A Remote Desktop Protocol client.
Version 1.9.0. Copyright (C) 1999-2016 Matthew Chapman et al.
See http://www.rdesktop.org/ for more information.

Usage: rdesktop [options] server[:port]
   -u: user name
   -d: domain
   -s: shell / seamless application to start remotely
   -c: working directory
   -p: password (- to prompt)
   -n: client hostname
   -k: keyboard layout on server (en-us, de, sv, etc.)
   -g: desktop geometry (WxH[@DPI][+X[+Y]])
   -i: enables smartcard authentication, password is used as pin
   -f: full-screen mode
   -b: force bitmap updates
   -L: local codepage
   -A: path to SeamlessRDP shell, this enables SeamlessRDP mode
   -V: tls version (1.0, 1.1, 1.2, defaults to negotiation)
   -B: use BackingStore of X-server (if available)
   -e: disable encryption (French TS)
   -E: disable encryption from client to server
   -m: do not send motion events
   -M: use local mouse cursor
   -C: use private colour map
   -D: hide window manager decorations
   -K: keep window manager key bindings
   -S: caption button size (single application mode)
   -T: window title
   -t: disable use of remote ctrl
   -N: enable numlock synchronization
   -X: embed into another window with a given id.
   -a: connection colour depth
   -z: enable rdp compression
   -x: RDP5 experience (m[odem 28.8], b[roadband], l[an] or hex nr.)
   -P: use persistent bitmap caching
   -r: enable specified device redirection (this flag can be repeated)
         '-r comport:COM1=/dev/ttyS0': enable serial redirection of /dev/ttyS0 to COM1
             or      COM1=/dev/ttyS0,COM2=/dev/ttyS1
         '-r disk:floppy=/mnt/floppy': enable redirection of /mnt/floppy to 'floppy' share
             or   'floppy=/mnt/floppy,cdrom=/mnt/cdrom'
         '-r clientname=<client name>': Set the client name displayed
             for redirected disks
         '-r lptport:LPT1=/dev/lp0': enable parallel redirection of /dev/lp0 to LPT1
             or      LPT1=/dev/lp0,LPT2=/dev/lp1
         '-r printer:mydeskjet': enable printer redirection
             or      mydeskjet="HP LaserJet IIIP" to enter server driver as well
         '-r sound:[local[:driver[:device]]|off|remote]': enable sound redirection
                     remote would leave sound on server
                     available drivers for 'local':
                     alsa:	ALSA output driver, default device: default
         '-r clipboard:[off|PRIMARYCLIPBOARD|CLIPBOARD]': enable clipboard
                      redirection.
                      'PRIMARYCLIPBOARD' looks at both PRIMARY and CLIPBOARD
                      when sending data to server.
                      'CLIPBOARD' looks at only CLIPBOARD.
         '-r scard[:"Scard Name"="Alias Name[;Vendor Name]"[,...]]
          example: -r scard:"eToken PRO 00 00"="AKS ifdh 0"
                   "eToken PRO 00 00" -> Device in GNU/Linux and UNIX environment
                   "AKS ifdh 0"       -> Device shown in Windows environment 
          example: -r scard:"eToken PRO 00 00"="AKS ifdh 0;AKS"
                   "eToken PRO 00 00" -> Device in GNU/Linux and UNIX environment
                   "AKS ifdh 0"       -> Device shown in Microsoft Windows environment 
                   "AKS"              -> Device vendor name                 
   -0: attach to console
   -4: use RDP version 4
   -5: use RDP version 5 (default)
   -o: name=value: Adds an additional option to rdesktop.
           sc-csp-name        Specifies the Crypto Service Provider name which
                              is used to authenticate the user by smartcard
           sc-container-name  Specifies the container name, this is usually the username
           sc-reader-name     Smartcard reader name to use
           sc-card-name       Specifies the card name of the smartcard to use
   -v: enable verbose logging
```

Updated on: 2026-Jun-17

### sipvicious

Source: https://www.kali.org/tools/sipvicious/

#### Tool Documentation:



#### Tool Documentation:

#### svmap Usage Example

Scan the given network range ( 192.168.1.0/24 ) and display verbose output ( -v ):

```
root@kali:~# svmap 192.168.1.0/24 -v
INFO:DrinkOrSip:trying to get self ip .. might take a while
INFO:root:start your engines
INFO:DrinkOrSip:Looks like we received a SIP request from 192.168.1.202:5060
INFO:DrinkOrSip:Looks like we received a SIP request from 192.168.1.202:5060
INFO:DrinkOrSip:Looks like we received a SIP request from 192.168.1.202:5060
```


#### sipvicious

Tools to audit SIP based VoIP systems SIPVicious suite is a set of tools that can be used
to audit SIP based VoIP systems. This suite has five
tools: svmap, svwar, svcrack, svreport, svcrash.
svmap is a sip scanner. When launched against ranges
of ip address space, it will identify any SIP servers
which it finds on the way.
svwar identifies working extension lines on a PBX.
Also tells you if extension line requires authentication or not.
svcrack is a password cracker making use of digest authentication.
It is able to crack passwords on both registrar servers and proxy
servers.
svreport is able to manage sessions created by the rest of the tools
and export to pdf, xml, csv and plain text.
svcrash responds to svwar and svcrack SIP messages with a message
that causes old versions to crash.
Installed size: 197 KB How to install: sudo apt install sipvicious
- python3
- python3-scapy

##### svcrack

Online password guessing tool for SIP devices

```
root@kali:~# svcrack -h
Usage: svcrack -u username [options] target
examples:
svcrack -u100 -d dictionary.txt udp://10.0.0.1:5080
svcrack -u100 -r1-9999 -z4 10.0.0.1

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  Destination port of the SIP device - eg -p 5060
  -v, --verbose         Increase verbosity
  -q, --quiet           Quiet mode
  -P PORT, --localport=PORT
                        Source port for our packets
  -x IP, --externalip=IP
                        IP Address to use as the external ip. Specify this if
                        you have multiple interfaces or if you are behind NAT
  -b BINDINGIP, --bindingip=BINDINGIP
                        By default we bind to all interfaces. This option
                        overrides that and binds to the specified ip address
  -t SELECTTIME, --timeout=SELECTTIME
                        This option allows you to trottle the speed at which
                        packets are sent. Change this if you're losing
                        packets. For example try 0.5.
  -R, --reportback      Send the author an exception traceback. Currently
                        sends the command line parameters and the traceback
  -A, --autogetip       Automatically get the current IP address. This is
                        useful when you are not getting any responses back due
                        to SIPVicious not resolving your local IP.
  -s NAME, --save=NAME  save the session. Has the benefit of allowing you to
                        resume a previous scan and allows you to export scans
  --resume=NAME         resume a previous scan
  -c, --enablecompact   enable compact mode. Makes packets smaller but
                        possibly less compatible
  -u USERNAME, --username=USERNAME
                        username to try crack
  -d DICTIONARY, --dictionary=DICTIONARY
                        specify a dictionary file with passwords or - for
                        stdin
  -r RANGE, --range=RANGE
                        specify a range of numbers. example:
                        100-200,300-310,400
  -e EXTENSION, --extension=EXTENSION
                        Extension to crack. Only specify this when the
                        extension is different from the username.
  -z PADDING, --zeropadding=PADDING
                        the number of zeros used to padd the password. the
                        options "-r 1-9999 -z 4"would give 0001 0002 0003 ...
                        9999
  -n, --reusenonce      Reuse nonce. Some SIP devices don't mind you reusing
                        the nonce (making them vulnerable to replay attacks).
                        Speeds up the cracking.
  -T TEMPLATE, --template=TEMPLATE
                        A format string which allows us to specify a template
                        for the extensionsexample svwar.py -e 1-999
                        --template="123%#04i999" would scan between 1230001999
                        to 1230999999"
  --maximumtime=MAXIMUMTIME
                        Maximum time in seconds to keep sending requests
                        without receiving a response back
  -D, --enabledefaults  Scan for default / typical passwords such
                        as1000,2000,3000 ... 1100, etc. This option is off by
                        default.Use --enabledefaults to enable this
                        functionality
  --domain=DOMAIN       force a specific domain name for the SIP message, eg.
                        example.org
  --requesturi=REQUESTURI
                        force the first line URI to a specific value; e.g.
                        sip:
[email protected]
-6                    Scan an IPv6 address
  -m METHOD, --method=METHOD
                        Specify a SIP method to use
```

##### svcrash

Stop unauthorized scans from svcrack/svwar tool

```
root@kali:~# svcrash -h
Usage: svcrash [options]

Options:
  --version        show program's version number and exit
  -h, --help       show this help message and exit
  --auto           Automatically send responses to attacks
  --astlog=ASTLOG  Path for the asterisk full logfile
  -d IPADDR        specify attacker's ip address
  -p PORT          specify attacker's port
  -b               bruteforce the attacker's port
```

##### svmap

Scanner that searches for SIP devices on a given network

```
root@kali:~# svmap -h
Usage: svmap [options] host1 host2 hostrange
Scans for SIP devices on a given network

examples:

svmap 10.0.0.1-10.0.0.255 172.16.131.1 sipvicious.org/22 10.0.1.1/241.1.1.1-20 1.1.2-20.* 4.1.*.*

svmap -s session1 --randomize 10.0.0.1/8

svmap --resume session1 -v

svmap -p5060-5062 10.0.0.3-20 -m INVITE

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  Destination port or port ranges of the SIP device - eg
                        -p5060,5061,8000-8100
  -v, --verbose         Increase verbosity
  -q, --quiet           Quiet mode
  -P PORT, --localport=PORT
                        Source port for our packets
  -x IP, --externalip=IP
                        IP Address to use as the external ip. Specify this if
                        you have multiple interfaces or if you are behind NAT
  -b BINDINGIP, --bindingip=BINDINGIP
                        By default we bind to all interfaces. This option
                        overrides that and binds to the specified ip address
  -t SELECTTIME, --timeout=SELECTTIME
                        This option allows you to trottle the speed at which
                        packets are sent. Change this if you're losing
                        packets. For example try 0.5.
  -R, --reportback      Send the author an exception traceback. Currently
                        sends the command line parameters and the traceback
  -A, --autogetip       Automatically get the current IP address. This is
                        useful when you are not getting any responses back due
                        to SIPVicious not resolving your local IP.
  -s NAME, --save=NAME  save the session. Has the benefit of allowing you to
                        resume a previous scan and allows you to export scans
  --resume=NAME         resume a previous scan
  -c, --enablecompact   enable compact mode. Makes packets smaller but
                        possibly less compatible
  --randomscan          Scan random IP addresses
  -i scan1, --input=scan1
                        Scan IPs which were found in a previous scan. Pass the
                        session name as the argument
  -I scan1, --inputtext=scan1
                        Scan IPs from a text file - use the same syntax as
                        command line but with new lines instead of commas.
                        Pass the file name as the argument
  -m METHOD, --method=METHOD
                        Specify the request method - by default this is
                        OPTIONS.
  -d, --debug           Print SIP messages received
  --first=FIRST         Only send the first given number of messages (i.e.
                        usually used to scan only X IPs)
  -e EXTENSION, --extension=EXTENSION
                        Specify an extension - by default this is not set
  --randomize           Randomize scanning instead of scanning consecutive ip
                        addresses
  --srv                 Scan the SRV records for SIP on the destination domain
                        name.The targets have to be domain names - example.org
                        domain1.com
  --fromname=FROMNAME   specify a name for the from header
  -6, --ipv6            scan an IPv6 address
```

##### svreport

Report engine manage sessions from previous scans with SIPVicious

```
root@kali:~# svreport -h
Usage: svreport [command] [options]

Supported commands:

                - list:	lists all scans

                - export:	exports the given scan to a given format

                - delete:	deletes the scan

                - stats:	print out some statistics of interest

                - search:	search for a specific string in the user agent (svmap)

examples:

      svreport.py list

      svreport.py export -f pdf -o scan1.pdf -s scan1

      svreport.py delete -s scan1

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -v, --verbose         Increase verbosity
  -q, --quiet           Quiet mode
  -t SESSIONTYPE, --type=SESSIONTYPE
                        Type of session. This is usually either svmap, svwar
                        or svcrack. If not set I will try to find the best
                        match
  -s SESSION, --session=SESSION
                        Name of the session
  -f FORMAT, --format=FORMAT
                        Format type. Can be stdout, pdf, xml, csv or txt
  -o OUTPUTFILE, --output=OUTPUTFILE
                        Output filename
  -n                    Do not resolve the ip address
  -c, --count           Used togather with 'list' command to count the number
                        of entries
```

##### svwar

Extension line scanner

```
root@kali:~# svwar -h
Usage: svwar [options] target
examples:
svwar -e100-999 udp://10.0.0.1:5080
svwar -d dictionary.txt 10.0.0.2

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -p PORT, --port=PORT  Destination port of the SIP device - eg -p 5060
  -v, --verbose         Increase verbosity
  -q, --quiet           Quiet mode
  -P PORT, --localport=PORT
                        Source port for our packets
  -x IP, --externalip=IP
                        IP Address to use as the external ip. Specify this if
                        you have multiple interfaces or if you are behind NAT
  -b BINDINGIP, --bindingip=BINDINGIP
                        By default we bind to all interfaces. This option
                        overrides that and binds to the specified ip address
  -t SELECTTIME, --timeout=SELECTTIME
                        This option allows you to trottle the speed at which
                        packets are sent. Change this if you're losing
                        packets. For example try 0.5.
  -R, --reportback      Send the author an exception traceback. Currently
                        sends the command line parameters and the traceback
  -A, --autogetip       Automatically get the current IP address. This is
                        useful when you are not getting any responses back due
                        to SIPVicious not resolving your local IP.
  -s NAME, --save=NAME  save the session. Has the benefit of allowing you to
                        resume a previous scan and allows you to export scans
  --resume=NAME         resume a previous scan
  -c, --enablecompact   enable compact mode. Makes packets smaller but
                        possibly less compatible
  -d DICTIONARY, --dictionary=DICTIONARY
                        specify a dictionary file with possible extension
                        names or - for stdin
  -m OPTIONS, --method=OPTIONS
                        specify a request method. The default is REGISTER.
                        Other possible methods are OPTIONS and INVITE
  -e RANGE, --extensions=RANGE
                        specify an extension or extension range  example: -e
                        100-999,1000-1500,9999
  -z PADDING, --zeropadding=PADDING
                        the number of zeros used to padd the username.the
                        options "-e 1-9999 -z 4" would give 0001 0002 0003 ...
                        9999
  --force               Force scan, ignoring initial sanity checks.
  -T TEMPLATE, --template=TEMPLATE
                        A format string which allows us to specify a template
                        for the extensionsexample svwar.py -e 1-999
                        --template="123%#04i999" would scan between 1230001999
                        to 1230999999"
  -D, --enabledefaults  Scan for default / typical extensions such
                        as1000,2000,3000 ... 1100, etc. This option is off by
                        default.Use --enabledefaults to enable this
                        functionality
  --maximumtime=MAXIMUMTIME
                        Maximum time in seconds to keep sending requests
                        without receiving a response back
  --domain=DOMAIN       force a specific domain name for the SIP message, eg.
                        -d example.org
  --debug               Print SIP messages received
  -6                    scan an IPv6 address
```

Updated on: 2026-Mar-13

### smbmap

Source: https://www.kali.org/tools/smbmap/

#### Tool Documentation:



#### Tool Documentation:

#### smbmap Usage Examples

Check for shares on the specified host with the username and password provided:

```
root@kali:~# smbmap -u victim -p s3cr3t -H 192.168.86.61
[+] Finding open SMB ports....
[+] User SMB session establishd on 192.168.86.61...
[+] IP: 192.168.86.61:445   Name: win7-x86.lan
    Disk                                                    Permissions
    ----                                                    -----------
    ADMIN$                                              NO ACCESS
    C$                                                  NO ACCESS
    IPC$                                                NO ACCESS
    Users                                               READ ONLY
```


#### smbmap

Handy SMB enumeration tool SMBMap allows users to enumerate samba share drives across an entire domain.
List share drives, drive permissions, share contents, upload/download
functionality, file name auto-download pattern matching, and even execute
remote commands. This tool was designed with pen testing in mind, and is
intended to simplify searching for potentially sensitive data across large
networks.
Features:
Pass-the-Hash Support
File upload/download/delete
Permission enumeration (writable share, meet Metasploit)
Remote Command Execution
Distrubted file content searching (beta!)
File name matching (with an auto downoad capability)
Host file parser supports IPs, host names, and CIDR
SMB sigining detection
Server version output
Kerberos support! (super beta)
Installed size: 134 KB How to install: sudo apt install smbmap
- python3
- python3-impacket
- python3-pyasn1
- python3-termcolor

##### smbmap

SMB enumeration tool

```
root@kali:~# smbmap -h
usage: smbmap [-h] (-H HOST | --host-file FILE) [-u USERNAME] [-p PASSWORD |
              --prompt] [-k] [--no-pass] [--dc-ip IP or Host] [-s SHARE]
              [-d DOMAIN] [-P PORT] [-v] [--signing] [--admin] [--no-banner]
              [--no-color] [--no-update] [--timeout SCAN_TIMEOUT] [-x COMMAND]
              [--mode CMDMODE] [-L | -r [PATH]] [-g FILE | --csv FILE]
              [--dir-only] [--no-write-check] [-q] [--depth DEPTH]
              [--exclude SHARE [SHARE ...]] [-A PATTERN] [-F PATTERN]
              [--search-path PATH] [--search-timeout TIMEOUT]
              [--download PATH] [--upload SRC DST] [--delete PATH TO FILE]
              [--skip]

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans -
[email protected]
https://github.com/ShawnDEvans/smbmap

options:
  -h, --help            show this help message and exit

Main arguments:
  -H HOST               IP or FQDN
  --host-file FILE      File containing a list of hosts
  -u, --username USERNAME
                        Username, if omitted null session assumed
  -p, --password PASSWORD
                        Password or NTLM hash, format is LMHASH:NTHASH
  --prompt              Prompt for a password
  -s SHARE              Specify a share (default C$), ex 'C$'
  -d DOMAIN             Domain name (default WORKGROUP)
  -P PORT               SMB port (default 445)
  -v, --version         Return the OS version of the remote host
  --signing             Check if host has SMB signing disabled, enabled, or
                        required
  --admin               Just report if the user is an admin
  --no-banner           Removes the banner from the top of the output
  --no-color            Removes the color from output
  --no-update           Removes the "Working on it" message
  --timeout SCAN_TIMEOUT
                        Set port scan socket timeout. Default is .5 seconds

Kerberos settings:
  -k, --kerberos        Use Kerberos authentication
  --no-pass             Use CCache file (export KRB5CCNAME='~/current.ccache')
  --dc-ip IP or Host    IP or FQDN of DC

Command Execution:
  Options for executing commands on the specified host

  -x COMMAND            Execute a command ex. 'ipconfig /all'
  --mode CMDMODE        Set the execution method, wmi or psexec, default wmi

Shard drive Search:
  Options for searching/enumerating the share of the specified host(s)

  -L                    List all drives on the specified host, requires ADMIN
                        rights.
  -r [PATH]             Recursively list dirs and files (no share\path lists
                        the root of ALL shares), ex. 'email/backup'
  -g FILE               Output to a file in a grep friendly format, used with
                        -r (otherwise it outputs nothing), ex -g grep_out.txt
  --csv FILE            Output to a CSV file, ex --csv shares.csv
  --dir-only            List only directories, ommit files.
  --no-write-check      Skip check to see if drive grants WRITE access.
  -q                    Quiet verbose output. Only shows shares you have READ
                        or WRITE on, and suppresses file listing when
                        performing a search (-A).
  --depth DEPTH         Traverse a directory tree to a specific depth. Default
                        is 1 (root node).
  --exclude SHARE [SHARE ...]
                        Exclude share(s) from searching and listing, ex.
                        --exclude ADMIN$ C$'
  -A PATTERN            Define a file name pattern (regex) that auto downloads
                        a file on a match (requires -r), not case sensitive,
                        ex '(web|global).(asax|config)'

File Content Search:
  Options for searching the content of files (must run as root), kind of experimental

  -F PATTERN            File content search, -F '[Pp]assword' (requires admin
                        access to execute commands, and PowerShell on victim
                        host)
  --search-path PATH    Specify drive/path to search (used with -F, default
                        C:\Users), ex 'D:\HR\'
  --search-timeout TIMEOUT
                        Specifcy a timeout (in seconds) before the file search
                        job gets killed. Default is 300 seconds.

Filesystem interaction:
  Options for interacting with the specified host's filesystem

  --download PATH       Download a file from the remote system,
                        ex.'C$\temp\passwords.txt'
  --upload SRC DST      Upload a file to the remote system ex.
                        '/tmp/payload.exe C$\temp\payload.exe'
  --delete PATH TO FILE
                        Delete a remote file, ex. 'C$\temp\msf.exe'
  --skip                Skip delete file confirmation prompt

Examples:

$ smbmap -u jsmith -p password1 -d workgroup -H 192.168.0.1
$ smbmap -u jsmith -p 'aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d' -H 172.16.0.20
$ smbmap -u 'apadmin' -p 'asdf1234!' -d ACME -Hh 10.1.3.30 -x 'net group "Domain Admins" /domain'
```

Updated on: 2025-Dec-09

### smtp-user-enum

Source: https://www.kali.org/tools/smtp-user-enum/

#### Tool Documentation:



#### Tool Documentation:

#### smtp-user-enum Usage Example

Use the VRFY method ( -M VRFY ) to search for the specified user ( -u root ) on the target server ( -t 192.168.1.25 ):

```
root@kali:~# smtp-user-enum -M VRFY -u root -t 192.168.1.25
Starting smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Mode ..................... VRFY
Worker Processes ......... 5
Target count ............. 1
Username count ........... 1
Target TCP port .......... 25
Query timeout ............ 5 secs
Target domain ............

######## Scan started at Tue May 13 16:06:28 2014 #########
192.168.1.25: root exists
######## Scan completed at Tue May 13 16:06:29 2014 #########
1 results.

1 queries in 1 seconds (1.0 queries / sec)
```


#### smtp-user-enum

Username guessing tool for the SMTP service Username guessing tool primarily for use against the
default Solaris SMTP service. Can use either EXPN, VRFY or
RCPT TO.
Installed size: 98 KB How to install: sudo apt install smtp-user-enum
- libio-socket-ip-perl
- libsocket-perl
- perl

##### smtp-user-enum

```
root@kali:~# smtp-user-enum -h
smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )

Usage: smtp-user-enum [options] ( -u username | -U file-of-usernames ) ( -t host | -T file-of-targets )

options are:
        -m n     Maximum number of processes (default: 5)
	-M mode  Method to use for username guessing EXPN, VRFY or RCPT (default: VRFY)
	-u user  Check if user exists on remote system
	-f addr  MAIL FROM email address.  Used only in "RCPT TO" mode (default:
[email protected]
)
        -D dom   Domain to append to supplied user list to make email addresses (Default: none)
                 Use this option when you want to guess valid email addresses instead of just usernames
                 e.g. "-D example.com" would guess
[email protected]
,
[email protected]
, etc.  Instead of 
                      simply the usernames foo and bar.
	-U file  File of usernames to check via smtp service
	-t host  Server host running smtp service
	-T file  File of hostnames running the smtp service
	-p port  TCP port on which smtp service runs (default: 25)
	-d       Debugging output
	-w n     Wait a maximum of n seconds for reply (default: 5)
	-v       Verbose
	-h       This help message

Also see smtp-user-enum-user-docs.pdf from the smtp-user-enum tar ball.

Examples:

$ smtp-user-enum -M VRFY -U users.txt -t 10.0.0.1
$ smtp-user-enum -M EXPN -u admin1 -t 10.0.0.1
$ smtp-user-enum -M RCPT -U users.txt -T mail-server-ips.txt
$ smtp-user-enum -M EXPN -D example.com -U users.txt -t 10.0.0.1
```

Updated on: 2025-Dec-09

### sqlmap

Source: https://www.kali.org/tools/sqlmap/

#### Tool Documentation:



#### Tool Documentation:

#### sqlmap Usage Example

Attack the given URL ( -u “http://192.168.1.250/?p=1&forumaction=search” ) and extract the database names ( –dbs ):

```
root@kali:~# sqlmap -u "http://192.168.1.250/?p=1&forumaction=search" --dbs
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.2.11#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting at 13:37:00

[13:37:00] [INFO] testing connection to the target URL
```


#### sqlmap

Automatic SQL injection tool sqlmap goal is to detect and take advantage of SQL injection
vulnerabilities in web applications. Once it detects one or more SQL
injections on the target host, the user can choose among a variety of
options to perform an extensive back-end database management system
fingerprint, retrieve DBMS session user and database, enumerate users,
password hashes, privileges, databases, dump entire or user’s specific
DBMS tables/columns, run his own SQL statement, read specific files on
the file system and more.
Installed size: 10.36 MB How to install: sudo apt install sqlmap
- python3
- python3-magic

##### sqlmap

Automatic SQL injection tool

```
root@kali:~# sqlmap -h
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.10.6#stable}
|_ -| . [.]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

Usage: python3 sqlmap [options]

Options:
  -h, --help            Show basic help message and exit
  -hh                   Show advanced help message and exit
  --version             Show program's version number and exit
  -v VERBOSE            Verbosity level: 0-6 (default 1)

  Target:
    At least one of these options has to be provided to define the
    target(s)

    -u URL, --url=URL   Target URL (e.g. "http://www.site.com/vuln.php?id=1")
    -g GOOGLEDORK       Process Google dork results as target URLs

  Request:
    These options can be used to specify how to connect to the target URL

    --data=DATA         Data string to be sent through POST (e.g. "id=1")
    --cookie=COOKIE     HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
    --random-agent      Use randomly selected HTTP User-Agent header value
    --proxy=PROXY       Use a proxy to connect to the target URL
    --tor               Use Tor anonymity network
    --check-tor         Check to see if Tor is used properly

  Injection:
    These options can be used to specify which parameters to test for,
    provide custom injection payloads and optional tampering scripts

    -p TESTPARAMETER    Testable parameter(s)
    --dbms=DBMS         Force back-end DBMS to provided value

  Detection:
    These options can be used to customize the detection phase

    --level=LEVEL       Level of tests to perform (1-5, default 1)
    --risk=RISK         Risk of tests to perform (1-3, default 1)

  Techniques:
    These options can be used to tweak testing of specific SQL injection
    techniques

    --technique=TECH..  SQL injection techniques to use (default "BEUSTQ")

  Enumeration:
    These options can be used to enumerate the back-end database
    management system information, structure and data contained in the
    tables

    -a, --all           Retrieve everything
    -b, --banner        Retrieve DBMS banner
    --current-user      Retrieve DBMS current user
    --current-db        Retrieve DBMS current database
    --passwords         Enumerate DBMS users password hashes
    --dbs               Enumerate DBMS databases
    --tables            Enumerate DBMS database tables
    --columns           Enumerate DBMS database table columns
    --schema            Enumerate DBMS schema
    --dump              Dump DBMS database table entries
    --dump-all          Dump all DBMS databases tables entries
    -D DB               DBMS database to enumerate
    -T TBL              DBMS database table(s) to enumerate
    -C COL              DBMS database table column(s) to enumerate

  Operating system access:
    These options can be used to access the back-end database management
    system underlying operating system

    --os-shell          Prompt for an interactive operating system shell
    --os-pwn            Prompt for an OOB shell, Meterpreter or VNC

  General:
    These options can be used to set some general working parameters

    --batch             Never ask for user input, use the default behavior
    --flush-session     Flush session files for current target

  Miscellaneous:
    These options do not fit into any other category

    --wizard            Simple wizard interface for beginner users

[!] to see full list of options run with '-hh'
```

##### sqlmapapi

Automatic SQL injection tool, api server

```
root@kali:~# sqlmapapi -h
Usage: sqlmapapi [options]

Options:
  -h, --help            show this help message and exit
  -s, --server          Run as a REST-JSON API server
  -c, --client          Run as a REST-JSON API client
  -H HOST, --host=HOST  Host of the REST-JSON API server (default "127.0.0.1")
  -p PORT, --port=PORT  Port of the REST-JSON API server (default 8775)
  --adapter=ADAPTER     Server (bottle) adapter to use (default "wsgiref")
  --database=DATABASE   Set IPC database filepath (optional)
  --username=USERNAME   Basic authentication username (optional)
  --password=PASSWORD   Basic authentication password (optional)
```

#### Learn more with OffSec

Want to learn more about sqlmap? get access to in-depth training and hands-on labs:
- WEB-200: 8.4.1. SQL Injection: SQLMap
- PEN-200: 10.3.2. SQL Injection Attacks: Automating the Attack
WEB-200 course
PEN-200 course
Updated on: 2026-Jun-17

### sslscan

Source: https://www.kali.org/tools/sslscan/

#### sslscan

Tests SSL/TLS enabled services to discover supported cipher suites This tool allow queries SSL/TLS services (such as HTTPS) and reports the
protocol versions, cipher suites, key exchanges, signature algorithms, and
certificates in use. This helps the user understand which parameters are
weak from a security standpoint.
sslscan can also output results into an XML file for easy consumption by
external programs.
Installed size: 178 KB How to install: sudo apt install sslscan
- libc6
- libssl3t64

##### sslscan

Fast SSL/TLS scanner

```
root@kali:~# sslscan -h
                   _
           ___ ___| |___  ___ __ _ _ __
          / __/ __| / __|/ __/ _` | '_ \
          \__ \__ \ \__ \ (_| (_| | | | |
          |___/___/_|___/\___\__,_|_| |_|

		2.1.5
		OpenSSL 3.6.2 7 Apr 2026

Command:
  sslscan [options] [host:port | host]

Options:
  --targets=<file>     A file containing a list of hosts to check.
                       Hosts can  be supplied  with ports (host:port)
  --sni-name=<name>    Hostname for SNI
  --ipv4, -4           Only use IPv4
  --ipv6, -6           Only use IPv6

  --show-certificate   Show full certificate information
  --show-certificates  Show chain full certificates information
  --show-client-cas    Show trusted CAs for TLS client auth
  --no-check-certificate  Don't warn about weak certificate algorithm or keys
  --ocsp               Request OCSP response from server
  --pk=<file>          A file containing the private key or a PKCS#12 file
                       containing a private key/certificate pair
  --pkpass=<password>  The password for the private  key or PKCS#12 file
  --certs=<file>       A file containing PEM/ASN1 formatted client certificates

  --ssl2               Only check if SSLv2 is enabled
  --ssl3               Only check if SSLv3 is enabled
  --tls10              Only check TLSv1.0 ciphers
  --tls11              Only check TLSv1.1 ciphers
  --tls12              Only check TLSv1.2 ciphers
  --tls13              Only check TLSv1.3 ciphers
  --tlsall             Only check TLS ciphers (all versions)
  --show-ciphers       Show supported client ciphers
  --show-cipher-ids    Show cipher ids
  --iana-names         Use IANA/RFC cipher names rather than OpenSSL ones
  --show-times         Show handhake times in milliseconds

  --no-cipher-details  Disable EC curve names and EDH/RSA key lengths output
  --no-ciphersuites    Do not check for supported ciphersuites
  --no-compression     Do not check for TLS compression (CRIME)
  --no-fallback        Do not check for TLS Fallback SCSV
  --no-groups          Do not enumerate key exchange groups
  --no-heartbleed      Do not check for OpenSSL Heartbleed (CVE-2014-0160)
  --no-renegotiation   Do not check for TLS renegotiation
  --show-sigs          Enumerate signature algorithms

  --starttls-ftp       STARTTLS setup for FTP
  --starttls-imap      STARTTLS setup for IMAP
  --starttls-irc       STARTTLS setup for IRC
  --starttls-ldap      STARTTLS setup for LDAP
  --starttls-mysql     STARTTLS setup for MYSQL
  --starttls-pop3      STARTTLS setup for POP3
  --starttls-psql      STARTTLS setup for PostgreSQL
  --starttls-smtp      STARTTLS setup for SMTP
  --starttls-xmpp      STARTTLS setup for XMPP
  --xmpp-server        Use a server-to-server XMPP handshake
  --rdp                Send RDP preamble before starting scan

  --bugs               Enable SSL implementation bug work-arounds
  --no-colour          Disable coloured output
  --sleep=<msec>       Pause between connection request. Default is disabled
  --timeout=<sec>      Set socket timeout. Default is 3s
  --connect-timeout=<sec>  Set connect timeout. Default is 75s
  --verbose            Display verbose output
  --version            Display the program version
  --xml=<file>         Output results to an XML file. Use - for STDOUT.
  --help               Display the help text you are now reading

Example:
  sslscan 127.0.0.1
  sslscan [::1]
```

#### Learn more with OffSec

Want to learn more about sslscan? get access to in-depth training and hands-on labs:
- Web System Administration Foundations: 5. TLS and PKI Essentials: 5.2. TLS Concepts Overview
Updated on: 2026-May-25

### sslyze

Source: https://www.kali.org/tools/sslyze/

#### Tool Documentation:



#### Tool Documentation:

#### sslyze Usage Example

Launch a regular scan type ( –regular ) against the target host ( www.example.com ):

```
root@kali:~# sslyze --regular www.example.com

 REGISTERING AVAILABLE PLUGINS
 -----------------------------

  PluginCompression
  PluginCertInfo
  PluginSessionResumption
  PluginSessionRenegotiation
  PluginOpenSSLCipherSuites

 CHECKING HOST(S) AVAILABILITY
 -----------------------------

   www.example.com:443                 => 93.184.216.119:443

 SCAN RESULTS FOR WWW.EXAMPLE.COM:443 - 93.184.216.119:443
 ---------------------------------------------------------

  * Compression :
        Compression Support:      Disabled

  * Certificate :
      Validation w/ Mozilla's CA Store:  Certificate is Trusted
```


#### sslyze

Fast and full-featured SSL scanner SSLyze is a Python tool that can analyze the SSL configuration
of a server by connecting to it. It is designed to be fast and
comprehensive, and should help organizations and testers
identify misconfigurations affecting their SSL servers.
Installed size: 2.19 MB How to install: sudo apt install sslyze
- libjs-sphinxdoc
- python3
- python3-cryptography
- python3-nassl
- python3-pkg-resources
- python3-pydantic
- python3-tls-parser
- python3-typing-extensions

##### sslyze

```
root@kali:~# sslyze -h
usage: sslyze [-h] [--update_trust_stores] [--cert CERTIFICATE_FILE]
              [--key KEY_FILE] [--keyform KEY_FORMAT] [--pass PASSPHRASE]
              [--json_out JSON_FILE] [--targets_in TARGET_FILE] [--quiet]
              [--slow_connection] [--https_tunnel PROXY_SETTINGS]
              [--starttls PROTOCOL] [--xmpp_to HOSTNAME]
              [--sni SERVER_NAME_INDICATION] [--tlsv1_3] [--http_headers]
              [--fallback] [--robot] [--ems] [--tlsv1_1] [--tlsv1]
              [--compression] [--early_data] [--reneg] [--openssl_ccs]
              [--sslv2] [--heartbleed] [--elliptic_curves] [--certinfo]
              [--certinfo_ca_file CERTINFO_CA_FILE] [--sslv3] [--resum]
              [--resum_attempts RESUM_ATTEMPTS] [--tlsv1_2]
              [--custom_tls_config CUSTOM_TLS_CONFIG]
              [--mozilla_config {modern,intermediate,old,disable}]
              [target ...]

SSLyze version 6.3.1

positional arguments:
  target                The list of servers to scan.

options:
  -h, --help            show this help message and exit
  --custom_tls_config CUSTOM_TLS_CONFIG
                        Path to a JSON file containing a specific TLS
                        configuration to check the server against, following
                        Mozilla's format. Cannot be used with
                        --mozilla_config.
  --mozilla_config {modern,intermediate,old,disable}
                        Shortcut to queue various scan commands needed to
                        check the server's TLS configurations against one of
                        Mozilla's recommended TLS configurations. Set to
                        "intermediate" by default. Use "disable" to disable
                        this check.

Trust stores options:
  --update_trust_stores
                        Update the default trust stores used by SSLyze. The
                        latest stores will be downloaded from https://github.c
                        om/nabla-c0d3/trust_stores_observatory. This option is
                        meant to be used separately, and will silence any
                        other command line option supplied to SSLyze.

Client certificate options:
  --cert CERTIFICATE_FILE
                        Client certificate chain filename. The certificates
                        must be in PEM format and must be sorted starting with
                        the subject's client certificate, followed by
                        intermediate CA certificates if applicable.
  --key KEY_FILE        Client private key filename.
  --keyform KEY_FORMAT  Client private key format. DER or PEM (default).
  --pass PASSPHRASE     Client private key passphrase.

Input and output options:
  --json_out JSON_FILE  Write the scan results as a JSON document to the file
                        JSON_FILE. If JSON_FILE is set to '-', the JSON output
                        will instead be printed to stdout. The resulting JSON
                        file is a serialized version of the ScanResult objects
                        described in SSLyze's Python API: the nodes and
                        attributes will be the same. See https://nabla-
                        c0d3.github.io/sslyze/documentation/available-scan-
                        commands.html for more details.
  --targets_in TARGET_FILE
                        Read the list of targets to scan from the file
                        TARGET_FILE. It should contain one host:port per line.
  --quiet               Do not output anything to stdout; useful when using
                        --json_out.

Connectivity options:
  --slow_connection     Greatly reduce the number of concurrent connections
                        initiated by SSLyze. This will make the scans slower
                        but more reliable if the connection between your host
                        and the server is slow, or if the server cannot handle
                        many concurrent connections. Enable this option if you
                        are getting a lot of timeouts or errors.
  --https_tunnel PROXY_SETTINGS
                        Tunnel all traffic to the target server(s) through an
                        HTTP CONNECT proxy. HTTP_TUNNEL should be the proxy's
                        URL: 'http://USER:PW@HOST:PORT/'. For proxies
                        requiring authentication, only Basic Authentication is
                        supported.
  --starttls PROTOCOL   Perform a StartTLS handshake when connecting to the
                        target server(s). StartTLS should be one of: auto,
                        smtp, xmpp, xmpp_server, pop3, imap, ftp, ldap, rdp,
                        postgres. The 'auto' option will cause SSLyze to
                        deduce the protocol (ftp, imap, etc.) from the
                        supplied port number, for each target server.
  --xmpp_to HOSTNAME    Optional setting for STARTTLS XMPP. XMPP_TO should be
                        the hostname to be put in the 'to' attribute of the
                        XMPP stream. Default is the server's hostname.
  --sni SERVER_NAME_INDICATION
                        Use Server Name Indication to specify the hostname to
                        connect to. Will only affect TLS 1.0+ connections.

Scan commands:
  --tlsv1_3             Test a server for TLS 1.3 support.
  --http_headers        Test a server for the presence of security-related
                        HTTP headers.
  --fallback            Test a server for the TLS_FALLBACK_SCSV mechanism to
                        prevent downgrade attacks.
  --robot               Test a server for the ROBOT vulnerability.
  --ems                 Test a server for TLS Extended Master Secret extension
                        support.
  --tlsv1_1             Test a server for TLS 1.1 support.
  --tlsv1               Test a server for TLS 1.0 support.
  --compression         Test a server for TLS compression support, which can
                        be leveraged to perform a CRIME attack.
  --early_data          Test a server for TLS 1.3 early data support.
  --reneg               Test a server for insecure TLS renegotiation and
                        client-initiated renegotiation.
  --openssl_ccs         Test a server for the OpenSSL CCS Injection
                        vulnerability (CVE-2014-0224).
  --sslv2               Test a server for SSL 2.0 support.
  --heartbleed          Test a server for the OpenSSL Heartbleed
                        vulnerability.
  --elliptic_curves     Test a server for supported elliptic curves.
  --certinfo            Retrieve and analyze a server's certificate(s) to
                        verify its validity.
  --certinfo_ca_file CERTINFO_CA_FILE
                        To be used with --certinfo. Path to a file containing
                        root certificates in PEM format that will be used to
                        verify the validity of the server's certificate.
  --sslv3               Test a server for SSL 3.0 support.
  --resum               Test a server for TLS 1.2 session resumption support
                        using session IDs and TLS tickets.
  --resum_attempts RESUM_ATTEMPTS
                        To be used with --resum. Number of session resumptions
                        (both with Session IDs and TLS Tickets) that SSLyze
                        should attempt. The default value is 5, but a higher
                        value such as 100 can be used to get a more accurate
                        measure of how often session resumption succeeds or
                        fails with the server.
  --tlsv1_2             Test a server for TLS 1.2 support.
```

Updated on: 2026-Jun-17

### subfinder

Source: https://www.kali.org/tools/subfinder/

#### subfinder

Subdomain discovery tool This package contains a subdomain discovery tool that discovers valid
subdomains for websites by using passive online sources. It has a simple
modular architecture and is optimized for speed. subfinder is built for doing
one thing only - passive subdomain enumeration, and it does that very well.
Installed size: 31.01 MB How to install: sudo apt install subfinder
- libc6

##### subfinder

```
root@kali:~# subfinder -h
Subfinder is a subdomain discovery tool that discovers subdomains for websites by using passive online sources.

Usage:
  subfinder [flags]

Flags:
INPUT:
   -d, -domain string[]  domains to find subdomains for
   -dL, -list string     file containing list of domains for subdomain discovery

SOURCE:
   -s, -sources string[]           specific sources to use for discovery (-s crtsh,github). Use -ls to display all available sources.
   -recursive                      use only sources that can handle subdomains recursively rather than both recursive and non-recursive sources
   -all                            use all sources for enumeration (slow)
   -es, -exclude-sources string[]  sources to exclude from enumeration (-es alienvault,zoomeyeapi)

FILTER:
   -m, -match string[]   subdomain or list of subdomain to match (file or comma separated)
   -f, -filter string[]   subdomain or list of subdomain to filter (file or comma separated)

RATE-LIMIT:
   -rl, -rate-limit int      maximum number of http requests to send per second (global)
   -rls, -rate-limits value  maximum number of http requests to send per second for providers in key=value format (-rls hackertarget=10/m) (default ["github=30/m", "fullhunt=60/m", "pugrecon=10/s", "robtex=18446744073709551615/ms", "securitytrails=1/s", "shodan=1/s", "virustotal=4/m", "hackertarget=2/s", "waybackarchive=15/m", "whoisxmlapi=50/s", "securitytrails=2/s", "sitedossier=8/m", "netlas=1/s", "github=83/m", "hudsonrock=5/s", "urlscan=1/s"])
   -t int                    number of concurrent goroutines for resolving (-active only) (default 10)

UPDATE:
   -up, -update                 update subfinder to latest version
   -duc, -disable-update-check  disable automatic subfinder update check

OUTPUT:
   -o, -output string       file to write output to
   -oJ, -json               write output in JSONL(ines) format
   -oD, -output-dir string  directory to write output (-dL only)
   -cs, -collect-sources    include all sources in the output (-json only)
   -oI, -ip                 include host IP in output (-active only)

CONFIGURATION:
   -config string                flag config file (default "/root/.config/subfinder/config.yaml")
   -pc, -provider-config string  provider config file (default "/root/.config/subfinder/provider-config.yaml")
   -r string[]                   comma separated list of resolvers to use
   -rL, -rlist string            file containing list of resolvers to use
   -nW, -active                  display active subdomains only
   -proxy string                 http proxy to use with subfinder
   -ei, -exclude-ip              exclude IPs from the list of domains

DEBUG:
   -silent             show only subdomains in output
   -version            show version of subfinder
   -v                  show verbose output
   -nc, -no-color      disable color in output
   -ls, -list-sources  list all available sources
   -stats              report source statistics

OPTIMIZATION:
   -timeout int   seconds to wait before timing out (default 30)
   -max-time int  minutes to wait for enumeration results (default 10)
```

Updated on: 2026-May-25

### swaks

Source: https://www.kali.org/tools/swaks/

#### swaks

SMTP command-line test tool swaks (Swiss Army Knife SMTP) is a command-line tool written in Perl
for testing SMTP setups; it supports STARTTLS and SMTP AUTH (PLAIN,
LOGIN, CRAM-MD5, SPA, and DIGEST-MD5). swaks allows one to stop the
SMTP dialog at any stage, e.g to check RCPT TO: without actually
sending a mail.
If you are spending too much time iterating “telnet foo.example 25”
swaks is for you.
Installed size: 312 KB How to install: sudo apt install swaks
- perl

##### swaks

Swiss Army Knife SMTP, the all-purpose SMTP transaction tester

```
root@kali:~# swaks --help
SWAKS(1)                             SWAKS                             SWAKS(1)

NAME
     Swaks - Swiss Army Knife SMTP, the all-purpose SMTP transaction tester

DESCRIPTION
     Swaks'  primary  design goal is to be a flexible, scriptable, transaction-
     oriented SMTP test tool.  It handles SMTP features and extensions such  as
     TLS, authentication, and pipelining; multiple version of the SMTP protocol
     including  SMTP, ESMTP, and LMTP; and multiple transport methods including
     UNIX-domain  sockets,  internet-domain  sockets,  and  pipes  to   spawned
     processes.   Options can be specified in environment variables, configura-
     tion files, and the command line allowing maximum configurability and ease
     of use for operators and scripters.

QUICK START
     Deliver  a  standard  test  email  to
[email protected]
on  port  25   of
     test-server.example.net:

      swaks --to
[email protected]
--server test-server.example.net

     Deliver  a  standard test email, requiring CRAM-MD5 authentication as user
[email protected]
.  An "X-Test" header will be added to the email body.   The
     authentication password will be prompted for if it cannot be obtained from
     your .netrc file.

      swaks --to
[email protected]
--from
[email protected]
--auth CRAM-MD5 --auth-user
[email protected]
--header-X-Test "test email"

     Test a virus scanner using EICAR in an attachment.  Don't show the message
     DATA part.:

      swaks -t
[email protected]
--attach - --server test-server.example.com --suppress-data </path/to/eicar.txt

     Test a spam scanner using GTUBE in the body of an email, routed via the MX
     records for example.com:

      swaks --to
[email protected]
--body @/path/to/gtube/file

     Deliver  a standard test email to
[email protected]
using the LMTP protocol
     via a UNIX domain socket file

      swaks --to
[email protected]
--socket /var/lda.sock --protocol LMTP

     Report all the recipients in a text file that are non-verifiable on a test
     server:

      for E in `cat /path/to/email/file`
      do
          swaks --to $E --server test-server.example.com --quit-after RCPT --hide-all
          [ $? -ne 0 ] && echo $E
      done

TERMS AND CONVENTIONS
     This document tries to be consistent and specific in its use of  the  fol-
     lowing terms to reduce confusion.

     Target
         The target of a transaction is the thing that Swaks connects to.  This
         generic  term  is used throughout the documentation because most other
         terms improperly imply something about the transport being used.

     Transport
         The transport is the underlying method used to connect to the target.

     Transaction
         A transaction is the opening of a connection over  a  transport  to  a
         target and using a messaging protocol to attempt to deliver a message.

     Protocol
         The  protocol is the application language used to communicate with the
         target.  This document uses SMTP to speak  generically  of  all  three
         supported  protocols  unless it states that it is speaking of the spe-
         cific 'SMTP' protocol and excluding the others.

     Message
         SMTP protocols exist to transfer  messages,  a  set  of  bytes  in  an
         agreed-upon format that has a sender and a recipient.

     Envelope
         A message's envelope contains the "true" sender and receiver of a mes-
         sage.   It  can also be referred to as its components, envelope-sender
         and envelope-recipients.  It is important to note that a messages  en-
         velope does not have to match its "To:" and "From:" headers.

     DATAThe  DATA portion of an SMTP transaction is the actual message that is
         being transported.  It consists of both the message's headers and  its
         body.  DATA and body are sometimes used synonymously, but they are al-
         ways two distinct things in this document.

     Headers
         A message's headers are defined as all the lines in the message's DATA
         section  before  the first blank line.  They contain information about
         the email that will be displayed  to  the  recipient  such  as  "To:",
         "From:",  "Subject:",  etc.   In  this document headers will always be
         written with a capitalized first letter and a trailing colon.

     BodyA message's body is the portion of  its  DATA  section  following  the
         first blank line.

     Option
         An  option  is a flag which changes Swaks' behavior.  Always called an
         option  regardless   of   how   it   is   provided.    For   instance,
         "--no-data-fixup" is an option.

     Argument
         When  an option takes addition data beside the option itself, that ad-
         ditional data is called an argument. In "--quit-after  <stop-point>'",
         "<stop-point>" is the argument to the "--quit-after" option.

     <literal-string>
         When used in the definition of an option, text that is inside of angle
         brackets  ("<>")  indicates  a  descriptive label for a value that the
         user should provide.  For instance, "--quit-after <stop-point>"  indi-
         cates  that  "<stop-point>" should be replaced with a valid stop-point
         value.

     [<optional-value>]
         When used in the definition of an option, text inside of square brack-
         ets ([]) indicates that the value is optional and can be omitted.  For
         instance, "--to [<recipient>]" indicates that the "--to" option can be
         used with or without a specified "<recipient>".

OPTION PROCESSING
     To prevent potential confusion in this document a flag to Swaks is  always
     referred to as an "option".  If the option takes additional data, that ad-
     ditional  data  is referred to as an argument to the option.  For example,
     "--from
[email protected]
" might be provided to Swaks on the command  line,
     with "--from" being the option and "
[email protected]
" being "--from"'s ar-
     gument.

     Options  and  arguments  are the only way to provide information to Swaks.
     If Swaks finds data during option processing that is neither an option nor
     an  option's  argument,  it  will  error  and  exit.   For  instance,   if
     "--no-data-fixup  1"  were found on the command line, this would result in
     an error because "--no-data-fixup" does not take an argument and therefore
     Swaks would not know what to do with 1.

     Options can be given to Swaks in three ways.  They can be specified  in  a
     configuration  file,  in  environment  variables, and on the command line.
     Depending on the specific option and whether an argument is given  to  it,
     Swaks may prompt the user for the argument.

     When  Swaks evaluates its options, it first looks for a configuration file
     (either in a default location or  specified  with  "--config").   Then  it
     evaluates  any  options  in  environment variables.  Finally, it evaluates
     command line options.  At each round of processing, any options  set  ear-
     lier  will  be  overridden.  Additionally, any option can be prefixed with
     "no-" to cause Swaks to forget that the variable had previously  been  set
     (either in an earlier round, or earlier in the same round).  This capabil-
     ity  is  necessary because many options treat defined-but-no-argument dif-
     ferently than not-defined.

     As a general rule, if the same option is given  multiple  time,  the  last
     time  it  is given is the one that will be used.  This applies to both in-
     tra-method (if  "--from
[email protected]
--from
[email protected]
"  is
     given,  "
[email protected]
"  will  be  used)  and  inter-method  (if "from
[email protected]
" is given in  a  config  file  and  "--from  user2@exam-
     ple.com" is given on the command line, "
[email protected]
" will be used)

     Each  option  definition ends with a parenthetical synopsis of how the op-
     tion behaves.  The following codes can be used

     Arg-None, Arg-Optional, Arg-Required
         These three codes are mutually exclusive and describe whether  or  not
         the option takes an argument.  Note that this does not necessarily de-
         scribe  whether the argument is required to be specified directly, but
         rather whether an argument  is  required  eventually.   For  instance,
         "--to"  is  labeled as Arg-Required, but it is legal to specify "--to"
         on the command line without an argument.  This is  because  Swaks  can
         prompt for the required argument if it is not directly provided.

     From-Prompt
         An  option labeled with From-Prompt will prompt the user interactively
         for the argument if none is provided.

     From-File
         An option labeled with From-File will handle  arguments  as  files  in
         certain situations.

         If  the initial argument is "-", the final argument is the contents of
         "STDIN".  Multiple options can all specify "STDIN", but the same  con-
         tent will be used for each of them.

         If  the  initial  argument  is prefixed with "@", the argument will be
         treated as a path to a file.  The file will be opened and the contents
         will be used as the final argument.  If the contents of the file can't
         be read, Swaks will exit.  To specify a literal string value  starting
         with  an "@", use two "@" symbols.  The first will be stripped.  It is
         not possible to include an unqualified file which starts with  an  "@"
         sign  (like "--attach @file.txt" or "--attach @@file.txt"), but if you
         include a path to the file which splits up the  two  "@"  signs,  that
         will work (eg "--attach @./@file.txt" will include the contents of the
         file @file.txt).

     Sensitive
         If an option marked Sensitive attempts to prompt the user for an argu-
         ment  and  the "--protect-prompt" option is set, Swaks will attempt to
         mask the user input from being echoed on the terminal.  Swaks tries to
         mask the input in several ways, but if none of them work program  flow
         will continue with unmasked input.

     Deprecated
         An  option  labeled Deprecated has been officially deprecated and will
         be removed in a future release.  See  the  "DEPRECATIONS"  section  of
         this documentation for details about the deprecations.

     The  exact  mechanism and format for using each of the types is listed be-
     low.

     CONFIGURATION FILES
         A configuration file can be used to set  commonly-used  or  abnormally
         verbose   options.    By   default,   Swaks   looks   in   order   for
         $SWAKS_HOME/.swaksrc, $HOME/.swaksrc, and $LOGDIR/.swaksrc.  If one of
         those is found to exist (and "--config" has not been used)  that  file
         is used as the configuration file.

         Additionally,  a  configuration  file in a non-default location can be
         specified using "--config".  If this is set and not given an  argument
         Swaks will not use any configuration file, including any default file.
         If  "--config" points to a readable file, it is used as the configura-
         tion file, overriding any default that may exist.  If it points  to  a
         non-readable file an error will be shown and Swaks will exit.

         A  set of "portable" defaults can also be created by adding options to
         the end of the Swaks program file.  As distributed, the last  line  of
         Swaks  should  be  "__END__".  Any lines added after "__END__" will be
         treated as the contents of a configuration file.  This allows a set of
         user preferences to be automatically copied from server to server in a
         single file.

         If configuration files  have  not  been  explicitly  turned  off,  the
         "__END__"  config  is  always read.  Only one other configuration file
         will ever be used per single invocation of  Swaks,  even  if  multiple
         configuration  files  are  specified.  If the "__END__" config and an-
         other config are to be read, the "__END__" config  will  be  processed
         first.   Specifying  the  "--config" option with no argument turns off
         the processing of both the "__END__"  config  and  any  actual  config
         files.

         In a configuration file lines beginning with a hash ("#") are ignored.
         All other lines are assumed to be an option to Swaks, with the leading
         dash  or  dashes  optional.   Everything  after an option line's first
         space is assumed  to  be  the  option's  argument  and  is  not  shell
         processed.   Therefore,  quoting  is  usually unneeded and will be in-
         cluded literally in the argument.

         There is a subtle difference between providing an option with no argu-
         ment and providing an option with an empty  argument.   If  an  option
         line  does  not  have a space, the entire line is treated as an option
         and there is no argument.  If the line ends in a single space, it will
         be processed as an option with an empty argument.  So, "apt"  will  be
         treated as "--apt", but "apt " will be treated as "--apt ''".

         Here is an example of the contents of a configuration file:

             # always use this sender, no matter server or logged in user
             --from
[email protected]
#### I prefer my test emails have a pretty from header.  Note
             # the lack of dashes on option and lack of quotes around
             # entire argument.
             h-From: "Fred Example" <
[email protected]
>

         Options specific to configuration file:

         --config [<config-file>]
             This option provides a path to a specific configuration file to be
             used.   If specified with no argument, no automatically-found con-
             figuration file (via $HOME, etc, or "__END__") will be  processed.
             If  the  argument  is  a valid file, that file will be used as the
             configuration file (after "__END__" config).  If argument is not a
             valid, readable file, Swaks will error and exit.  This option  can
             be  specified multiple times, but only the first time it is speci-
             fied (in environment variable and the command line  search  order)
             will be used. (Arg-Optional)

     CONFIGURATION ENVIRONMENT VARIABLES
         Options  can be supplied via environment variables.  The variables are
         in the form $SWAKS_OPT_name, where "name" is the name  of  the  option
         that  would  be  specified on the command line.  Because dashes aren't
         allowed in environment variable names  in  most  UNIX-ish  shells,  no
         leading  dashes should be used and any dashes inside the option's name
         should be replaced with underscores.  The following would  create  the
         same options shown in the configuration file example:

             $ SWAKS_OPT_from='
[email protected]
'
             $ SWAKS_OPT_h_From='"Fred Example" <
[email protected]
>'

         Setting  a  variable to an empty value is the same as specifying it on
         the  command  line  with   no   argument.    For   instance,   setting
         <SWAKS_OPT_server="">  would  cause  Swaks  to prompt the user for the
         server to which to connect at each invocation.  On Windows, it is  not
         possible to set empty environment variables.  The behavior can be sim-
         ulated by setting the environment variable to "<>" instead.  Addition-
         ally,  embedding  the header name in the header option via environment
         variable is not allowed on Windows (eg "SWAKS_OPT_header_Foo=bar" will
         result in an error, but "SWAKS_OPT_header="Foo: bar"" will work.)

         Because there is no inherent order in options provided by setting  en-
         vironment  variables,  the  options are sorted before being processed.
         This is not a great solution, but it at least  defines  the  behavior,
         which   would   be  otherwise  undefined.   As  an  example,  if  both
         $SWAKS_OPT_from  and   $SWAKS_OPT_f   were   set,   the   value   from
         $SWAKS_OPT_from  would  be  used, because it sorts after $SWAKS_OPT_f.
         Also as a result of not having an inherent order in  environment  pro-
         cessing,  unsetting  options  with the "no-" prefix is unreliable.  It
         works if the option being turned off sorts before "no-", but fails  if
         it  sorts  after.  Because "no-" is primarily meant to operate between
         config types (for instance, unsetting from the command line an  option
         that was set in a config file), this is not likely to be a problem.

         In  addition  to  setting  the  equivalent  of  command  line options,
         $SWAKS_HOME can be set to a directory containing the default  .swaksrc
         to be used.

     COMMAND LINE OPTIONS
         The  final  method  of  supplying  options to Swaks is via the command
         line.  The options behave in a manner consistent  with  most  UNIX-ish
         command  line  programs.  Many options have both a short and long form
         (for instance "-s" and "--server").  By convention short  options  are
         specified  with  a  single  dash and long options are specified with a
         double-dash.  This is only a convention and either  prefix  will  work
         with either type.

         The following demonstrates the example shown in the configuration file
         and environment variable sections:

             $ swaks --from
[email protected]
--h-From: '"Fred Example" <
[email protected]
>'

TRANSPORTS
     Swaks  can connect to a target via UNIX pipes ("pipes"), UNIX domain sock-
     ets ("UNIX sockets"), or  internet  domain  sockets  ("network  sockets").
     Connecting  via  network  sockets is the default behavior.  Because of the
     singular nature of the transport used, each set of options in the  follow-
     ing   section   is  mutually  exclusive.   Specifying  more  than  one  of
     "--server", "--pipe", or "--socket" will result in an error.  Mixing other
     options between transport types will only result in the irrelevant options
     being ignored.  Below is a brief description of each type of transport and
     the options that are specific to that transport type.

     NETWORK SOCKETS
         This transport attempts to deliver a message via TCP/IP, the  standard
         method  for delivering SMTP.  This is the default transport for Swaks.
         If none of "--server", "--pipe", or "--socket"  are  given  then  this
         transport is used and the target server is determined from the recipi-
         ent's domain (see "--server" below for more details).

         This  transport  requires  the IO::Socket::IP module for both IPv4 and
         IPv6 sockets.  If this module is not loadable, Swaks will  attempt  to
         use  the  IO::Socket  library  for IPv4 and IO::Socket::INET6 for IPv6
         support.  Attempting to use this transport  with  none  of  those  li-
         braries available will result in an error and program termination.

         The  fall  back  to IO::Socket and IO::Socket::INET6 is deprecated and
         will be removed in a future release.  See DEPRECATIONS below

         -s, --server [<target-server>[:<port>]]
             Explicitly tell Swaks to use network sockets and specify the host-
             name or IP address to which to connect, or prompt if  no  argument
             is  given.  If this option is not given and no other transport op-
             tion is given, the target mail server is determined from  the  ap-
             propriate  DNS  records  for the domain of the recipient email ad-
             dress using the Net::DNS module.  If  Net::DNS  is  not  available
             Swaks will attempt to connect to localhost to deliver.  The target
             port  can  optionally be set here.  Supported formats for this in-
             clude  SERVER:PORT  (supporting   names   and   IPv4   addresses);
             [SERVER]:PORT and SERVER/PORT (supporting names, IPv4 and IPv6 ad-
             dresses).   A  port  set  via this option will only be used if the
             "--port" option is not used.  See also "--copy-routing".  (Arg-Re-
             quired, From-Prompt)

         -p, --port [<port>]
             Specify  which  TCP port on the target is to be used, or prompt if
             no argument is listed.  The argument can be a service name (as re-
             trieved by getservbyname(3)) or a port number.  The  default  port
             is smtp/25 unless influenced by the "--protocol" or "--tls-on-con-
             nect" options. (Arg-Required, From-Prompt)

         -li, --local-interface [<local-interface>[:<port>]]
             Use  argument as the local interface for the outgoing SMTP connec-
             tion, or prompt user if no argument given.  Argument can be an  IP
             address  or  a  hostname.   Default action is to let the operating
             system choose the local interface.  See "--server" for  additional
             comments  on :<port> format.  A port set via this option will only
             be used if the "--port" option is not used.  (Arg-Required,  From-
             Prompt)

         -lp, --local-port, --lport [<port>]
             Specify the outgoing port from which to originate the transaction.
             The  argument  can  be  a service name (as retrieved by getservby-
             name(3)) or a port number.  If this option is  not  specified  the
             system  will pick an ephemeral port.  Note that regular users can-
             not specify some ports. (Arg-Required, From-Prompt)

         --copy-routing <domain>
             The argument is interpreted as the domain part of an email address
             and it is used to find the target server using the same logic that
             would be used to look up the target server for a  recipient  email
             address.   See "--to" option for more details on how the target is
             determined from the email domain. (Arg-Required)

         -4, -6
             Force IPv4 or IPv6. (Arg-None)

     UNIX SOCKETS
         This transport method attempts to deliver messages via  a  UNIX-domain
         socket  file.   This  is  useful  for  testing MTA/MDAs that listen on
         socket files (for instance, testing LMTP  delivery  to  Cyrus).   This
         transport  requires  the  IO::Socket::UNIX module which is part of the
         standard Perl distribution.  If this module is not loadable,  attempt-
         ing to use this transport will result in an error and program termina-
         tion.

         --socket [<socket-file>]
             This  option  takes as its argument a UNIX-domain socket file.  If
             Swaks is unable to open this socket it will display an  error  and
             exit. (Arg-Required, From-Prompt)

     PIPES
         This transport attempts to spawn a process and communicate with it via
         pipes.   The  spawned  program  must  be  prepared to behave as a mail
         server over  "STDIN"/"STDOUT".   Any  MTA  designed  to  operate  from
         inet/xinet  should support this.  In addition, some MTAs provide test-
         ing modes that can be communicated with  via  "STDIN"/"STDOUT".   This
         transport  can  be used to automate that testing.  For example, if you
         implemented DNSBL checking with Exim and you wanted to  make  sure  it
         was  working, you could run "swaks --pipe "exim -bh 127.0.0.2"".  Ide-
         ally, the process you are talking to should  behave  exactly  like  an
         SMTP  server on "STDIN" and "STDOUT".  Any debugging should be sent to
         "STDERR", which will be directed to your terminal.  In practice, Swaks
         can generally handle some debug on the child's "STDOUT", but there are
         no guarantees on how much it can handle.

         This transport requires the IPC::Open2 module which  is  part  of  the
         standard  Perl distribution.  If this module is not loadable, attempt-
         ing to use this transport will result in an error and program termina-
         tion.

         --pipe [<command-and-arguments>]
             Provide a process name and arguments to the process.   Swaks  will
             attempt  to  spawn  the process and communicate with it via pipes.
             If the argument is not an executable Swaks will display  an  error
             and exit. (Arg-Required, From-Prompt)

PROTOCOL OPTIONS
     These options are related to the protocol layer.

     -t, --to [<email-address>[,<email-address>[,...]]]
     --cc [<email-address>[,<email-address>[,...]]]
     --bcc [<email-address>[,<email-address>[,...]]]
         These  options  all tell Swaks to use the argument(s) as the envelope-
         recipient for the email.  There are subtle differences  between  these
         three options, detailed below.  If any option is specified but with no
         arguments, Swaks will prompt the user for an argument.

         "--to"  is  special  in  that it is the only option required by Swaks.
         There is no default value for this option.  If no recipients are  pro-
         vided  via  any  means,  user will be prompted to provide one interac-
         tively.  The only exception to this is if a  "--quit-after"  value  is
         provided which will cause the SMTP transaction to be terminated before
         the  recipient is needed.  If multiple recipients are provided and the
         recipient domain is needed to determine routing,  the  domain  of  the
         last recipient in the "--to" argument list is used.

         The  primary  distinction between these options is how their arguments
         are treated when generating the DATA portion of the email.  They  each
         have their own replacement tokens ("%TO_ADDRESS%", "%CC_ADDRESS%", and
         "%BCC_ADDRESS%"  respectively)  which can be used by anyone crafting a
         custom DATA.  In Swaks' default message, "%TO_ADDRESS%" will  be  used
         for the To: header and, if it is populated, "%CC_HEADER%" will be used
         for  a  Cc:  header.  "%BCC_ADDRESS%" is not used in the default DATA.
         (Arg-Required, From-Prompt)

     -f, --from [<email-address>]
         Use argument as envelope-sender for email, or prompt user if no  argu-
         ment  specified.   The  string  "<>"  can be supplied to mean the null
         sender.  If user does not specify a sender address a default value  is
         used.   The  domain-part  of the default sender is a best guess at the
         fully-qualified domain name of the local host.  The method  of  deter-
         mining the local-part varies.  If the $LOGNAME environment variable is
         set,  it  will  be  used  as the local-part.  Otherwise the value from
         Win32::LoginName() will be used on Windows and getpwuid(3) on UNIX-ish
         platforms.  See also "--force-getpwuid".  If Swaks cannot determine  a
         local  hostname  and the sender address is needed for the transaction,
         Swaks will error and exit.  In this case, a valid string must be  pro-
         vided via this option. (Arg-Required, From-Prompt)

     --ehlo, --lhlo, -h, --helo [<helo-string>]
         String to use as argument to HELO/EHLO/LHLO command, or prompt user if
         no  argument is specified.  If this option is not used a best guess at
         the fully-qualified domain name of the local host is used.   If  Swaks
         cannot  determine  a  local hostname and the helo string is needed for
         the transaction, Swaks will error and exit.  In  this  case,  a  valid
         string must be provided via this option. (Arg-Required, From-Prompt)

     -q, --quit, --quit-after <stop-point>
         Point  at which the transaction should be stopped.  When the requested
         stopping point is reached in the transaction, and provided that  Swaks
         has  not  errored out prior to reaching it, Swaks will send "QUIT" and
         attempt to close the connection cleanly.  These are  the  valid  argu-
         ments and notes about their meaning. (Arg-Required)

         PROXY
             Quit  after  the server sends a response to a PROXY request.  Note
             that if there is not an error negotiating proxy, this will be syn-
             onymous with CONNECT.

         CONNECT, BANNER
             Terminate the session after receiving the greeting banner from the
             target.

         FIRST-HELO, FIRST-EHLO, FIRST-LHLO
             In a STARTTLS (but  not  tls-on-connect)  session,  terminate  the
             transaction  after  the  first  of  two  HELOs.  In a non-STARTTLS
             transaction, behaves the same as HELO (see below).

         XCLIENT
             Quit after XCLIENT is negotiation. This  always  quits  after  the
             point  where  XCLIENT  would  have  been negotiated, regardless of
             whether it was attempted.

         XCLIENT-HELO
             Quit after the HELO that XCLIENT negotiation triggers.  This  dif-
             fers from HELO and FIRST-HELO because XCLIENT negotiation can hap-
             pen  at multiple points in the SMTP transaction and it is impossi-
             ble to specifically refer to the XCLIENT-triggered HELO using  the
             HELO  or FIRST-HELO stop-points. This always quits after the point
             where the XCLIENT-triggered HELO would have  occurred,  regardless
             of whether it was attempted.

         STARTTLS, TLS
             Quit  the transaction immediately following TLS negotiation.  Note
             that this happens in different places depending on whether  START-
             TLS or tls-on-connect are used.  This always quits after the point
             where TLS would have been negotiated, regardless of whether it was
             attempted.

         HELO, EHLO, LHLO
             In  a  STARTTLS  or  XCLIENT  session, quit after the second HELO.
             Otherwise quit after the first and only HELO.

         AUTHQuit after authentication.  This  always  quits  after  the  point
             where  authentication  would  have  been negotiated, regardless of
             whether it was attempted.

         MAIL, FROM
             Quit after MAIL FROM: is sent.

         RCPT, TO
             Quit after RCPT TO: is sent.

     --da, --drop-after <stop-point>
         The option is similar to "--quit-after",  but  instead  of  trying  to
         cleanly  shut down the session it simply terminates the session.  This
         option accepts the same stop-points as "--quit-after" and additionally
         accepts DATA and DOT, detailed below. (Arg-Required)

         DATADrop the connection after DATA is sent by server.

         DOT Drop the connection after the final '.' of the message is sent  by
             server.

     --das, --drop-after-send <stop-point>
         This  option is similar to "--drop-after", but instead of dropping the
         connection after reading a response to the stop-point,  it  drops  the
         connection  immediately after sending stop-point.  It accepts the same
         stop-points as "--drop-after". If the stop-point is  for  an  optional
         part  of  the  transaction  which  is  not actually sent (for instance
         STARTTLS or AUTH), this option will behave identically to  "--drop-af-
         ter". See below for specific details. (Arg-Required)

         CONNECT
             Connect to the server and then drops the connection before receiv-
             ing the server's banner.

         STARTTLS, TLS
             Behaves identically to "--drop-after".

         HELO, EHLO, LHLO
             Doesn't  necessarily  work as expected.  If it appears to read the
             HELO response incorrectly, use FIRST-HELO instead.

     --timeout [<time>]
         Use argument as the SMTP transaction timeout, or prompt user if no ar-
         gument given.  Argument can either be a pure digit, which will be  in-
         terpreted  as seconds, or can have a specifier s, m, or h (5s = 5 sec-
         onds, 3m = 180 seconds, 1h = 3600 seconds).   As  a  special  case,  0
         means  don't timeout the transactions.  Default value is 30s. (Arg-Re-
         quired, From-Prompt)

     --protocol <protocol>
         Specify which protocol to use in the transaction.  Valid  options  are
         shown  in  the  table below.  Currently the 'core' protocols are SMTP,
         ESMTP, and LMTP.  By using variations of these protocol types one  can
         tersely  specify  default  ports, whether authentication should be at-
         tempted, and the type of TLS connection that should be attempted.  The
         default protocol is  ESMTP.   The  following  table  demonstrates  the
         available  arguments  to  "--protocol"  and the options each sets as a
         side effect.  (Arg-Required)

         SMTPHELO, "-p 25"

         SSMTP
             EHLO->HELO, "-tlsc -p 465"

         SSMTPA
             EHLO->HELO, "-a -tlsc -p 465"

         SMTPS
             HELO, "-tlsc -p 465"

         ESMTP
             EHLO->HELO, "-p 25"

         ESMTPA
             EHLO->HELO, "-a -p 25"

         ESMTPS
             EHLO->HELO, "-tls -p 25"

         ESMTPSA
             EHLO->HELO, "-a -tls -p 25"

         LMTPLHLO, "-p 24"

         LMTPA
             LHLO, "-a -p 24"

         LMTPS
             LHLO, "-tls -p 24"

         LMTPSA
             LHLO, "-a -tls -p 24"

     --pipeline
         If the remote server supports it, attempt SMTP PIPELINING (RFC  2920).
         (Arg-None)

     --prdr
         If  the server supports it, attempt Per-Recipient Data Response (PRDR)
         (<https://tools.ietf.org/html/draft-hall-prdr-00.txt>).  PRDR  is  not
         yet standardized, but MTAs have begun implementing the proposal. (Arg-
         None)

     --force-getpwuid
         Tell Swaks to use the system-default method of determining the current
         user's  username  for  the default sender local-part instead of trying
         $LOGNAME first.  Despite the UNIX-ish-specific option name,  this  op-
         tion also works on Windows. (Arg-None)

TLS / ENCRYPTION
     These  are options related to encrypting the transaction.  These have been
     tested and confirmed to  work  with  all  three  transport  methods.   The
     Net::SSLeay module is used to perform encryption when it is requested.  If
     this  module  is  not loadable Swaks will either ignore the TLS request or
     error out, depending on whether the request was optional.  STARTTLS is de-
     fined as an extension in the ESMTP protocol and  will  be  unavailable  if
     "--protocol"  is  set to a variation of plain SMTP.  Because it is not de-
     fined in the protocol itself, "--tls-on-connect" is available for any pro-
     tocol type if the target supports it.

     A local certificate is not required for a TLS connection to be negotiated.
     However, some servers use client certificate checking to verify  that  the
     client  is  allowed to connect.  Swaks can be told to use a specific local
     certificate using the "--tls-cert" and "--tls-key" options, and optionally
     to use a certificate chain using the "--tls-chain" option.

     -tlsRequire connection to use STARTTLS.  Exit if TLS not available for any
         reason (not advertised, negotiations failed, etc). (Arg-None)

     -tlso, --tls-optional
         Attempt to use STARTTLS if available, continue with normal transaction
         if TLS was unable to be negotiated for any reason.  Note that this  is
         a semi-useless option as currently implemented because after a negoti-
         ation  failure the state of the connection is unknown.  In some cases,
         like a version mismatch, the connection should be left  as  plaintext.
         In others, like a verification failure, the server-side may think that
         it  should  continue speaking TLS while the client thinks it is plain-
         text.  There may be an attempt to add more granular state detection in
         the future, but for now just be aware that odd things may happen  with
         this option if the TLS negotiation is attempted and fails. (Arg-None)

     -tlsos, --tls-optional-strict
         Attempt to use STARTTLS if available.  Proceed with transaction if TLS
         is negotiated successfully or STARTTLS not advertised.  If STARTTLS is
         advertised  but  TLS  negotiations  fail,  treat as an error and abort
         transaction.  Due to the caveat noted above, this is a much saner  op-
         tion than "--tls-optional". (Arg-None)

     -tlsc, --tls-on-connect
         Initiate a TLS connection immediately on connection.  Following common
         convention,  if this option is specified the default port changes from
         25 to 465, though this can still be overridden with the --port option.
         (Arg-None)

     -tlsp, --tls-protocol <tls-version-specification>
         Specify which protocols to use (or not use) when negotiating TLS.   At
         the  time  of  this writing, the available protocols are sslv2, sslv3,
         tlsv1, tlsv1_1, tlsv1_2, and tlsv1_3.  The availability of these  pro-
         tocols  is dependent on your underlying OpenSSL library, so not all of
         these may be available.  The list of available protocols is  shown  in
         the output of "--dump" (assuming TLS is available at all).

         The  specification  string is a comma-delimited list of protocols that
         can be used or not used.  For instance 'tlsv1,tlsv1_1' will only  suc-
         ceed if one of those two protocols is available on both the client and
         the server.  Conversely, 'no_sslv2,no_sslv3' will attempt to negotiate
         any  protocol  except sslv2 and sslv3.  The two forms of specification
         cannot be mixed. (Arg-Required)

     --tls-cipher <cipher-string>
         The argument to this option is passed to the  underlying  OpenSSL  li-
         brary  to  set  the  list of acceptable ciphers to the be used for the
         connection.  The format of this string is opaque to Swaks and  is  de-
         fined    in   <https://www.openssl.org/docs/manmaster/man1/openssl-ci-
         phers.html#CIPHER-LIST-FORMAT>.  A brief example would  be  "--tls-ci-
         pher '3DES:+RSA'". (Arg-Required)

     --tls-verify
         Tell Swaks to attempt to verify the server's certificate.  This option
         is  identical to specifying both the "--tls-verify-ca" and "--tls-ver-
         ify-host" options.  See those options for detailed descriptions of how
         to fine-tune each type of verification.

         By default, TLS verification is not required.  If TLS verification  is
         required  by "--tls-verify", "--tls-verify-ca", or "--tls-verify-host"
         and the requested type of verification fails, TLS negotiation will not
         succeed. (Arg-None)

     --tls-verify-ca
         Require that the server's certificate be signed by a known certificate
         authority and not be expired.  By default the list of known  CAs  will
         be  whatever is available via the client Swaks is running on.  To pro-
         vide a custom CA, see "--tls-ca-path". (Arg-None)

     --tls-verify-host
         Require that the target of the current connection  be  listed  in  the
         server certificate's Subject Alternative Name (SAN) or Subject Common-
         Name (CN).

         The  target  that  Swaks uses for verification will vary.  It can be a
         hostname, either provided directly via the "--server" option or looked
         up via MX records.  In this case, verification performs  as  expected.
         If  the  target is an IP, the IP will be looked up in the certificate,
         which is possible but  unusual.   If  the  transport  is  "--pipe"  or
         "--socket",  there  will  not  be a meaningful target to verify in the
         certificate and verification will fail.  In this situation it's better
         to use only "--tls-verify-ca" or to override the target used for veri-
         fication with the "--tls-verify-target" option. (Arg-None)

     --tls-verify-target <verification-string>
         When set, the argument to this option will be used as the host  to  be
         verified  for  "--tls-verify-host".   This  is  necessary  when  using
         "--tls-verify-host" with either the "--pipe" or "--socket" transports,
         which do not have a verifiable target by default.  It can also be used
         to override the default target lookup when using the "--server" trans-
         port.  For instance, it can be used to verify that the certificate  of
         a server explicitly connect to via IP contains a specific certificate.
         (Arg-Required)

     --tls-ca-path <ca-location>
         Specify  an alternate location for CA information for verifying server
         certificates.  The argument can point to a file or directory.  The de-
         fault behavior is to use the underlying OpenSSL library's default  in-
         formation. (Arg-Required)

     --tls-cert <cert-file>
         Provide a path to a file containing the local certificate Swaks should
         use  if  TLS  is  negotiated.  If a certificate chain needs to be pro-
         vided, it can be provided via this file or via a  separate  file  with
         "--tls-chain".   The file path argument is required.  As currently im-
         plemented the certificate in the file must be in PEM format.   Contact
         the  author  if there's a compelling need for ASN1.  If this option is
         set, "--tls-key" is also required. (Arg-Required)

     --tls-key <key-file>
         Provide a path to a file containing the local private key Swaks should
         use if TLS is negotiated.  The file path  argument  is  required.   As
         currently  implemented the certificate in the file must be in PEM for-
         mat.  Contact the author if there's a compelling need  for  ASN1.   If
         this option is set, "--tls-cert" is also required. (Arg-Required)

     --tls-chain <chain-file>
         Provide  a path to a file containing the local certificate chain Swaks
         should use if TLS is negotiated.  The file path argument is  required.
         As  currently  implemented  the certificate in the file must be in PEM
         format.  Contact the author if there's a compelling need for ASN1.  If
         this option is set, "--tls-cert" and "--tls-key"  are  also  required.
         (Arg-Required)

     --tls-get-peer-cert [<output-file>]
         Get a copy of the TLS peer's certificate.  If no argument is given, it
         will  be displayed to "STDOUT".  If an argument is given it is assumed
         to be a filesystem path specifying where  the  certificate  should  be
         written.   The  saved  certificate can then be examined using standard
         tools such as the openssl command.  If a file is  specified  its  con-
         tents will be overwritten.  This option will only ever return one cer-
         tificate.   In  order to get every certificate sent by the server, see
         "--tls-get-peer-chain". (Arg-Optional)

     --tls-get-peer-chain [<output-file>]
         Get a copy of the TLS certificate chain sent by the server.  If no ar-
         gument is given, it will be displayed to "STDOUT".  If an argument  is
         given  it is assumed to be a filesystem path specifying where the cer-
         tificate should be written.  The saved chain can then be examined  us-
         ing  standard  tools such as the openssl command.  If a file is speci-
         fied its contents will be overwritten. See also "--tls-get-peer-cert".
         (Arg-Optional)

     --tls-sni <sni-string>
         Specify the Server Name Indication field to send when the TLS  connec-
         tion is initiated. (Arg-Required)

AUTHENTICATION
     Swaks will attempt to authenticate to the target mail server if instructed
     to  do  so.  This section details available authentication types, require-
     ments, options and their interactions, and other fine points in  authenti-
     cation  usage.   Because  authentication is defined as an extension in the
     ESMTP protocol it will be unavailable if "--protocol" is set to  a  varia-
     tion of SMTP.

     All  authentication  methods require base64 encoding.  If the MIME::Base64
     Perl module is loadable Swaks attempts to use it to perform  these  encod-
     ings.   If  MIME::Base64  is  not available Swaks will use its own onboard
     base64 routines.  These are slower than the MIME::Base64 routines and less
     reviewed, though they have been tested thoroughly.  Using the MIME::Base64
     module is encouraged.

     If authentication is required (see options below for when it is and  isn't
     required)  and  the  requirements  aren't  met for the authentication type
     available, Swaks displays an error and exits.  Two ways  this  can  happen
     include  forcing  Swaks  to  use a specific authentication type that Swaks
     can't use due to missing requirements, or allowing Swaks to  use  any  au-
     thentication  type,  but the server only advertises types Swaks can't sup-
     port.  In the former case Swaks errors out at option processing time since
     it knows up front it won't be able to authenticate.  In  the  latter  case
     Swaks  will  error out at the authentication stage of the SMTP transaction
     since Swaks will not be aware that it will not be able to authenticate un-
     til that point.

     Following are the supported authentication types including any  individual
     notes and requirements.

     The  following options affect Swaks' use of authentication.  These options
     are all inter-related.  For  instance,  specifying  "--auth-user"  implies
     "--auth"  and  "--auth-password".   Specifying  "--auth-optional"  implies
     "--auth-user" and "--auth-password", etc.

     -a, --auth [<auth-type>[,<auth-type>[,...]]]
         Require Swaks to authenticate.  If no argument is given, any supported
         auth-types advertised by the server are tried until  one  succeeds  or
         all  fail.   If  one  or more auth-types are specified as an argument,
         each that the server also supports is tried in order  until  one  suc-
         ceeds  or all fail.  This option requires Swaks to authenticate, so if
         no common auth-types are found or no credentials succeed,  Swaks  dis-
         plays an error and exits. (Arg-Optional)

         The following tables lists the valid auth-types

         LOGIN, PLAIN
             These  basic  authentication  types are fully supported and tested
             and have no additional requirements

         CRAM-MD5
             The CRAM-MD5 authenticator requires the Digest::MD5 module.  It is
             fully tested and believed to work against any server  that  imple-
             ments it.

         DIGEST-MD5
             The  DIGEST-MD5  authenticator (RFC2831) requires the Authen::SASL
             module.  Version 20100211.0  and  earlier  used  Authen::DigestMD5
             which had some protocol level errors which prevented it from work-
             ing with some servers.  Authen::SASL's DIGEST-MD5 handling is much
             more robust.

             The  DIGEST-MD5  implementation  in  Swaks is fairly immature.  It
             currently supports only the "auth" qop type, for instance.  If you
             have DIGEST-MD5 experience and would like to  help  Swaks  support
             DIGEST-MD5 better, please get in touch with me.

             The  DIGEST-MD5  protocol's  "realm"  value  can  be set using the
             "--auth-extra" "realm" keyword.  If no realm is given,  a  reason-
             able default will be used.

             The DIGEST-MD5 protocol's "digest-uri" values can be set using the
             "--auth-extra" option.  For instance, you could create the digest-
             uri-value  of  "lmtp/mail.example.com/example.com" with the option
             "--auth-extra             dmd5-serv-type=lmtp,dmd5-host=mail.exam-
             ple.com,dmd5-serv-name=example.com".     The    "digest-uri-value"
             string and its components is defined in RFC2831.  If none of these
             values are given, reasonable defaults will be used.

         CRAM-SHA1
             The CRAM-SHA1 authenticator requires the Digest::SHA module.  This
             type has only been tested against a non-standard implementation on
             an Exim server and may therefore have  some  implementation  defi-
             ciencies.

         NTLM/SPA/MSN
             These  authenticators  require the Authen::NTLM module.  This type
             has been tested against Exim, Communigate, and Exchange 2007.

             In addition to the standard username and password, this  authenti-
             cation  type can also recognize a "domain".  The domain can be set
             using the "--auth-extra" "domain" keyword.   Note  that  this  has
             never been tested with a mail server that doesn't ignore DOMAIN so
             this may be implemented incorrectly.

     -ao, --auth-optional [<auth-type>[,<auth-type>[,...]]]
         This  option  behaves  identically to "--auth" except that it requests
         authentication rather than requiring it.  If no common auth-types  are
         found  or  no credentials succeed, Swaks proceeds as if authentication
         had not been requested. (Arg-Optional)

     -aos, --auth-optional-strict [<auth-type>[,<auth-type>[,...]]]
         This option is a compromise between  "--auth"  and  "--auth-optional".
         If authentication is never attempted (server doesn't advertise authen-
         tication or no common authentication types are found), it behaves like
         "--auth-optional"  and the smtp transaction continues.  If authentica-
         tion is attempted but fails, it behaves like "--auth" and  exits  with
         an error. (Arg-Optional)

     -au, --auth-user [<username>]
         Provide the username to be used for authentication.  If no username is
         provided,  indicate that Swaks should attempt to find the username via
         .netrc (requires the Net::Netrc module).  If no username  is  provided
         and  cannot be found via .netrc,  the user will be prompted to provide
         one.  The string "<>" can be supplied to mean an empty username. (Arg-
         Required, From-Prompt)

     -ap, --auth-password [<password>]
         Provide the password to be used for authentication. If no password  is
         provided,  indicate that Swaks should attempt to find the password via
         .netrc (requires the Net::Netrc module).  If no password  is  provided
         and  cannot be found via .netrc,  the user will be prompted to provide
         one.  The string "<>" can be supplied to mean an empty password. (Arg-
         Required, From-Prompt, Sensitive)

     -ae, --auth-extra <key-value-pair>[,<key-value-pair>[,...]]
         Some of the authentication types allow extra  information  to  be  in-
         cluded  in  the  authentication process.  Rather than add a new option
         for every nook and cranny of each  authenticator,  the  "--auth-extra"
         option  allows  this  information  to  be  supplied.   The  format for
         <key-value-pair> is KEYWORD=VALUE. (Arg-Required)

         The following table lists the currently recognized  keywords  and  the
         authenticators that use them

         realm, domain
             The  realm  and domain keywords are synonymous.  Using either will
             set the "domain" option in NTLM/MSN/SPA and the "realm" option  in
             DIGEST-MD5

         dmd5-serv-type
             The dmd5-serv-type keyword is used by the DIGEST-MD5 authenticator
             and  is  used,  in part, to build the digest-uri-value string (see
             RFC2831)

         dmd5-host
             The dmd5-host keyword is used by the DIGEST-MD5 authenticator  and
             is  used,  in  part,  to  build  the  digest-uri-value string (see
             RFC2831)

         dmd5-serv-name
             The dmd5-serv-name keyword is used by the DIGEST-MD5 authenticator
             and is used, in part, to build the  digest-uri-value  string  (see
             RFC2831)

     -am, --auth-map <key-value-pair>[,<key-value-pair>[,...]]
         Provides  a way to map alternate names onto base authentication types.
         Useful for any sites that use alternate names for common  types.   The
         format for <key-value-pair> is AUTH-ALIAS=AUTH-TYPE.  This functional-
         ity is actually used internally to map types SPA and MSN onto the base
         type  NTLM.   The  command  line  argument  to  simulate this would be
         "--auth-map SPA=NTLM,MSN=NTLM".  All of the  auth-types  listed  above
         are valid targets for mapping except SPA and MSN. (Arg-Required)

     -apt, --auth-plaintext
         Instead  of  showing AUTH strings base64 encoded as they are transmit-
         ted, translate them to plaintext before printing on screen. (Arg-None)

     -ahp, --auth-hide-password [<replacement-string>]
         If this option is specified, any time a  readable  password  would  be
         printed  to  the terminal (specifically AUTH PLAIN and AUTH LOGIN) the
         password is replaced with the string  'PROVIDED_BUT_REMOVED'  (or  the
         contents  of  <replacement-string> if provided).  The dummy string may
         or may not be base64 encoded, contingent on the "--auth-plaintext" op-
         tion.

         Note that "--auth-hide-password" is similar, but not identical, to the
         "--protect-prompt" option.  The former protects passwords  from  being
         displayed  in the SMTP transaction regardless of how they are entered.
         The latter protects sensitive strings when the user types them at  the
         terminal, regardless of how the string would be used. (Arg-Optional)

XCLIENT OPTIONS
     XCLIENT  is  an SMTP extension introduced by the Postfix project.  XCLIENT
     allows a (properly-authorized) client to tell a server  to  use  alternate
     information,  such as IP address or hostname, for the client.  This allows
     much easier paths for testing mail server configurations.  Full details on
     the      protocol      are      available       at       <http://www.post-
     fix.org/XCLIENT_README.html>.

     The  XCLIENT verb can be passed to the server multiple times per SMTP ses-
     sion with different attributes.  For instance, HELO  and  PROTO  might  be
     passed in one call and NAME and ADDR passed in a second. Because it can be
     useful for testing, Swaks exposes some control over how the attributes are
     grouped and in what order they are passed to the server. The different op-
     tions  attempt to expose simplicity for those using Swaks as a client, and
     complexity for those using Swaks to test installs.

     --xclient-addr [<string>]
     --xclient-name [<string>]
     --xclient-port [<string>]
     --xclient-proto [<string>]
     --xclient-destaddr [<string>]
     --xclient-destport [<string>]
     --xclient-helo [<string>]
     --xclient-login [<string>]
     --xclient-reverse-name [<string>]
         These options specify XCLIENT attributes that should be  sent  to  the
         target  server.   If  <string>  is not provided, Swaks will prompt and
         read    the    value    on     "STDIN".      See     <http://www.post-
         fix.org/XCLIENT_README.html>  for  official documentation for what the
         attributes mean and their possible values, including the special "[UN-
         AVAILABLE]" and "[TEMPUNAVAIL]" values.

         By way of  simple  example,  setting  "--xclient-name  foo.example.com
         --xclient-addr  192.168.1.1" will cause Swaks to send the SMTP command
         "XCLIENT NAME=foo.example.com ADDR=192.168.1.1".

         Note that the "REVERSE_NAME" attribute doesn't seem to appear  in  the
         official documentation.  There is a mailing list thread that documents
         it,     viewable     at    <http://comments.gmane.org/gmane.mail.post-
         fix.user/192623>.

         These options can all be mixed with each other, and can be mixed  with
         the  "--xclient" option (see below). By default all attributes will be
         combined into one XCLIENT call, but  see  "--xclient-delim".  (Arg-Re-
         quired, From-Prompt)

     --xclient-delim
         When this option is specified, it indicates a break in XCLIENT attrib-
         utes  to be sent.  For instance, setting "--xclient-helo 'helo string'
         --xclient-delim    --xclient-name    foo.example.com    --xclient-addr
         192.168.1.1"  will  cause  Swaks  to  send two XCLIENT calls, "XCLIENT
         HELO=helo+20string"      and       "XCLIENT       NAME=foo.example.com
         ADDR=192.168.1.1".  This option is ignored where it doesn't make sense
         (at  the  start  or  end of XCLIENT options, by itself, consecutively,
         etc). (Arg-None)

     --xclient [<string>]
         This is the "free form" XCLIENT option.  Whatever  value  is  provided
         for <string> will be sent verbatim as the argument to the XCLIENT SMTP
         command.  For example, if "--xclient 'NAME= ADDR=192.168.1.1 FOO=bar'"
         is   used,   Swaks   will   send   the  SMTP  command  "XCLIENT  NAME=
         ADDR=192.168.1.1 FOO=bar".  If no argument is passed on command  line,
         Swaks will prompt and read the value on STDIN.

         The  primary advantage to this over the more specific options above is
         that there is no XCLIENT syntax validation here.  This allows  you  to
         send  invalid XCLIENT to the target server for testing.  Additionally,
         at least one MTA (Message Systems' Momentum, formerly  ecelerity)  im-
         plements   XCLIENT  without  advertising  supported  attributes.   The
         "--xclient" option allows you to skip the "supported attributes" check
         when  communicating  with  this  type  of   MTA   (though   see   also
         "--xclient-no-verify").

         The  "--xclient" option can be mixed freely with the "--xclient-*" op-
         tions above.  The argument to "--xclient" will be sent in its own com-
         mand   group.    For   instance,   if   "--xclient-addr    192.168.0.1
         --xclient-port  26  --xclient  'FOO=bar NAME=wind'" is given to Swaks,
         "XCLIENT ADDR=192.168.0.1 PORT=26"  and  "XCLIENT  FOO=bar  NAME=wind"
         will both be sent to the target server. (Arg-Required, From-Prompt)

     --xclient-no-verify
         Do  not  enforce the requirement that an XCLIENT attribute must be ad-
         vertised by the server in order for Swaks to send  it  in  an  XCLIENT
         command.  This is to support servers which don't advertise the attrib-
         utes but still support them. (Arg-None)

     --xclient-before-starttls
         If  Swaks  is configured to attempt both XCLIENT and STARTTLS, it will
         do STARTTLS first.  If  this  option  is  specified  it  will  attempt
         XCLIENT first. (Arg-None)

     --xclient-optional
     --xclient-optional-strict
         In  normal operation, setting one of the "--xclient*" options will re-
         quire a successful XCLIENT transaction to take place in order to  pro-
         ceed  (that is, XCLIENT needs to be advertised, all the user-requested
         attributes need to have been advertised, and the server needs to  have
         accepted Swaks' XCLIENT request).  These options change that behavior.
         "--xclient-optional"  tells  Swaks to proceed unconditionally past the
         XCLIENT stage of the SMTP transaction, regardless of  whether  it  was
         successful.  "--xclient-optional-strict" is similar but more granular.
         The  strict  version  will continue to XCLIENT was not advertised, but
         will fail if XCLIENT was attempted but did not succeed. (Arg-None)

PROXY OPTIONS
     Swaks    implements    the    Proxy     protocol     as     defined     in
     <http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt>.   Proxy  al-
     lows an application load balancer, such as HAProxy, to be used in front of
     an MTA while still allowing the MTA access to the originating host  infor-
     mation.  Proxy support in Swaks allows direct testing of an MTA configured
     to  expect  requests from a proxy, bypassing the proxy itself during test-
     ing.

     Swaks makes no effort to ensure that the Proxy options used are internally
     consistent.  For instance, "--proxy-family" (in version 1) is expected  to
     be  one  of  "TCP4" or "TCP6".  While it will likely not make sense to the
     target server, Swaks makes no attempt to ensure that "--proxy-source"  and
     "--proxy-dest" are in the same protocol family as "--proxy-family" or each
     other.

     The  "--proxy" option is mutually exclusive with all other "--proxy-*" op-
     tions except "--proxy-version".

     When "--proxy" is not used,  all  of  "--proxy-family",  "--proxy-source",
     "--proxy-source-port",  "--proxy-dest",  and  "--proxy-dest-port"  are re-
     quired.  Additionally, when "--proxy-version" is 2, "--proxy-protocol" and
     "--proxy-command" are optional.

     --proxy-version [ 1 | 2 ]
         Whether to use version 1 (human readable) or version 2 (binary) of the
         Proxy protocol.  Version 1 is the default.  Version 2 is  only  imple-
         mented through the "address block", and is roughly on par with the in-
         formation provided in version 1. (Arg-Required, From-Prompt)

     --proxy [<string>]
         This  option  provides  the raw proxy string which will be sent to the
         server.  The protocol prefix ("PROXY " for version 1, the 12-byte pro-
         tocol header for version 2) can be present or  not  in  the  argument.
         This  option allows sending incomplete or malformed Proxy strings to a
         target server for testing.  This option is mutually exclusive with all
         other "--proxy-*" options which provide granular proxy information.

         Because version 2 of the Proxy protocol is a  binary  protocol,  there
         are  multiple ways to provide the argument to this option.  If the ar-
         gument starts with "base64:", that prefix is stripped and the rest  of
         the  string is base64 decoded before use.  If the argument starts with
         "@" it will be treated as a filename and the proxy value will be  read
         from the file.  Any other value is assumed to be the literal value for
         the proxy string. (Arg-Required, From-Prompt, From-File)

     --proxy-family [<string>]
         For  version 1, specifies both the address family and transport proto-
         col.  The protocol defines TCP4 and TCP6.

         For version 2, specifies only the address family.   The  protocol  de-
         fines  AF_UNSPEC, AF_INET, AF_INET6, and AF_UNIX. (Arg-Required, From-
         Prompt)

     --proxy-protocol [<string>]
         For version 2, specifies the transport protocol.  The protocol defines
         UNSPEC, STREAM, and DGRAM.  The default is STREAM.  This option is un-
         used in version 1. (Arg-Required, From-Prompt)

     --proxy-command [<string>]
         For version 2, specifies the transport protocol.  The protocol defines
         LOCAL and PROXY.  The default is PROXY.  This option is unused in ver-
         sion 1. (Arg-Required, From-Prompt)

     --proxy-source [<string>]
         Specify the source address of the proxied  connection.  (Arg-Required,
         From-Prompt)

     --proxy-source-port [<string>]
         Specify  the  source  port  of  the proxied connection. (Arg-Required,
         From-Prompt)

     --proxy-dest [<string>]
         Specify the destination address of the  proxied  connection.  (Arg-Re-
         quired, From-Prompt)

     --proxy-dest-port [<string>]
         Specify the destination port of the proxied connection. (Arg-Required,
         From-Prompt)

DATA OPTIONS
     These  options  pertain  to  the contents for the DATA portion of the SMTP
     transaction.  By default a very simple message is sent.  If the "--attach"
     or "--attach-body" options are used, Swaks attempts to upgrade to  a  MIME
     message.

     -d, --data [<data-portion>]
         Use argument as the entire contents of DATA.

         If no argument is provided, user will be prompted to supply value.

         If  the  argument  "-"  is provided the data will be read from "STDIN"
         with no prompt.

         If the argument starts with "@" it will be treated as a filename.   If
         you would like to pass in an argument that starts with "@" and isn't a
         filename,  prefix  the  argument with an additional "@".  For example,
         "@file.txt" will force processing of file.txt.  @@data  will  use  the
         string '@data'.

         If  the argument does not contain any literal (0x0a) or representative
         (0x5c, 0x6e or %NEWLINE%) newline characters, it will be treated as  a
         filename.   If the file is open-able, the contents of the file will be
         used as the data portion.  If the file cannot be  opened,  Swaks  will
         error  and  exit.   The entire behavior described in this paragraph is
         deprecated and will be removed in a future  release.   Instead  use  a
         leading "@" to explicitly set that the argument is a filename.

         Any other argument will be used as the DATA contents.

         The value can be on one single line, with "\n" (ASCII 0x5c, 0x6e) rep-
         resenting  where  line  breaks should be placed.  Leading dots will be
         quoted.  Closing dot is not required  but  is  allowed.   The  default
         %FROM_ADDRESS%\nSubject:     test      %DATE%\nMessage-Id:      <%MES-
         SAGEID%>\nX-Mailer:         swaks         v%SWAKS_VERSION%        jet-
         more.org/john/code/swaks/\n%NEW_HEADERS%\n%BODY%\n".

         Very basic token parsing is performed on the DATA portion.   The  fol-
         lowing table shows the recognized tokens and their replacement values.
         (Arg-Required, From-Prompt, From-File)

         %FROM_ADDRESS%, ..FROM_ADDRESS..
             Replaced with the envelope-sender.

         %TO_ADDRESS%, ..TO_ADDRESS..
             Replaced with the envelope-recipient(s) set by the "--to" option.

         %CC_ADDRESS%, ..CC_ADDRESS..
             Replaced with the envelope-recipient(s) set by the "--cc" option.

         %BCC_ADDRESS%, ..BCC_ADDRESS..
             Replaced with the envelope-recipient(s) set by the "--bcc" option.

         %DATE%, ..DATE..
             Replaced  with the current time in a format suitable for inclusion
             ule  POSIX  for timezone calculations.  If this module is unavail-
             able or the current environment doesn't support  the  %z  strftime
             format token (as on Windows) the date string will be in GMT.

         %MESSAGEID%, ..MESSAGEID..
             Replaced with a message ID string suitable for use in a Message-Id
             header.   The  value for this token will remain consistent for the
             life of the process.

         %SWAKS_VERSION%, ..SWAKS_VERSION..
             Replaced with the version of the currently-running Swaks process.

         %NEW_HEADERS%, ..NEW_HEADERS..
             Replaced with the  contents  of  the  "--add-header"  option.   If
             "--add-header" is not specified this token is simply removed.

         %BODY%, ..BODY..
             Replaced  with  the  value  specified by the "--body" option.  See
             "--body" for default.

         %NEWLINE%, ..BODY..
             Replaced with carriage return,  newline  (0x0d,  0x0a).   This  is
             identical  to using "\n" (0x5c, 0x6e), but doesn't have the escap-
             ing concerns that the backslash can cause on the newline.

     -dab, --dump-as-body [<section>[,<section>[,...]]]
         If "--dump-as-body" is used and no other option is used to change  the
         default  body of the message, the body is replaced with output similar
         to the output of what is provided  by  "--dump".   "--dump"'s  initial
         program  capability stanza is not displayed, and the "data" section is
         not included.  Additionally, "--dump" always includes  passwords.   By
         default  "--dump-as-body"  does not include passwords, though this can
         be  changed  with  "--dump-as-body-shows-password".   "--dump-as-body"
         takes the same arguments as "--dump" except the SUPPORT and DATA argu-
         ments are not supported. (Arg-Optional)

     -dabsp, --dump-as-body-shows-password
         Cause "--dump-as-body" to include plaintext passwords.  This option is
         not recommended.  This option implies "--dump-as-body". (Arg-None)

     --body [<body-specification>]
         Specify  the  body of the email.  The default is "This is a test mail-
         ing".  If no argument to "--body" is given, prompt to supply  one  in-
         teractively.   If "-" is supplied, the body will be read from standard
         input.  Arguments beginning with "@" will be treated as filenames con-
         taining the body data to use (see "--data" for more detail).

         If, after the above processing, the argument represents  an  open-able
         file,  the  content  of that file is used as the body.  This is depre-
         cated behavior and will be removed in a future release.  Instead use a
         leading "@" to explicitly set that the argument is a filename.

         If the message is forced to MIME format (see "--attach") "--body 'body
         text'" is the same as "--attach-type  text/plain  --attach-body  'body
         text'".   See  "--attach-body" for details on creating a multipart/al-
         ternative body. (Arg-Required, From-Prompt, From-File)

     --attach [<attachment-specification>]
         When one or more "--attach" option is supplied, the message is changed
         into a multipart/mixed MIME message.  The arguments to "--attach"  are
         processed the same as "--body" with respect to "STDIN", file contents,
         etc.  "--attach" can be supplied multiple times to create multiple at-
         tachments.   By  default,  each  attachment is attached as an applica-
         tion/octet-stream file.  See "--attach-type" for changing this  behav-
         ior.

         If  the  contents  of the attachment are provided via a file name, the
         MIME encoding will include that file name.   See  "--attach-name"  for
         more detail on file naming.

         It  is legal for "-" ("STDIN") to be specified as an argument multiple
         times (once for "--body" and multiple times for "--attach").  In  this
         case,  the  same  content  will be attached each time it is specified.
         This is useful for attaching  the  same  content  with  multiple  MIME
         types. (Arg-Required, From-File)

     --attach-body [<body-specification>]
         This  is  a  variation on "--attach" that is specifically for the body
         part of the email.  It behaves identically to "--attach"  in  that  it
         takes  the  same  arguments and forces the creation of a MIME message.
         However, it is different in that the argument will always be the first
         MIME part in the message, no matter where in option  processing  order
         it is encountered.  Additionally, "--attach-body" options stack to al-
         low  creation  of  multipart/alternative  bodies.  For example, "--at-
         tach-type text/plain --attach-body  'plain  text  body'  --attach-type
         text/html --attach-body 'html body'" would create a multipart/alterna-
         tive message body. (Arg-Required, From-File)

     --attach-type <mime-type>
         By  default,  content  that  gets  MIME attached to a message with the
         "--attach" option is encoded as application/octet-stream  (except  for
         the  body,  which  is text/plain by default).  "--attach-type" changes
         the mime type for every "--attach" option which follows it.  It can be
         specified multiple times.  The current MIME type gets reset to  appli-
         cation/octet-stream  between  processing  body  parts and other parts.
         (Arg-Required)

     --attach-name [<name>]
         This option sets the filename that will be included in the  MIME  part
         created  for  the  next  "--attach" option.  If no argument is set for
         this option, it causes no filename information to be included for  the
         next  MIME  part,  even if Swaks could generate it from the local file
         name. (Arg-Optional)

     -ah, --add-header <header>
         This option allows headers to be added to the  DATA.   If  "%NEW_HEAD-
         ERS%"  is present in the DATA it is replaced with the argument to this
         option.  If "%NEW_HEADERS%" is not present, the argument  is  inserted
         between the first two consecutive newlines in the DATA (that is, it is
         inserted at the end of the existing headers).

         The  option  can  either  be specified multiple times or a single time
         with multiple  headers  separated  by  a  literal  "\n"  string.   So,
         "--add-header  'Foo:  bar'  --add-header 'Baz: foo'" and "--add-header
         'Foo: bar\nBaz: foo'" end up adding the  same  two  headers.  (Arg-Re-
         quired)

     --header <header-and-data>, --h-<header> <data>
         These  options allow a way to change headers that already exist in the
         DATA.  "--header 'Subject: foo'" and "--h-Subject foo" are equivalent.
         If the header does not already exist in the data  then  this  argument
         behaves identically to "--add-header".  However, if the header already
         exists it is replaced with the one specified.  Negating the version of
         this  option  with the header name in the option (eg "--no-header-Sub-
         ject") will remove all previously processed  "--header"  options,  not
         just the ones used for 'Subject'. Embedding the header name in the op-
         tion via environment variable is not supported on Windows and will re-
         sult in an error. (Arg-Required)

     -g  This  option is a direct alias to "--data -" (read DATA from "STDIN").
         It is totally secondary to "--data".  Any occurrence of "--data"  will
         cause  "-g"  to  be  ignored.   This option cannot be negated with the
         "no-" prefix.  This option is deprecated and will be removed in a  fu-
         ture version of Swaks. (Arg-None, Deprecated)

     --no-data-fixup, -ndf
         This option forces Swaks to do no massaging of the DATA portion of the
         email.  This includes token replacement, From_ stripping, trailing-dot
         addition,  "--body"/attachment  inclusion,  and  any header additions.
         This option is only useful when used with "--data", since the internal
         default DATA portion uses tokens. (Arg-None)

     --no-strip-from, -nsf
         Don't strip the From_ line from the DATA portion,  if  present.  (Arg-
         None)

OUTPUT OPTIONS
     Swaks  provides  a  transcript  of  its  transactions to its caller ("STD-
     OUT"/"STDERR") by default.  This transcript aims to be as faithful a  rep-
     resentation as possible of the transaction though it does modify this out-
     put  by  adding informational prefixes to lines and by providing plaintext
     versions of TLS transactions

     The "informational prefixes" are referred to as transaction hints.   These
     hints  are  initially  composed  of those marking lines that are output of
     Swaks itself, either informational or error messages, and those that indi-
     cate a line of data actually sent or received in a transaction.  This  ta-
     ble indicates the hints and their meanings:

     "==="
         Indicates an informational line generated by Swaks.

     "***"
         Indicates an error generated within Swaks.

     " ->"
         Indicates an expected line sent by Swaks to target server.

     " ~>"
         Indicates  a  TLS-encrypted,  expected  line  sent  by Swaks to target
         server.

     "**>"
         Indicates an unexpected line sent by Swaks to the target server.

     "*~>"
         Indicates a TLS-encrypted, unexpected line sent  by  Swaks  to  target
         server.

     "  >"
         Indicates  a  raw  chunk of text sent by Swaks to a target server (see
         "--show-raw-text").  There is no concept of "expected" or "unexpected"
         at this level.

     "<- "
         Indicates an expected line sent by target server to Swaks.

     "<~ "
         Indicates a TLS-encrypted, expected line  sent  by  target  server  to
         Swaks.

     "<**"
         Indicates an unexpected line sent by target server to Swaks.

     "<~*"
         Indicates  a  TLS-encrypted,  unexpected line sent by target server to
         Swaks.

     "<  "
         Indicates a raw chunk of text received by Swaks from a  target  server
         (see  "--show-raw-text").  There is no concept of "expected" or "unex-
         pected" at this level.

     The following options control what and how  output  is  displayed  to  the
     caller.

     -n, --suppress-data
         Summarizes  the DATA portion of the SMTP transaction instead of print-
         ing every line.  This option is very helpful, bordering  on  required,
         when  using  Swaks  to  send certain test emails.  Emails with attach-
         ments, for instance, will quickly overwhelm a terminal if the DATA  is
         not suppressed. (Arg-None)

     -stl, --show-time-lapse [i]
         Display  time  lapse  between send/receive pairs.  This option is most
         useful when Time::HiRes is available, in which  case  the  time  lapse
         will  be  displayed in thousandths of a second.  If Time::HiRes is un-
         available or "i" is given as an argument the lapse will  be  displayed
         in integer seconds only. (Arg-Optional)

         Don't  display  the  transaction  hint for informational transactions.
         This is most useful when needing to copy some portion of the  informa-
         tional    lines,    for   instance   the   certificate   output   from
         "--tls-get-peer-cert". (Arg-None)

     -nih, --no-info-hints
     -nsh, --no-send-hints
     -nrh, --no-receive-hints
     -nth, --no-hints
         "--no-info-hints", "--no-send-hints",  and  "--no-receive-hints"  sup-
         press  the  transaction  hints from info, send, and receive lines, re-
         spectively.  This is often useful when copying  some  portion  of  the
         transaction   for   use   elsewhere  (for  instance,  "--no-send-hints
         --hide-receive --hide-informational" is a useful way to get  only  the
         client-side  commands  for  a  given  transaction and "--no-info-hints
         --tls-get-peer-cert" for copying the peer certificate).   "--no-hints"
         is  identical  to specifying "--no-info-hints --no-send-hints --no-re-
         ceive-hints". (Arg-None)

     -raw, --show-raw-text
         This option will print a hex dump of raw data  sent  and  received  by
         Swaks.  Each hex dump is the contents of a single read or write on the
         network.   This should be identical to what is already being displayed
         (with the exception of the "\r" characters being removed).   This  op-
         tion is useful in seeing details when servers are sending lots of data
         in single packets, or breaking up individual lines into multiple pack-
         ets.   If  you really need to go in depth in that area you're probably
         better with a packet sniffer, but this option is a good first step  to
         seeing odd connection issues. (Arg-None)

     --output, --output-file <file-path>
     --output-file-stdout <file-path>
     --output-file-stderr <file-path>
         These  options allow the user to send output to files instead of "STD-
         OUT"/"STDERR".  The first option sends both to the same file.  The ar-
         guments of &STDOUT and &STDERR are treated specially, referring to the
         "normal" file handles, so "--output-file-stderr '&STDOUT'" would redi-
         rect "STDERR" to "STDOUT".  These options are honored for  all  output
         except "--help" and "--version". (Arg-Required)

     -pp, --protect-prompt
         Don't echo user input on prompts that are potentially sensitive (right
         now  only  authentication  password).   Very  specifically, any option
         which is marked 'Sensitive' and eventually  prompts  for  an  argument
         will  do  its  best to mask that argument from being echoed.  See also
         "--auth-hide-password". (Arg-None)

     -hr, --hide-receive
         Don't display lines sent from the  remote  server  being  received  by
         Swaks. (Arg-None)

     -hs, --hide-send
         Don't  display  lines  being sent by Swaks to the remote server. (Arg-
         None)

     -hi, --hide-informational
         Don't display non-error informational lines from Swaks  itself.  (Arg-
         None)

     -ha, --hide-all
         Do not display any content to the terminal. (Arg-None)

     -S, --silent [ 1 | 2 | 3 ]
         Cause  Swaks  to be silent.  If no argument is given or if an argument
         of "1" is given, print no output unless/until an error  occurs,  after
         which all output is shown.  If an argument of "2" is given, only print
         errors.   If  "3"  is  given, show no output ever.  "--silent" affects
         most  output  but  not  all.   For  instance,  "--help",  "--version",
         "--dump", and "--dump-mail" are not affected.  For historical reasons,
         -S   is   not  settable  via  environment  variable  on  Windows,  use
         SWAKS_OPT_silent instead. (Arg-Optional)

     --support
         Print capabilities and exit.  Certain  features  require  non-standard
         Perl modules.  This option evaluates whether these modules are present
         and  displays  which  functionality  is available and which isn't, and
         which modules would need to be added to gain the  missing  functional-
         ity. (Arg-None)

     --dump-mail
         Cause  Swaks  to  process all options to generate the message it would
         send, then print that message to "STDOUT" instead of sending it.  This
         output is identical to the "data" section of "--dump", except  without
         the trailing dot. (Arg-None)

     --dump [<section>[,<section>[,...]]]
         This  option  causes  Swaks to print the results of option processing,
         immediately before mail would have been sent.  No mail  will  be  sent
         when  "--dump"  is  used.  Note that "--dump" is a pure self-diagnosis
         tool and no effort is made or will ever be made to mask  passwords  in
         the  "--dump"  output. If a section is provided as an argument to this
         option, only the requested section will be shown.  Currently supported
         arguments are SUPPORT,  APP,  OUTPUT,  TRANSPORT,  PROTOCOL,  XCLIENT,
         PROXY, TLS, AUTH, DATA, and ALL.  If no argument is provided, all sec-
         tions are displayed (Arg-Optional)

     --help
         Display this help information and exit. (Arg-None)

     --version
         Display version information and exit. (Arg-None)

DEPRECATIONS
     The following features are deprecated and will be removed in a future ver-
     sion of Swaks

     use of IO::Socket and IO::Socket::INET6 modules
         Will be removed no sooner than (February 1, 2025).

         The  primary  method  of  sending over IPv4 and IPv6 sockets is imple-
         mented with the IO::Socket::IP module.  For the time  being  there  is
         still  legacy  support of the IO::Socket and IO::Socket::INET6 modules
         which were previously used.  Please ensure IO::Socket::IP is installed
         to ensure future functionality.

PORTABILITY
     OPERATING SYSTEMS
         This program was primarily intended for  use  on  UNIX-like  operating
         systems, and it should work on any reasonable version thereof.  It has
         been  developed and tested on Solaris, Linux, and Mac OS X and is fea-
         ture complete on all of these.

         This program is known to demonstrate basic  functionality  on  Windows
         using  Strawberry Perl.  In all documentation, unless otherwise noted,
         "Windows" refers to running Swaks via CMD.exe, not WSL or cygwin.   It
         has  not been fully tested, but known to work are basic SMTP function-
         ality and the LOGIN, PLAIN, and CRAM-MD5 auth types.  Unknown  is  any
         TLS  functionality  and  the NTLM/SPA and DIGEST-MD5 auth types.  Some
         functionality is known to be limited on Windows,  including  inability
         to  embed header name in environment variables (see "CONFIGURATION EN-
         VIRONMENT VARIABLES" and "--header"), inability to generate  a  local-
         timezone date string (see "%DATE%" token under "--data"), inability to
         use  "-S"  option as an environment variable (see "--silent"), and in-
         ability to have a "set but empty" value  in  an  environment  variable
         (see "CONFIGURATION ENVIRONMENT VARIABLES" for workaround).

         Because this program should work anywhere Perl works, I would appreci-
         ate  knowing  about  any  new operating systems you've thoroughly used
         Swaks on as well as any problems encountered on a new OS.

     MAIL SERVERS
         This program  was  almost  exclusively  developed  against  Exim  mail
         servers.   It  has  been used casually by the author, though not thor-
         oughly tested, with Sendmail, Smail,  Exchange,  Oracle  Collaboration
         Suite,  qpsmtpd,  and Communigate.  Because all functionality in Swaks
         is based on known standards it should work with any fairly modern mail
         server.  If a problem is found, please alert the author at the address
         below.

ENVIRONMENT VARIABLES
     LOGNAME
         If Swaks must create a sender address, $LOGNAME is used as the message
         local-part if it is set, and unless "--force-getpwuid" is used.

     SWAKS_HOME
         Used when searching for a .swaksrc  configuration  file.   See  OPTION
         PROCESSING -> "CONFIGURATION FILES" above.

     SWAKS_OPT_*
         Environment  variable  prefix used to specify Swaks options from envi-
         ronment variables.  See OPTION PROCESSING ->  "CONFIGURATION  ENVIRON-
         MENT VARIABLES" above.

EXIT CODES
     0   no errors occurred

     1   error parsing command line options

     2   error connecting to remote server

     3   unknown connection type

     4   while running with connection type of "pipe", fatal problem writing to
         or reading from the child process

     5   while running with connection type of "pipe", child process died unex-
         pectedly.   This  can  mean  that  the program specified with "--pipe"
         doesn't exist.

     6   Connection closed unexpectedly.  If the close is detected in  response
         to  the 'QUIT' Swaks sends following an unexpected response, the error
         code for that unexpected response is used instead.  For instance, if a
         mail server returns a 550 response to a MAIL FROM:  and  then  immedi-
         ately  closes  the  connection,  Swaks  detects that the connection is
         closed, but uses the more specific exit code 23 to detail  the  nature
         of  the failure.  If instead the server return a 250 code and then im-
         mediately closes the connection, Swaks will use the exit  code  6  be-
         cause there is not a more specific exit code.

     10  error in prerequisites (needed module not available)

     21  error reading initial banner from server

     22  error in HELO transaction

     23  error in MAIL transaction

     24  no RCPTs accepted

     25  server returned error to DATA request

     26  server did not accept mail following data

     27  server returned error after normal-session quit request

     28  error in AUTH transaction

     29  error in TLS transaction

     30  PRDR requested/required but not advertised

     32  error in EHLO following TLS negotiation

     33  error in XCLIENT transaction

     34  error in EHLO following XCLIENT

     35  error in PROXY option processing

     36  error sending PROXY banner

ABOUT THE NAME
     The  name  "Swaks" is a (sort-of) acronym for "SWiss Army Knife SMTP".  It
     was chosen to be fairly distinct  and  pronounceable.   While  "Swaks"  is
     unique  as the name of a software package, it has some other, non-software
     meanings.  Please send in other uses of "swak" or "swaks" for inclusion.

     "Sealed With A Kiss"
         SWAK/SWAKs turns up occasionally on  the  internet  with  the  meaning
         "with love".

     bad / poor / ill (Afrikaans)
         Seen  in the headline "SA se bes en swaks gekledes in 2011", which was
         translated as "best and worst dressed"  by  native  speakers.   Google
         Translate  doesn't like "swaks gekledes", but it will translate "swak"
         as "poor" and "swak geklede" as "ill-dressed".

LICENSE
     This program is free software; you can redistribute it  and/or  modify  it
     under the terms of the GNU General Public License as published by the Free
     Software  Foundation; either version 2 of the License, or (at your option)
     any later version.

     This program is distributed in the hope that it will be useful, but  WITH-
     OUT  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
     FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License  for
     more details.

     You  should  have  received a copy of the GNU General Public License along
     with this program; if not, write to the Free Software Foundation, Inc., 51
     Franklin St, Fifth Floor, Boston, MA 02110-1301, USA.

CONTACT INFORMATION
     General contact, questions,  patches,  requests,  etc  to  proj-swaks@jet-
     more.net.

     Change   logs,   this   help,   and   the  latest  version  are  found  at
     <http://www.jetmore.org/john/code/swaks/>.

     Swaks is crafted with love by John Jetmore from the cornfields of Indiana,
     United States of America.

NOTIFICATIONS
     Email
[email protected]
If you would like to be put on a list to receive notifications when  a
         new  version  of  Swaks  is released, please send an email to this ad-
         dress.  There will not be a response to your email.

     Website
         <http://www.jetmore.org/john/blog/c/swaks/>

     RSS Feed
         <http://www.jetmore.org/john/blog/c/swaks/feed/>

     Twitter
         <http://twitter.com/SwaksSMTP>

perl v5.40.0                       2024-12-07                          SWAKS(1)
```

Updated on: 2026-May-25

### tnscmd10g

Source: https://www.kali.org/tools/tnscmd10g/

#### Tool Documentation:



#### Tool Documentation:

#### tnscmd10g Usage Example

Retrieve the version ( version ) from the target server ( -h 192.168.1.205 ):

```
root@kali:~# tnscmd10g version -h 192.168.1.205
sending (CONNECT_DATA=(COMMAND=version)) to 192.168.1.205:1521
writing 90 bytes
reading
.M.......6.........-. ..........(DESCRIPTION=(TMP=)(VSNNUM=153092352)(ERR=0)).7........TNSLSNR for 32-bit Windows: Version 9.2.0.1.0 - Production..TNS for 32-bit Windows: Version 9.2.0.1.0 - Production..Windows NT Named Pipes NT Protocol Adapter for 32-bit Windows: Version 9.2.0.1.0 - Production..Windows NT TCP/IP NT Protocol Adapter for 32-bit Windows: Version 9.2.0.1.0 - Production,,.........@
```


#### tnscmd10g

Tool to prod the oracle tnslsnr process A tool to prod the oracle tnslsnr process
on port 1521/tcp.
Installed size: 18 KB How to install: sudo apt install tnscmd10g
- libio-socket-ip-perl
- perl

##### tnscmd10g

```
root@kali:~# tnscmd10g -h
usage: /usr/bin/tnscmd10g [command] -h hostname
       where 'command' is something like ping, version, status, etc.  
       (default is ping)
       [-p port] - alternate TCP port to use (default is 1521)
       [--logfile logfile] - write raw packets to specified logfile
       [--indent] - indent & outdent on parens
       [--10G] - make it work against 10G
       [--rawcmd command] - build your own CONNECT_DATA string
       [--cmdsize bytes] - fake TNS command size (reveals packet leakage)
```

Updated on: 2026-Mar-02

### wfuzz

Source: https://www.kali.org/tools/wfuzz/

#### Tool Documentation:



#### Tool Documentation:

#### wfuzz Usage Example

Use colour output ( -c ), a wordlist as a payload ( -z file,/usr/share/wfuzz/wordlist/general/common.txt ), and hide 404 messages ( –hc 404 ) to fuzz the given URL ( http://192.168.1.202/FUZZ ):

```
root@kali:~# wfuzz -c -z file,/usr/share/wfuzz/wordlist/general/common.txt --hc 404 http://192.168.1.202/FUZZ

********************************************************
* Wfuzz 2.2.11 - The Web Fuzzer                        *
********************************************************

Target: http://192.168.1.202/FUZZ
Payload type: file,/usr/share/wfuzz/wordlist/general/common.txt

Total requests: 950
==================================================================
ID  Response   Lines      Word         Chars          Request
==================================================================

00429:  C=200      4 L        25 W      177 Ch    " - index"
00466:  C=301      9 L        28 W      319 Ch    " - javascript"
```


#### wfuzz

Web application bruteforcer Wfuzz is a tool designed for bruteforcing Web Applications,
it can be used for finding resources not linked
directories, servlets, scripts, etc, bruteforce GET and
POST parameters for checking different kind of injections
(SQL, XSS, LDAP,etc), bruteforce Forms parameters
(User/Password), Fuzzing, etc.
Installed size: 1.54 MB How to install: sudo apt install wfuzz
- python3
- python3-chardet
- python3-legacy-cgi
- python3-pycurl
- python3-pyparsing

##### wfuzz

A web application bruteforcer

```
root@kali:~# wfuzz --help
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
*                                                      *
* Version up to 1.4c coded by:                         *
* Christian Martorella (
[email protected]
) *
* Carlos del ojo (
[email protected]
)                   *
*                                                      *
* Version 1.4d to 3.1.0 coded by:                      *
* Xavier Mendez (
[email protected]
)            *
********************************************************

Usage:	wfuzz [options] -z payload,params <url>

	FUZZ, ..., FUZnZ  wherever you put these keywords wfuzz will replace them with the values of the specified payload.
	FUZZ{baseline_value} FUZZ will be replaced by baseline_value. It will be the first request performed and could be used as a base for filtering.

Options:
	-h/--help                 : This help
	--help                    : Advanced help
	--filter-help             : Filter language specification
	--version                 : Wfuzz version details
	-e <type>                 : List of available encoders/payloads/iterators/printers/scripts
	
	--recipe <filename>       : Reads options from a recipe. Repeat for various recipes.
	--dump-recipe <filename>  : Prints current options as a recipe
	--oF <filename>           : Saves fuzz results to a file. These can be consumed later using the wfuzz payload.
	
	-c                        : Output with colors
	-v                        : Verbose information.
	-f filename,printer       : Store results in the output file using the specified printer (raw printer if omitted).
	-o printer                : Show results using the specified printer.
	--interact                : (beta) If selected,all key presses are captured. This allows you to interact with the program.
	--dry-run                 : Print the results of applying the requests without actually making any HTTP request.
	--prev                    : Print the previous HTTP requests (only when using payloads generating fuzzresults)
	--efield <expr>           : Show the specified language expression together with the current payload. Repeat for various fields.
	--field <expr>            : Do not show the payload but only the specified language expression. Repeat for various fields.
	
	-p addr                   : Use Proxy in format ip:port:type. Repeat option for using various proxies.
	                            Where type could be SOCKS4,SOCKS5 or HTTP if omitted.
	
	-t N                      : Specify the number of concurrent connections (10 default)
	-s N                      : Specify time delay between requests (0 default)
	-R depth                  : Recursive path discovery being depth the maximum recursion level.
	-D depth                  : Maximum link depth level.
	-L,--follow               : Follow HTTP redirections
	--ip host:port            : Specify an IP to connect to instead of the URL's host in the format ip:port
	-Z                        : Scan mode (Connection errors will be ignored).
	--req-delay N             : Sets the maximum time in seconds the request is allowed to take (CURLOPT_TIMEOUT). Default 90.
	--conn-delay N            : Sets the maximum time in seconds the connection phase to the server to take (CURLOPT_CONNECTTIMEOUT). Default 90.
	
	-A, --AA, --AAA           : Alias for -v -c and --script=default,verbose,discover respectively
	--no-cache                : Disable plugins cache. Every request will be scanned.
	--script=                 : Equivalent to --script=default
	--script=<plugins>        : Runs script's scan. <plugins> is a comma separated list of plugin-files or plugin-categories
	--script-help=<plugins>   : Show help about scripts.
	--script-args n1=v1,...   : Provide arguments to scripts. ie. --script-args grep.regex="<A href=\"(.*?)\">"
	
	-u url                    : Specify a URL for the request.
	-m iterator               : Specify an iterator for combining payloads (product by default)
	-z payload                : Specify a payload for each FUZZ keyword used in the form of name[,parameter][,encoder].
	                            A list of encoders can be used, ie. md5-sha1. Encoders can be chained, ie. md5@sha1.
	                            Encoders category can be used. ie. url
	                            Use help as a payload to show payload plugin's details (you can filter using --slice)
	--zP <params>             : Arguments for the specified payload (it must be preceded by -z or -w).
	--zD <default>            : Default parameter for the specified payload (it must be preceded by -z or -w).
	--zE <encoder>            : Encoder for the specified payload (it must be preceded by -z or -w).
	--slice <filter>          : Filter payload's elements using the specified expression. It must be preceded by -z.
	-w wordlist               : Specify a wordlist file (alias for -z file,wordlist).
	-V alltype                : All parameters bruteforcing (allvars and allpost). No need for FUZZ keyword.
	-X method                 : Specify an HTTP method for the request, ie. HEAD or FUZZ
	
	-b cookie                 : Specify a cookie for the requests. Repeat option for various cookies.
	-d postdata               : Use post data (ex: "id=FUZZ&catalogue=1")
	-H header                 : Use header (ex:"Cookie:id=1312321&user=FUZZ"). Repeat option for various headers.
	--basic/ntlm/digest auth  : in format "user:pass" or "FUZZ:FUZZ" or "domain\FUZ2Z:FUZZ"
	
	--hc/hl/hw/hh N[,N]+      : Hide responses with the specified code/lines/words/chars (Use BBB for taking values from baseline)
	--sc/sl/sw/sh N[,N]+      : Show responses with the specified code/lines/words/chars (Use BBB for taking values from baseline)
	--ss/hs regex             : Show/hide responses with the specified regex within the content
	--filter <filter>         : Show/hide responses using the specified filter expression (Use BBB for taking values from baseline)
	--prefilter <filter>      : Filter items before fuzzing using the specified expression. Repeat for concatenating filters.
```

#### Learn more with OffSec

Want to learn more about wfuzz? get access to in-depth training and hands-on labs:
- WEB-200: 8.2.5. SQL Injection: Fuzzing
- WEB-200: 9.5.3. Directory Traversal Attacks: Fuzzing the Path Parameter
WEB-200 course
Updated on: 2025-Dec-09

### whatweb

Source: https://www.kali.org/tools/whatweb/

#### Tool Documentation:



#### Tool Documentation:

#### WhatWeb Usage Example

```
root@kali:~# whatweb -v -a 3 192.168.0.102
WhatWeb report for http://192.168.0.102
Status    : 200 OK
Title     : Toolz TestBed
IP        : 192.168.0.102
Country   : RESERVED, ZZ

Summary   : JQuery, Script, X-UA-Compatible[IE=edge], HTML5, Apache[2.2,2.2.22], HTTPServer[Ubuntu Linux][Apache/2.2.22 (Ubuntu)]

Detected Plugins:
[ Apache ]
  The Apache HTTP Server Project is an effort to develop and
  maintain an open-source HTTP server for modern operating
  systems including UNIX and Windows NT. The goal of this
  project is to provide a secure, efficient and extensible
  server that provides HTTP services in sync with the current
  HTTP standards.

  Version      : 2.2.22 (from HTTP Server Header)
  Version      : 2.2
  Version      : 2.2
  Google Dorks: (3)
  Website     : http://httpd.apache.org/

[ HTML5 ]
  HTML version 5, detected by the doctype declaration

[ HTTPServer ]
  HTTP server header string. This plugin also attempts to
  identify the operating system from the server header.

  OS           : Ubuntu Linux
  String       : Apache/2.2.22 (Ubuntu) (from server string)

[ JQuery ]
  A fast, concise, JavaScript that simplifies how to traverse
  HTML documents, handle events, perform animations, and add
  AJAX.

  Website     : http://jquery.com/

[ Script ]
  This plugin detects instances of script HTML elements and
  returns the script language/type.

[ X-UA-Compatible ]
  This plugin retrieves the X-UA-Compatible value from the
  HTTP header and meta http-equiv tag. - More Info:
  http://msdn.microsoft.com/en-us/library/cc817574.aspx

  String       : IE=edge

HTTP Headers:
  HTTP/1.1 200 OK
  Server: Apache/2.2.22 (Ubuntu)
  Last-Modified: Fri, 02 Feb 2018 15:27:56 GMT
  ETag: "11f-2e38-5643c5b56a8d3"
  Accept-Ranges: bytes
  Vary: Accept-Encoding
  Content-Encoding: gzip
  Content-Length: 3541
  Connection: close
  Content-Type: text/html

root@kali:~#
```


#### whatweb

Next generation web scanner WhatWeb identifies websites. It recognises web technologies including
content management systems (CMS), blogging platforms, statistic/analytics
packages, JavaScript libraries, web servers, and embedded devices.
WhatWeb has over 900 plugins, each to recognise something different.
It also identifies version numbers, email addresses, account IDs,
web framework modules, SQL errors, and more.
Installed size: 18.76 MB How to install: sudo apt install whatweb
- ruby
- ruby-addressable
- ruby-ipaddress

##### whatweb

Next generation Web scanner. Identify technologies used by websites.

```
root@kali:~# whatweb -h

.$$$     $.                                   .$$$     $.
$$$$     $$. .$$$  $$$ .$$$$$$.  .$$$$$$$$$$. $$$$     $$. .$$$$$$$. .$$$$$$.
$ $$     $$$ $ $$  $$$ $ $$$$$$. $$$$$ $$$$$$ $ $$     $$$ $ $$   $$ $ $$$$$$.
$ `$     $$$ $ `$  $$$ $ `$  $$$ $$' $ `$ `$$ $ `$     $$$ $ `$      $ `$  $$$'
$. $     $$$ $. $$$$$$ $. $$$$$$ `$  $. $  :' $. $     $$$ $. $$$$   $. $$$$$.
$::$  .  $$$ $::$  $$$ $::$  $$$     $::$     $::$  .  $$$ $::$      $::$  $$$$
$;;$ $$$ $$$ $;;$  $$$ $;;$  $$$     $;;$     $;;$ $$$ $$$ $;;$      $;;$  $$$$
$$$$$$ $$$$$ $$$$  $$$ $$$$  $$$     $$$$     $$$$$$ $$$$$ $$$$$$$$$ $$$$$$$$$'

WhatWeb - Next generation web scanner version 0.6.4.
Developed by Andrew Horton (urbanadventurer) and Brendan Coles (bcoles).
Homepage: https://morningstarsecurity.com/research/whatweb

Usage: whatweb [options] <URLs>

TARGET SELECTION:
  <TARGETs>			Enter URLs, hostnames, IP addresses, filenames or
  				IP ranges in CIDR, x.x.x-x, or x.x.x.x-x.x.x.x
  				format.
  --input-file=FILE, -i		Read targets from a file. You can pipe
				hostnames or URLs directly with -i /dev/stdin.

TARGET MODIFICATION:
  --url-prefix			Add a prefix to target URLs.
  --url-suffix			Add a suffix to target URLs.
  --url-pattern			Insert the targets into a URL.
				e.g. example.com/%insert%/robots.txt

AGGRESSION:
The aggression level controls the trade-off between speed/stealth and
reliability.
  --aggression, -a=LEVEL	Set the aggression level. Default: 1.
  1. Stealthy			Makes one HTTP request per target and also
  				follows redirects.
  3. Aggressive			If a level 1 plugin is matched, additional
  				requests will be made.
  4. Heavy			Makes a lot of HTTP requests per target. URLs
  				from all plugins are attempted.

HTTP OPTIONS:
  --user-agent, -U=AGENT	Identify as AGENT instead of WhatWeb/0.6.4.
  --header, -H			Add an HTTP header. eg "Foo:Bar". Specifying a
				default header will replace it. Specifying an
				empty value, e.g. "User-Agent:" will remove it.
  --follow-redirect=WHEN	Control when to follow redirects. WHEN may be
				`never', `http-only', `meta-only', `same-site',
				or `always'. Default: always.
  --max-redirects=NUM		Maximum number of redirects. Default: 10.

AUTHENTICATION:
  --user, -u=<user:password>	HTTP basic authentication.
  --cookie, -c=COOKIES		Use cookies, e.g. 'name=value; name2=value2'.
  --cookie-jar=FILE		Read cookies from a file and save cookies to the
				same file. Creates the file if it doesn't exist.
  --no-cookies			Disable automatic cookie handling (improves performance with high thread counts).

PROXY:
  --proxy			<hostname[:port]> Set proxy hostname and port.
				Default: 8080.
  --proxy-user			<username:password> Set proxy user and password.

PLUGINS:
  --list-plugins, -l		List all plugins.
  --info-plugins, -I=[SEARCH]	List all plugins with detailed information.
				Optionally search with keywords in a comma
				delimited list.
  --search-plugins=STRING	Search plugins for a keyword.
  --plugins, -p=LIST		Select plugins. LIST is a comma delimited set
				of selected plugins. Default is all.
				Each element can be a directory, file or plugin
				name and can optionally have a modifier, +/-.
				Examples: +/tmp/moo.rb,+/tmp/foo.rb
				title,md5,+./plugins-disabled/
				./plugins-disabled,-md5
				-p + is a shortcut for -p +plugins-disabled.
  --grep, -g=STRING|REGEXP	Search for STRING or a Regular Expression. Shows
				only the results that match.
				Examples: --grep "hello"
				--grep "/he[l]*o/"
  --custom-plugin=DEFINITION	Define a custom plugin named Custom-Plugin,
				Examples: ":text=>'powered by abc'"
				":version=>/powered[ ]?by ab[0-9]/"
				":ghdb=>'intitle:abc \"powered by abc\"'"
				":md5=>'8666257030b94d3bdb46e05945f60b42'"
				"{:text=>'powered by abc'}"
  --dorks=PLUGIN		List Google dorks for the selected plugin.

OUTPUT:
  --verbose, -v			Verbose output includes plugin descriptions.
				Use twice for debugging.
  --colour,--color=WHEN		control whether colour is used. WHEN may be
				`never', `always', or `auto'.
  --quiet, -q			Do not display brief logging to STDOUT.
  --no-errors			Suppress error messages.

LOGGING:
  --log-brief=FILE		Log brief, one-line output.
  --log-verbose=FILE		Log verbose output.
  --log-errors=FILE		Log errors.
  --log-xml=FILE		Log XML format.
  --log-json=FILE		Log JSON format.
  --log-sql=FILE		Log SQL INSERT statements.
  --log-sql-create=FILE		Create SQL database tables.
  --log-json-verbose=FILE	Log JSON Verbose format.
  --log-magictree=FILE		Log MagicTree XML format.
  --log-object=FILE		Log Ruby object inspection format.
  --log-mongo-database		Name of the MongoDB database.
  --log-mongo-collection	Name of the MongoDB collection.
				Default: whatweb.
  --log-mongo-host		MongoDB hostname or IP address.
				Default: 0.0.0.0.
  --log-mongo-username		MongoDB username. Default: nil.
  --log-mongo-password		MongoDB password. Default: nil.
  --log-elastic-index		Name of the index to store results. Default: whatweb
  --log-elastic-host		Host:port of the elastic http interface. Default: 127.0.0.1:9200

PERFORMANCE & STABILITY:
  --max-threads, -t		Number of simultaneous threads. Default: 25.
  --open-timeout		Time in seconds. Default: 15.
  --read-timeout		Time in seconds. Default: 30.
  --wait=SECONDS		Wait SECONDS between connections.
				This is useful when using a single thread.
  --output-sync			Force immediate output flushing for real-time
				monitoring (slower with high thread counts).
  --output-buffer-size=SIZE	Set output buffer size. 0=unbuffered,
				default=auto based on thread count.

HELP & MISCELLANEOUS:
  --short-help			Short usage help.
  --help, -h			Complete usage help.
  --debug			Raise errors in plugins.
  --version			Display version information.

EXAMPLE USAGE:
* Scan example.com.
  ./whatweb example.com

* Scan reddit.com slashdot.org with verbose plugin descriptions.
  ./whatweb -v reddit.com slashdot.org

* An aggressive scan of wired.com detects the exact version of WordPress.
  ./whatweb -a 3 www.wired.com

* Scan the local network quickly and suppress errors.
  whatweb --no-errors 192.168.0.0/24

* Scan the local network for https websites.
  whatweb --no-errors --url-prefix https:// 192.168.0.0/24

* Scan for crossdomain policies in the Alexa Top 1000.
  ./whatweb -i plugin-development/alexa-top-100.txt \
  --url-suffix /crossdomain.xml -p crossdomain_xml
```

#### Learn more with OffSec

Want to learn more about whatweb? get access to in-depth training and hands-on labs:
- PEN-200: 27.1.2. Assembling the Pieces: WEBSRV1
PEN-200 course
Updated on: 2026-May-25

### whois

Source: https://www.kali.org/tools/whois/

#### whois

Intelligent WHOIS client This package provides a commandline client for the WHOIS (RFC 3912)
protocol, which queries online servers for information such as contact
details for domains and IP address assignments.
It can intelligently select the appropriate WHOIS server for most queries.
The package also contains mkpasswd, a features-rich front end to the
password encryption function crypt(3).
Installed size: 384 KB How to install: sudo apt install whois
- libc6
- libcrypt1
- libidn2-0

##### mkpasswd

Overfeatured front end to crypt(3)

```
root@kali:~# mkpasswd -h
Usage: mkpasswd [OPTIONS]... [PASSWORD [SALT]]
Crypts the PASSWORD using crypt(3).

      -m, --method=TYPE     select method TYPE
      -5                    like --method=md5crypt
      -S, --salt=SALT       use the specified SALT
      -R, --rounds=NUMBER   use the specified NUMBER of rounds
      -P, --password-fd=NUM read the password from file descriptor NUM
                            instead of /dev/tty
      -s, --stdin           like --password-fd=0
      -h, --help            display this help and exit
      -V, --version         output version information and exit

If PASSWORD is missing then it is asked interactively.
If no SALT is specified, a random one is generated.
If TYPE is 'help', available methods are printed.

Report bugs to <
[email protected]
>.
```

##### whois

Client for the whois directory service

```
root@kali:~# whois --help
Usage: whois [OPTION]... OBJECT...

-h HOST, --host HOST   connect to server HOST
-p PORT, --port PORT   connect to PORT
-I                     query whois.iana.org and follow its referral
-H                     hide legal disclaimers
      --verbose        explain what is being done
      --no-recursion   disable recursion from registry to registrar servers
      --help           display this help and exit
      --version        output version information and exit

These flags are supported by whois.ripe.net and some RIPE-like servers:
-l                     find the one level less specific match
-L                     find all levels less specific matches
-m                     find all one level more specific matches
-M                     find all levels of more specific matches
-c                     find the smallest match containing a mnt-irt attribute
-x                     exact match
-b                     return brief IP address ranges with abuse contact
-B                     turn off object filtering (show email addresses)
-G                     turn off grouping of associated objects
-d                     return DNS reverse delegation objects too
-i ATTR[,ATTR]...      do an inverse look-up for specified ATTRibutes
-T TYPE[,TYPE]...      only look for objects of TYPE
-K                     only primary keys are returned
-r                     turn off recursive look-ups for contact information
-R                     force to show local copy of the domain object even
                       if it contains referral
-a                     also search all the mirrored databases
-s SOURCE[,SOURCE]...  search the database mirrored from SOURCE
-g SOURCE:FIRST-LAST   find updates from SOURCE from serial FIRST to LAST
-t TYPE                request template for object of TYPE
-v TYPE                request verbose template for object of TYPE
-q [version|sources|types]  query specified server info
```

#### Learn more with OffSec

Want to learn more about whois? get access to in-depth training and hands-on labs:
- PEN-200: 6.2.1. Information Gathering: Whois Enumeration
PEN-200 course
Updated on: 2026-Mar-02

### xspy

Source: https://www.kali.org/tools/xspy/

#### Tool Documentation:



#### Tool Documentation:

#### xspy Usage Example

```
root@kali:~# xspy
opened :0.0 for snoopng

id
idBackSpaceBackSpacels
whoami
```


#### xspy

X server sniffer Sniffs keystrokes on remote or local
X-Windows servers.
Installed size: 25 KB How to install: sudo apt install xspy
- libc6
- libx11-6

##### xspy

```
root@kali:~# xspy -h
xspy: can't open display -h:0
blah....
```

Updated on: 2026-Mar-02

### tools that require a subcommand

Flagged so a caller — or a model drafting one — puts the
subcommand before the flags:

- `gobuster`: dir, dns, fuzz, gcs, s3, tftp, vhost

### tools whose fetch failed

Reported rather than dropped: a silent omission here reads as "no such tool".

- ajpycat: https://www.kali.org/tools/ajpycat/ returned HTTP 404
- alterx: https://www.kali.org/tools/alterx/ returned HTTP 404
- avahi-browse: https://www.kali.org/tools/avahi-browse/ returned HTTP 404
- coap-client: https://www.kali.org/tools/coap-client/ returned HTTP 404
- cqlsh: https://www.kali.org/tools/cqlsh/ returned HTTP 404
- dig: https://www.kali.org/tools/dig/ returned HTTP 404
- docker: https://www.kali.org/tools/docker/ returned HTTP 404
- etcdctl: https://www.kali.org/tools/etcdctl/ returned HTTP 404
- finger: https://www.kali.org/tools/finger/ returned HTTP 404
- ftp: https://www.kali.org/tools/ftp/ returned HTTP 404
- gitlab-api: https://www.kali.org/tools/gitlab-api/ returned HTTP 404
- govc: https://www.kali.org/tools/govc/ returned HTTP 404
- httpx: https://www.kali.org/tools/httpx/ returned HTTP 404
- impacket-GetNPUsers: https://www.kali.org/tools/impacket-GetNPUsers/ returned HTTP 404
- impacket-GetUserSPNs: https://www.kali.org/tools/impacket-GetUserSPNs/ returned HTTP 404
- impacket-mssqlclient: https://www.kali.org/tools/impacket-mssqlclient/ returned HTTP 404
- impacket-rpcdump: https://www.kali.org/tools/impacket-rpcdump/ returned HTTP 404
- impacket-smbclient: https://www.kali.org/tools/impacket-smbclient/ returned HTTP 404
- ipmitool: https://www.kali.org/tools/ipmitool/ returned HTTP 404
- irssi: https://www.kali.org/tools/irssi/ returned HTTP 404
- iscsiadm: https://www.kali.org/tools/iscsiadm/ returned HTTP 404
- jenkins-cli: https://www.kali.org/tools/jenkins-cli/ returned HTTP 404
- kafkacat: https://www.kali.org/tools/kafkacat/ returned HTTP 404
- kerbrute: https://www.kali.org/tools/kerbrute/ returned HTTP 404
- kube-hunter: https://www.kali.org/tools/kube-hunter/ returned HTTP 404
- kubectl: https://www.kali.org/tools/kubectl/ returned HTTP 404
- ldapdomaindump: https://www.kali.org/tools/ldapdomaindump/ returned HTTP 404
- ldapsearch: https://www.kali.org/tools/ldapsearch/ returned HTTP 404
- lftp: https://www.kali.org/tools/lftp/ returned HTTP 404
- logger: https://www.kali.org/tools/logger/ returned HTTP 404
- memcdump: https://www.kali.org/tools/memcdump/ returned HTTP 404
- modbus-cli: https://www.kali.org/tools/modbus-cli/ returned HTTP 404
- mongosh: https://www.kali.org/tools/mongosh/ returned HTTP 404
- mosquitto_sub: https://www.kali.org/tools/mosquitto_sub/ returned HTTP 404
- mysql: https://www.kali.org/tools/mysql/ returned HTTP 404
- mysqltuner: https://www.kali.org/tools/mysqltuner/ returned HTTP 404
- ncat: https://www.kali.org/tools/ncat/ returned HTTP 404
- ntpdate: https://www.kali.org/tools/ntpdate/ returned HTTP 404
- ntpq: https://www.kali.org/tools/ntpq/ returned HTTP 404
- psql: https://www.kali.org/tools/psql/ returned HTTP 404
- radclient: https://www.kali.org/tools/radclient/ returned HTTP 404
- redis-cli: https://www.kali.org/tools/redis-cli/ returned HTTP 404
- rlogin: https://www.kali.org/tools/rlogin/ returned HTTP 404
- rmg: https://www.kali.org/tools/rmg/ returned HTTP 404
- rpcclient: https://www.kali.org/tools/rpcclient/ returned HTTP 404
- rpcinfo: https://www.kali.org/tools/rpcinfo/ returned HTTP 404
- rsh: https://www.kali.org/tools/rsh/ returned HTTP 404
- rsync: https://www.kali.org/tools/rsync/ returned HTTP 404
- showmount: https://www.kali.org/tools/showmount/ returned HTTP 404
- smbclient: https://www.kali.org/tools/smbclient/ returned HTTP 404
- snmp-check: https://www.kali.org/tools/snmp-check/ returned HTTP 404
- snmptrap: https://www.kali.org/tools/snmptrap/ returned HTTP 404
- snmpwalk: https://www.kali.org/tools/snmpwalk/ returned HTTP 404
- sqsh: https://www.kali.org/tools/sqsh/ returned HTTP 404
- ssh-audit: https://www.kali.org/tools/ssh-audit/ returned HTTP 404
- telnet: https://www.kali.org/tools/telnet/ returned HTTP 404
- testssl: https://www.kali.org/tools/testssl/ returned HTTP 404
- tftp: https://www.kali.org/tools/tftp/ returned HTTP 404
- upnpc: https://www.kali.org/tools/upnpc/ returned HTTP 404
- vncviewer: https://www.kali.org/tools/vncviewer/ returned HTTP 404
- vulnx: https://www.kali.org/tools/vulnx/ returned HTTP 404
- wappalyzer: https://www.kali.org/tools/wappalyzer/ returned HTTP 404
- xfreerdp: https://www.kali.org/tools/xfreerdp/ returned HTTP 404
- xwd: https://www.kali.org/tools/xwd/ returned HTTP 404

