# Brute-force tool comparison: brutus vs medusa vs hydra

Measured on 2026-08-23 against the engagement target 192.168.1.150 (in scope).
Identical inputs for all three: 8 usernames x 5 passwords = 40 candidates, with
`msfadmin:msfadmin` present so correctness could be checked and not just speed.
`anonymous` and `ftp` were removed from the userlist, because Metasploitable's
vsftpd accepts anonymous and every tool would otherwise "succeed" instantly.

## Result: performance is NOT a reason to prefer one

ftp/21, three repeats each, matched at `-t 10`:

| tool   | runs (s)           | median | spread |
|--------|--------------------|-------:|-------:|
| medusa | 12.0, 12.7, 12.8   | 12.7   | 0.7    |
| brutus | 12.7, 13.0, 13.0   | 13.0   | 0.3    |
| hydra  | 15.4, 13.9, 14.9   | 14.9   | 1.5    |

All three found `msfadmin:msfadmin` and exited 0. brutus and medusa are
indistinguishable (13.0 vs 12.7, with overlapping spread); hydra is consistently
about 15% slower.

## Concurrency dominates tool choice

Same lists, same target, one run each:

| tool   | `-t 4` | `-t 10` | speedup |
|--------|-------:|--------:|--------:|
| brutus | 31.2s  | 12.7s   | 2.5x    |
| medusa | 33.8s  | 13.8s   | 2.4x    |
| hydra  | 37.5s  | 15.4s   | 2.4x    |

Raising the thread count is a **2.4-2.5x** improvement. The largest gap between
any two tools is ~21%. So the thread count is the decision that matters, and the
tool is close to irrelevant on speed.

**A first measurement said brutus was 2.5x faster than the others. That was
wrong** — brutus defaults to `-t 10` while hydra and medusa had been given
`-t 4`. It was measuring the default, not the tool. Match concurrency explicitly
or the comparison measures nothing.

## What actually differentiates them: protocol reliability

This mattered far more than seconds.

- **telnet/23 — medusa FAILS.** `ERROR: [telnet.mod] Failed to identify logon
  prompt`, four times, exiting 0 in **1.1 seconds**. A fast failure that reads
  exactly like a fast success, which is the whole reason output has to be
  analysed rather than timed.
- **telnet/23 — hydra works but crawls** at 2.0-2.25 tries/min: 10 of 40
  candidates in 300 seconds, then killed. It warns about this itself:
  "telnet is by its nature unreliable to analyze, if possible better choose FTP,
  SSH, etc. if available". Take the advice.
- **ssh/22 — hydra cannot connect at all** to this host:
  `kex error : no match for method mac algo client->server`. The target runs
  OpenSSH 4.7p1 offering only legacy MACs (hmac-md5, hmac-sha1, hmac-ripemd160)
  while modern hydra offers only SHA2. That is a crypto negotiation failure, not
  a credential result — and it would have been recorded as a scan that found
  nothing.
- **ftp/21 — all three work correctly.** Prefer ftp where a choice exists.

## Operational differences

- **brutus** emits JSONL directly, one object per hit, with a per-attempt
  duration: `{"protocol":"ftp","target":"192.168.1.150:21","username":"msfadmin",
  "password":"msfadmin","duration":"43.998958ms"}`. No output parsing needed.
  Installed **only in brutus-runner** (`/usr/local/bin/brutus`), and it needs
  fingerprintx-shaped JSON on stdin plus the `creds` subcommand.
- **medusa** needs `-M <module>` per protocol; its telnet module is unusable here.
- **hydra** leaves `./hydra.restore` behind and then STOPS AND PROMPTS on the
  next run unless given `-I` — the cause of several exit-255 failures in this
  stack. Installed only in kali-listener, alongside medusa.
- **ncrack** is not installed anywhere.

## Answer to "should we swap brutus for hydra or medusa?"

Not on performance — they are within 20%, and concurrency swamps the difference.
The reasons that would justify a swap are protocol coverage and where the binary
lives: brutus is absent from kali-listener, hydra and medusa are absent from
brutus-runner. Pick by which container is dispatching and which protocol is
being attacked, and set `-t` deliberately in every case.

## Invocations verified in this comparison

```
# brutus (in brutus-runner; needs the target as JSON on stdin)
echo '{"ip":"192.168.1.150","port":21,"protocol":"ftp"}' \
  | brutus creds -o /tmp/out.jsonl -q -U <userlist> -P <passlist> -t 10

# medusa (in kali-listener)
medusa -h 192.168.1.150 -U <userlist> -P <passlist> -M ftp -t 10

# hydra (in kali-listener; -I is not optional)
hydra -I -L <userlist> -P <passlist> ftp://192.168.1.150:21 -t 10
```
