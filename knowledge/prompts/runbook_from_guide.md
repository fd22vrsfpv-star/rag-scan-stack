# Prompt: per-service runbook from a guide

Copy everything below the line into Claude, then paste the guide (or attach it)
underneath. Produces a runbook to *follow* — prose, not the seed YAML that
`scripts/url-to-guide.sh` generates for import.

Use this when you want something to work from during an engagement. Use the
converter when you want rules the AI applies automatically. They are
complementary: the runbook is for you, the rules are for the scanner.

**Why a separate prompt.** The built-in converter optimises for *importable
rules* — terse, one concern each, machine-validated. A runbook optimises for a
human executing under time pressure: ordered, with stop conditions, and explicit
about what to capture as evidence. Asking one prompt for both produces something
mediocre at each.

---

You are writing an operational runbook for a penetration tester working under
time pressure on an authorised engagement.

I will give you a guide, writeup or vendor documentation. Convert it into a
runbook the tester can follow directly.

## Coverage — this is the part most attempts get wrong

Work through the source and list **every** service, port and technology it
covers before you write anything. Then write a section for each one.

If the source covers twenty services, the runbook has twenty sections. Do not
summarise, do not pick highlights, and do not stop after the interesting ones.
Missing services is the single most common failure here — a runbook that covers
a third of the source is worse than useless, because the tester assumes the rest
was not applicable.

Begin your answer with that inventory, so coverage is checkable:

```
Services covered: ftp, ssh, telnet, smtp, smb, mysql, postgresql, ...
```

If the source mentions something but gives no technique for it, still list it,
with one line saying only that it was present and nothing more is known.

## Section format

For each service, in this order:

```
## <service> (<port>)

**Why it matters here** — one line: what this gets you if it works.

1. <first action>
   why: <what it tells you, or why it precedes the next step>
2. <second action>
   ...

**Stop if:** <the condition that means move on rather than keep digging>
**Evidence to capture:** <exactly what to screenshot / save for the report>
**Cleanup:** <anything created that must be removed — omit if nothing>
```

Rules for the steps:

- **Order matters, and say why.** Cheap and quiet before slow and loud;
  read-only before anything that writes. If step 2 depends on step 1's output,
  say so.
- **Give real commands** with the flags that matter. A tester should be able to
  run them without re-deriving syntax. Use `<TARGET>` and `<PORT>` placeholders.
- **Vendor defaults are technique, not secrets.** "Try tomcat:tomcat on
  /manager/html" belongs in the runbook. A password someone set on a lab box
  does not — drop those.
- **Note what is destructive or noisy** before the step, not after.

## Ordering the runbook

Order the sections by what a tester should actually do first: information
disclosure and unauthenticated access before brute force; anything that yields
credentials before the services those credentials might open. Say at the top if
one section feeds another, e.g. "SNMP often yields the hostnames needed for
section 9".

## What not to do

- Do not invent technique the source does not support and that is not
  well-established practice for that service. A confident fabrication is the
  worst possible output — it will be executed against a real target.
- Do not carry over anything specific to the author's box: its IP, hostnames,
  discovered passwords, flags, or file paths.
- Do not pad a section to look complete. "Present, no technique documented" is a
  legitimate and useful section body.

## Finally

End with:

```
## Gaps
- <anything the source references but does not explain>
- <anything you were unsure about and did not include>
```

Be explicit about uncertainty. A tester can research a gap you named; they
cannot research one you concealed.
