import { describe, it, expect } from 'vitest'
import { formatTraceBody } from '@/pages/ExploitManager'

/**
 * Why this exists.
 *
 * Trace bodies are built by string concatenation and several phases emit one
 * very long line. The strategist plan packs PRIMARY / ALT1 / ALT2 and eight
 * key=value fields into a single run; the building-block and gather bodies DO
 * carry their own newlines, but the Key-trace tab rendered them in a plain
 * <div>, where HTML collapses whitespace — so the same body was readable in
 * the Full trace tab and a run-on paragraph in the Key trace tab.
 *
 * The contract that makes this safe to apply to every body: it only
 * REARRANGES WHITESPACE. Strip all whitespace from input and output and they
 * must be identical — no character of a trace body may be dropped, reordered
 * or re-worded on its way to the operator. Every case below asserts that.
 *
 * Fixtures are real bodies captured from /app/poc_logs/*.jsonl.
 */

const squash = (s: string) => s.replace(/\s+/g, '')

/** The invariant every case shares. */
function expectLossless(input: string, out: string) {
  expect(squash(out)).toBe(squash(input))
}

describe('formatTraceBody', () => {
  it('breaks the strategist plan onto its fields', () => {
    const real =
      'STRATEGIST-CURATED PLAN (authoritative — the recon has been analyzed for you; ' +
      'TRY THE PRIMARY FIRST, then fall back to alternatives on failure): ' +
      'PRIMARY: class=other endpoint=/ param=debug method=GET payload_hint=`1` ' +
      'success_signal=`` why=RECON SIGNALS confirmed info disclosure returning 3126 bytes. ' +
      'ALT1: class=SQLi endpoint=/process.php param=password payload=`foo\' OR 1=1--` ' +
      'why=Same process.php endpoint from recon.'
    const r = formatTraceBody(real)
    expect(r.shaped).toBe(true)
    expectLossless(real, r.body)

    const lines = r.body.split('\n')
    expect(lines.length).toBeGreaterThan(8)
    // Each alternative starts its own line.
    expect(lines.some(l => l.startsWith('PRIMARY:'))).toBe(true)
    expect(lines.some(l => l.startsWith('ALT1:'))).toBe(true)
    // Fields are indented under their alternative, one per line.
    expect(lines.some(l => l.trim().startsWith('endpoint=/process.php'))).toBe(true)
    expect(lines.some(l => l.trim().startsWith('payload_hint='))).toBe(true)
    // The payload is not split even though it contains spaces and quotes.
    expect(r.body).toContain("payload=`foo' OR 1=1--`")
  })

  it('leaves a body that is already laid out alone (idempotent)', () => {
    // Real gather_check body — it already has newlines.
    const real = [
      'GATHER CHECK (strict): NOT READY — missing: endpoint, method',
      '  [gathered] target_reachable = HTTP 200  (via probe)',
      '  [gathered] vuln_class = auth-bypass  (via nvd+classifier)',
      '  [MISSING] endpoint: ',
      '  [MISSING] method: ',
    ].join('\n')
    const once = formatTraceBody(real).body
    expectLossless(real, once)
    expect(once.split('\n').length).toBe(5)
    // Running it again changes nothing.
    expect(formatTraceBody(once).body).toBe(once)
  })

  it('does not collapse the building-block body it is given', () => {
    const real = [
      'CONFIRMED BUILDING BLOCKS (assemble the exploit from these verified pieces):',
      '  ✓ target_reachable: the target answers HTTP at all',
      '  ✓ endpoint_exists: the advisory\'s target endpoint responds (not 404)',
      'QUICK CHECKS TO VALIDATE NEXT (build the rest in pieces):',
      '  • [lightweight] version_in_range: fetch the product version',
    ].join('\n')
    const r = formatTraceBody(real)
    expectLossless(real, r.body)
    expect(r.body.split('\n').length).toBe(5)
  })

  it('splits a building-block body that arrived flattened', () => {
    // What the Key-trace tab used to show: the same content, newlines gone.
    const flat =
      'CONFIRMED BUILDING BLOCKS (assemble the exploit from these verified pieces): ' +
      '✓ target_reachable: the target answers HTTP at all ' +
      '✓ session_valid: the authenticated session is actually live ' +
      'QUICK CHECKS TO VALIDATE NEXT (build the rest in pieces): ' +
      '• [lightweight] version_in_range: fetch the product version'
    const r = formatTraceBody(flat)
    expect(r.shaped).toBe(true)
    expectLossless(flat, r.body)
    const lines = r.body.split('\n')
    expect(lines.filter(l => l.trim().startsWith('✓')).length).toBe(2)
    expect(lines.some(l => l.startsWith('QUICK CHECKS TO VALIDATE NEXT'))).toBe(true)
  })

  it('indents the gather verdict JSON that trails the body', () => {
    const real = '{"confirmed":["target_reachable"],"missing":["version_in_range","object_ids"]}'
    const r = formatTraceBody(real)
    expect(r.shaped).toBe(true)
    expectLossless(real, r.body)
    expect(r.body).toContain('\n')
    expect(r.body).toContain('"confirmed"')
  })

  it('leaves ordinary prose and tool output untouched', () => {
    for (const s of [
      'failure_analysis ok in 1.35s',
      'no OpenAPI spec published',
      "verdicts: {'PRIMARY': 'FAKE'}",
      'CVE-2024-34359: a GGUF model file artifact is required (input source template_in_file).',
      [
        '[proxy] DIRECT - the caller resolved no proxy for this target',
        'HTTP/1.1 200 OK',
        'Server: Apache/2.4.68 (Debian)',
      ].join('\n'),
    ]) {
      const r = formatTraceBody(s)
      expect(r.body).toBe(s)
      expect(r.shaped).toBe(false)
    }
  })

  it('never drops content, on every fixture', () => {
    const fixtures = [
      '',
      'PRIMARY: class=XSS endpoint=/ param=log (POST body) method=POST why=Recon shows only root',
      'EXPLOIT READINESS CHALLENGE — preconditions NOT satisfied: - exploit requires authentication',
      'a | [observed] 172.18.0.32 web_finding=Server Leaks Version | [observed] 172.18.0.32 again',
    ]
    for (const f of fixtures) expectLossless(f, formatTraceBody(f).body)
  })
})
