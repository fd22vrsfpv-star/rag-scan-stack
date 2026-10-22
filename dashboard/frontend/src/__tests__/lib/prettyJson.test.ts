import { describe, it, expect } from 'vitest'
import { prettyJson } from '@/pages/ExploitManager'

/**
 * Why this exists.
 *
 * Build-PoC trace bodies are a mix of prose, raw HTTP responses and JSON, all
 * written into the same `response` / `run_output` text slot. The JSON ones
 * arrive as a single unbroken line, so an OpenAPI spec or a strategist plan
 * rendered as a 4,000-character wall.
 *
 * Re-indenting is only safe if it NEVER touches the non-JSON bodies: an nmap
 * run, an HTTP response with headers, or a one-line reason must come back
 * byte-identical. These cases pin both directions.
 */
describe('prettyJson', () => {
  it('indents a JSON object', () => {
    const r = prettyJson('{"a":1,"b":{"c":2}}')
    expect(r.pretty).toBe(true)
    expect(r.body).toBe('{\n  "a": 1,\n  "b": {\n    "c": 2\n  }\n}')
  })

  it('indents a JSON array', () => {
    const r = prettyJson('[{"x":1},{"y":2}]')
    expect(r.pretty).toBe(true)
    expect(r.body.split('\n').length).toBeGreaterThan(3)
  })

  it('leaves a raw HTTP response untouched', () => {
    // Real shape from a trace run_output.
    const http = [
      '[proxy] DIRECT - the caller resolved no proxy for this target',
      'HTTP/1.1 200 OK',
      'Server: Apache/2.4.68 (Debian)',
      '',
      '<!DOCTYPE html><html><body>hi</body></html>',
    ].join('\n')
    const r = prettyJson(http)
    expect(r.pretty).toBe(false)
    expect(r.body).toBe(http)
  })

  it('leaves prose and one-line reasons untouched', () => {
    for (const s of [
      'failure_analysis ok in 1.35s',
      'probe not executed: [proxy] REFUSED',
      'no OpenAPI spec published',
      '',
    ]) {
      const r = prettyJson(s)
      expect(r.pretty).toBe(false)
      expect(r.body).toBe(s)
    }
  })

  it('does not reformat a bare scalar that happens to parse as JSON', () => {
    // JSON.parse('42') and '"hi"' both succeed; neither is worth reindenting,
    // and turning the string "hi" into "hi" with quotes would be a change.
    for (const s of ['42', '"hi"', 'true', 'null']) {
      expect(prettyJson(s).pretty).toBe(false)
      expect(prettyJson(s).body).toBe(s)
    }
  })

  it('indents a trailing object behind a prefix, keeping the prefix', () => {
    // Real shape: the prerun-probe feedback line.
    const s = 'PRERUN_PROBE_FEEDBACK status=422 body={"detail":[{"msg":"Field required"}]}'
    const r = prettyJson(s)
    expect(r.pretty).toBe(true)
    expect(r.body.startsWith('PRERUN_PROBE_FEEDBACK status=422 body=')).toBe(true)
    expect(r.body).toContain('\n')
    expect(r.body).toContain('"msg": "Field required"')
  })

  it('leaves malformed JSON alone instead of throwing', () => {
    const s = '{"a":1,'
    expect(() => prettyJson(s)).not.toThrow()
    expect(prettyJson(s).body).toBe(s)
  })

  it('skips absurdly large bodies rather than blocking the render', () => {
    const big = '{"a":"' + 'x'.repeat(400_001) + '"}'
    expect(prettyJson(big).pretty).toBe(false)
  })
})
