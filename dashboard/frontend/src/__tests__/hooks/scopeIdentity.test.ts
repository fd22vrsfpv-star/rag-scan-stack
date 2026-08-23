import { describe, it, expect } from 'vitest'

/**
 * An asset must match its scope on ANY identity it carries.
 *
 * The call sites passed `a.hostname || a.ip` — the FIRST non-empty value, not
 * all of them. A host named `metasploitable` whose scope entry is the IP
 * `192.168.1.150` therefore failed its own scope filter and was hidden from the
 * Assets view whenever that scope was selected.
 *
 * It stayed invisible for a while because the same host ALSO existed as a
 * second, hostname-less asset row, which did match by IP. Merging those
 * duplicates (one host, one row) removed the accidental cover and the host
 * disappeared from the scope view.
 *
 * This pins the matching contract directly, so it holds regardless of how the
 * hook is wired into React.
 */
function makeMatcher(targets: string[]) {
  const set = new Set(targets.map(t => t.toLowerCase().trim()).filter(Boolean))
  const matchesScope = (val: string): boolean => {
    if (!val) return false
    const v = val.toLowerCase().trim()
    if (set.has(v)) return true
    try {
      const url = v.startsWith('http') ? new URL(v) : null
      if (url) {
        if (set.has(url.hostname)) return true
        for (const t of set) if (url.hostname.endsWith('.' + t)) return true
      }
    } catch { /* not a URL */ }
    for (const t of set) if (v.endsWith('.' + t)) return true
    return false
  }
  const matchesAnyScope = (...vals: (string | null | undefined)[]): boolean => {
    const present = vals.filter((v): v is string => !!v && !!v.trim())
    if (present.length === 0) return true
    return present.some(matchesScope)
  }
  return { matchesScope, matchesAnyScope }
}

describe("scope matching across an asset's identities", () => {
  // The real 'msf' scope: one IP, plus a __placeholder__ row whose target is
  // empty and which must not affect anything.
  const scope = ['192.168.1.150', '']

  it('matches a NAMED asset whose scope entry is its IP', () => {
    const { matchesScope, matchesAnyScope } = makeMatcher(scope)
    // the exact bug: first-non-empty picks the hostname, which is not in scope
    expect(matchesScope('metasploitable')).toBe(false)
    expect(matchesAnyScope('metasploitable', '192.168.1.150')).toBe(true)
  })

  it('still matches an asset that has only an IP', () => {
    const { matchesAnyScope } = makeMatcher(scope)
    expect(matchesAnyScope(null, '192.168.1.150')).toBe(true)
  })

  it('still excludes a host that is genuinely out of scope', () => {
    const { matchesAnyScope } = makeMatcher(scope)
    expect(matchesAnyScope('evil.example', '8.8.8.8')).toBe(false)
  })

  it('the empty __placeholder__ target matches nothing on its own', () => {
    const { matchesAnyScope } = makeMatcher(scope)
    expect(matchesAnyScope('anything.example')).toBe(false)
  })

  it('keeps a row that carries no identity at all', () => {
    const { matchesAnyScope } = makeMatcher(scope)
    // Hiding it would silently drop a data problem out of the operator's view.
    expect(matchesAnyScope(null, undefined, '')).toBe(true)
  })

  it('matches a URL against an IP scope entry', () => {
    const { matchesAnyScope } = makeMatcher(scope)
    expect(matchesAnyScope(null, null, 'http://192.168.1.150:80/phpMyAdmin/')).toBe(true)
  })
})
