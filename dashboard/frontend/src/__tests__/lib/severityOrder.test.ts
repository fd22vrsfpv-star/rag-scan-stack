import { describe, it, expect } from 'vitest'
import {
  SEVERITY_LEVELS,
  LEGACY_SEVERITIES,
  SEVERITY_RANK,
  SEVERITY_BY_RANK,
  severityRank,
  compareSeverity,
  severityDot,
} from '@/lib/constants'

/**
 * Why this exists.
 *
 * Severity ordering was duplicated in four places, with TWO OPPOSITE
 * conventions:
 *
 *   AttackMap.tsx     SEV_RANK        { critical: 5 ... info: 1 }    high = severe
 *   TargetBoard.tsx   SEV_RANK        { critical: 5 ... info: 1 }    high = severe
 *   ContentIntel.tsx  SEVERITY_ORDER  { critical: 0 ... info: 4 }    LOW  = severe
 *   AttackMap.tsx     SEV_ORDER       ['critical' ... 'info']        display order
 *
 * None of them knew about the backend's 'recon' value, so 1495 attack vectors
 * sorted at rank 0 — below `info` and tied with unknown — and rendered with a
 * fallback colour. The backend emitted a severity the frontend had never heard
 * of, in four places at once, and nothing failed.
 *
 * The ranking is now derived from SEVERITY_LEVELS, and these tests assert the
 * derivation actually covers everything. A rank table that silently omits a
 * value is exactly the bug that happened.
 */
describe('canonical severity ordering', () => {
  it('ranks every severity the app can display', () => {
    for (const sev of SEVERITY_LEVELS) {
      expect(SEVERITY_RANK[sev], `no rank for '${sev}'`).toBeGreaterThan(0)
    }
    for (const legacy of LEGACY_SEVERITIES) {
      expect(SEVERITY_RANK[legacy], `no rank for legacy '${legacy}'`).toBeGreaterThan(0)
    }
  })

  it('orders critical above high above medium above low above info', () => {
    expect(severityRank('critical')).toBeGreaterThan(severityRank('high'))
    expect(severityRank('high')).toBeGreaterThan(severityRank('medium'))
    expect(severityRank('medium')).toBeGreaterThan(severityRank('low'))
    expect(severityRank('low')).toBeGreaterThan(severityRank('info'))
  })

  it('ranks legacy recon exactly as info, not as unknown', () => {
    // The actual defect: recon fell to 0, below info, tied with garbage.
    expect(severityRank('recon')).toBe(severityRank('info'))
    expect(severityRank('recon')).toBeGreaterThan(severityRank('nonsense'))
  })

  it('returns 0 for unknown, missing and empty so they sort last', () => {
    expect(severityRank('nonsense')).toBe(0)
    expect(severityRank(undefined)).toBe(0)
    expect(severityRank(null)).toBe(0)
    expect(severityRank('')).toBe(0)
  })

  it('is case-insensitive, because scanners are not consistent', () => {
    expect(severityRank('CRITICAL')).toBe(severityRank('critical'))
    expect(severityRank('Info')).toBe(severityRank('info'))
  })

  it('compareSeverity sorts most severe first', () => {
    const input = ['info', 'critical', 'low', 'high', 'nonsense', 'medium']
    expect([...input].sort(compareSeverity)).toEqual(
      ['critical', 'high', 'medium', 'low', 'info', 'nonsense'],
    )
  })

  it('compareSeverity puts unknown last, matching the old `?? 0` intent', () => {
    expect([...['nonsense', 'info']].sort(compareSeverity)).toEqual(['info', 'nonsense'])
  })

  it('SEVERITY_BY_RANK is the display order, most severe first', () => {
    const ranks = SEVERITY_BY_RANK.map(severityRank)
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks)
    expect(SEVERITY_BY_RANK[0]).toBe('critical')
    // and it covers the filterable set exactly — a chip list that silently
    // omits a severity hides rows from the operator
    expect([...SEVERITY_BY_RANK].sort()).toEqual([...SEVERITY_LEVELS].sort())
  })

  it('severityDot has a class for every severity and a fallback', () => {
    for (const sev of [...SEVERITY_LEVELS, ...LEGACY_SEVERITIES]) {
      expect(severityDot(sev), `no dot class for '${sev}'`).toMatch(/^bg-/)
    }
    expect(severityDot('nonsense')).toBe('bg-gray-500')
    expect(severityDot(undefined)).toBe('bg-gray-500')
  })

  it('adding a severity to SEVERITY_LEVELS ranks it automatically', () => {
    // The derivation, not a hand-maintained table: length - index. If someone
    // adds a level and forgets a rank entry, that is the original bug.
    SEVERITY_LEVELS.forEach((sev, i) => {
      expect(SEVERITY_RANK[sev]).toBe(SEVERITY_LEVELS.length - i)
    })
  })
})
