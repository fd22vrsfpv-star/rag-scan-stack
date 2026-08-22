import { describe, it, expect } from 'vitest'
import { findingFacets } from '@/lib/findingFacets'

/**
 * The bug this guards: Dashboard.tsx passed engagement_id and then charted
 * `by_severity`, which is GLOBAL and ignores the query filters. With an
 * engagement selected the card showed a filtered total (838) above a chart
 * summing to the whole dataset (840). Reports.tsx did the same under a heading
 * that literally read "Live findings count based on current filters".
 *
 * The API-side reconciliation is covered by tests/test_findings_rollup.py. This
 * covers the choice the pages make, which a Python test cannot see — pointing
 * Dashboard back at the global facet was caught by neither until now.
 */
describe('findingFacets', () => {
  const filtered = {
    total: 838,
    aggregations: {
      by_severity: { critical: 8, high: 5, info: 37 },      // global: sums to 850
      by_source: { nmap: 2, zap: 40, katana: 798 },
      problems_by_severity: { critical: 8, high: 5, info: 35 },
      problems_by_source: { zap: 40, katana: 798 },
      distinct_problems: 838,
      shared_problems: 1,
    },
  }

  it('prefers the filtered, per-problem facets when present', () => {
    const f = findingFacets(filtered)
    expect(f.bySeverity).toEqual({ critical: 8, high: 5, info: 35 })
    expect(f.bySource).toEqual({ zap: 40, katana: 798 })
    expect(f.isFiltered).toBe(true)
  })

  it('does not silently use the global facet when a filtered one exists', () => {
    const f = findingFacets(filtered)
    expect(f.bySeverity.info).not.toBe(37)
    expect(f.bySource).not.toHaveProperty('nmap')
  })

  it('reports distinct problems as the headline, rows separately', () => {
    const f = findingFacets(filtered)
    expect(f.problems).toBe(838)
    expect(f.rows).toBe(838)
    expect(f.isRolledUp).toBe(false)
  })

  it('flags a rolled-up set when rows exceed problems', () => {
    const f = findingFacets({
      total: 5,
      aggregations: {
        by_severity: {}, by_source: {},
        problems_by_severity: { high: 2 },
        problems_by_source: { zap: 2 },
        distinct_problems: 2,
        shared_problems: 1,
      },
    })
    expect(f.rows).toBe(5)
    expect(f.problems).toBe(2)
    expect(f.isRolledUp).toBe(true)
  })

  it('falls back to the global facets against an older API', () => {
    // Rendering an empty chart would be worse than showing global numbers.
    const f = findingFacets({
      total: 100,
      aggregations: { by_severity: { high: 4 }, by_source: { zap: 4 } },
    })
    expect(f.bySeverity).toEqual({ high: 4 })
    expect(f.bySource).toEqual({ zap: 4 })
    expect(f.isFiltered).toBe(false)
    expect(f.problems).toBe(100)   // no distinct_problems → fall back to rows
    expect(f.isRolledUp).toBe(false)
  })

  it('is safe with no data at all', () => {
    const f = findingFacets(undefined)
    expect(f.bySeverity).toEqual({})
    expect(f.bySource).toEqual({})
    expect(f.rows).toBe(0)
    expect(f.problems).toBe(0)
    expect(f.isRolledUp).toBe(false)
  })

  it('trusts distinct_problems over summing the facet', () => {
    // If a severity were ever missing from the facet, summing would disagree
    // with the server. The server's count wins.
    const f = findingFacets({
      total: 10,
      aggregations: {
        by_severity: {}, by_source: {},
        problems_by_severity: { high: 3 },
        problems_by_source: { zap: 3 },
        distinct_problems: 7,
        shared_problems: 0,
      },
    })
    expect(f.problems).toBe(7)
  })
})
