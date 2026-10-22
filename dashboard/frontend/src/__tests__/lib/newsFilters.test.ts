import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import {
  NEWS_FILTER_KEY,
  NEWS_FILTER_DEFAULTS,
  loadNewsFilters,
  saveNewsFilters,
  newsFiltersAreDefault,
} from '@/lib/newsFilters'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * Why this exists.
 *
 * Two separate defects made the News page's engagement-match view unusable:
 *
 *  1. Every filter was plain `useState`, so the operator ran "Analyze news",
 *     switched on "Affects this engagement", refreshed, and landed back on an
 *     unfiltered NEW tab. The match data itself was never lost — it lives in
 *     `news_items.metadata.engagement_match.<eid>` server-side — only the view
 *     was.
 *  2. `affectsEngagement` and `strongOnly` were read inside the `filters`
 *     useMemo but ABSENT from its dependency array, so toggling the button lit
 *     it up and changed nothing: the react-query key never moved and the list
 *     never refiltered. That filter had never worked.
 *
 * (1) is covered by the round-trip + fail-soft cases below. (2) cannot be
 * reached from this module, so it is pinned by reading News.tsx and asserting
 * both names appear in the dependency array — see the last case.
 */

describe('news filter persistence', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })
  afterEach(() => vi.restoreAllMocks())

  it('returns defaults when nothing has been stored', () => {
    expect(loadNewsFilters()).toEqual(NEWS_FILTER_DEFAULTS)
  })

  it('round-trips the engagement-match toggles across a reload', () => {
    saveNewsFilters({
      ...NEWS_FILTER_DEFAULTS,
      affectsEngagement: true,
      strongOnly: true,
      activeStatus: 'applies',
      sort: 'published',
    })
    const back = loadNewsFilters()
    expect(back.affectsEngagement).toBe(true)
    expect(back.strongOnly).toBe(true)
    expect(back.activeStatus).toBe('applies')
    expect(back.sort).toBe('published')
  })

  it('keeps maxAgeDays: null ("All time") rather than snapping back to 30', () => {
    saveNewsFilters({ ...NEWS_FILTER_DEFAULTS, maxAgeDays: null })
    expect(loadNewsFilters().maxAgeDays).toBeNull()
  })

  it('fills in keys a blob from an older build does not carry', () => {
    // A v1 writer that predates `strongOnly` / `sort`.
    localStorage.setItem(NEWS_FILTER_KEY, JSON.stringify({
      activeStatus: 'research', affectsEngagement: true,
    }))
    const back = loadNewsFilters()
    expect(back.activeStatus).toBe('research')
    expect(back.affectsEngagement).toBe(true)
    expect(back.strongOnly).toBe(NEWS_FILTER_DEFAULTS.strongOnly)
    expect(back.sort).toBe(NEWS_FILTER_DEFAULTS.sort)
    expect(back.redTeamOnly).toBe(NEWS_FILTER_DEFAULTS.redTeamOnly)
  })

  it('survives a corrupt blob instead of throwing out of the render', () => {
    localStorage.setItem(NEWS_FILTER_KEY, '{not json')
    expect(loadNewsFilters()).toEqual(NEWS_FILTER_DEFAULTS)
    localStorage.setItem(NEWS_FILTER_KEY, '["an","array"]')
    expect(loadNewsFilters()).toEqual(NEWS_FILTER_DEFAULTS)
    localStorage.setItem(NEWS_FILTER_KEY, 'null')
    expect(loadNewsFilters()).toEqual(NEWS_FILTER_DEFAULTS)
  })

  it('coerces a non-array hideStatuses — the caller feeds it to new Set()', () => {
    localStorage.setItem(NEWS_FILTER_KEY, JSON.stringify({ hideStatuses: 'deleted' }))
    const back = loadNewsFilters()
    expect(Array.isArray(back.hideStatuses)).toBe(true)
    expect(() => new Set(back.hideStatuses)).not.toThrow()
  })

  it('is fail-soft when storage is blocked (private window / quota)', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new DOMException('denied', 'SecurityError')
    })
    expect(loadNewsFilters()).toEqual(NEWS_FILTER_DEFAULTS)

    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('quota', 'QuotaExceededError')
    })
    expect(() => saveNewsFilters(NEWS_FILTER_DEFAULTS)).not.toThrow()
  })

  it('newsFiltersAreDefault only when nothing is narrowed', () => {
    expect(newsFiltersAreDefault(NEWS_FILTER_DEFAULTS)).toBe(true)
    expect(newsFiltersAreDefault({ ...NEWS_FILTER_DEFAULTS, affectsEngagement: true })).toBe(false)
    expect(newsFiltersAreDefault({ ...NEWS_FILTER_DEFAULTS, maxAgeDays: null })).toBe(false)
    expect(newsFiltersAreDefault({ ...NEWS_FILTER_DEFAULTS, hideStatuses: [] })).toBe(false)
    // Same contents, different spelling of the array — still default.
    expect(newsFiltersAreDefault({ ...NEWS_FILTER_DEFAULTS, hideStatuses: ['deleted'] })).toBe(true)
  })

  it('the News list query re-runs when the engagement-match filters change', () => {
    // Guard for defect (2). `affects_engagement` / `strong_only` are read
    // inside the `filters` useMemo; if they are not also in its dependency
    // array the react-query key never changes and the toggle is inert.
    // Delete either name from the deps and this fails.
    const src = readFileSync(
      resolve(__dirname, '../../pages/News.tsx'), 'utf8',
    )
    const memo = src.slice(src.indexOf('const filters = useMemo(() => {'))
    const deps = memo.slice(memo.indexOf('}, ['), memo.indexOf('])') + 2)

    expect(deps).toContain('affectsEngagement')
    expect(deps).toContain('strongOnly')
    // and the values really are consumed inside the memo body
    expect(memo.slice(0, memo.indexOf('}, ['))).toContain('affects_engagement:')
    expect(memo.slice(0, memo.indexOf('}, ['))).toContain('strong_only:')
  })
})
