/**
 * News page filter persistence.
 *
 * The engagement match itself is stored server-side, in
 * `news_items.metadata.engagement_match.<engagement_id>`, so a reload never
 * loses the analysis. What used to be lost was the *view*: every filter on the
 * News page was plain `useState`, so an operator who ran "Analyze news" and
 * switched on "Affects this engagement" landed back on an unfiltered NEW tab
 * after every refresh and had to re-apply the whole toolbar.
 *
 * Every access is fail-soft. A private window, cleared site data, a blocked
 * third-party-storage policy or a quota error must leave the page rendering
 * with defaults — forgetting the view is acceptable, failing to draw it is not.
 */
import type { NewsStatus } from './types'
import type { NewsSort } from '@/api/news'

export const NEWS_FILTER_KEY = 'news.filters.v1'

export interface PersistedNewsFilters {
  activeStatus: NewsStatus | 'all'
  search: string
  cveFilter: string
  kevOnly: boolean
  rceOnly: boolean
  redTeamOnly: boolean
  affectsEngagement: boolean
  strongOnly: boolean
  hideStatuses: NewsStatus[]
  maxAgeDays: number | null
  sort: NewsSort
}

export const NEWS_FILTER_DEFAULTS: PersistedNewsFilters = {
  activeStatus: 'new',
  search: '',
  cveFilter: '',
  kevOnly: false,
  rceOnly: false,
  redTeamOnly: true,
  affectsEngagement: false,
  strongOnly: false,
  hideStatuses: ['deleted'],
  maxAgeDays: 30,
  sort: 'relevance',
}

export function loadNewsFilters(): PersistedNewsFilters {
  try {
    const raw = localStorage.getItem(NEWS_FILTER_KEY)
    if (!raw) return { ...NEWS_FILTER_DEFAULTS }
    const saved = JSON.parse(raw)
    if (!saved || typeof saved !== 'object' || Array.isArray(saved)) {
      return { ...NEWS_FILTER_DEFAULTS }
    }
    // Merge key-by-key rather than `{...defaults, ...saved}`: a blob written by
    // an older build is missing keys this one reads, and a spread would also
    // let an explicit `undefined` overwrite a default.
    const out = { ...NEWS_FILTER_DEFAULTS }
    for (const k of Object.keys(NEWS_FILTER_DEFAULTS) as (keyof PersistedNewsFilters)[]) {
      if (saved[k] !== undefined) (out as Record<string, unknown>)[k] = saved[k]
    }
    // maxAgeDays is legitimately null ("All time"), so it is not validated
    // here. hideStatuses must stay an array — the caller feeds it to `new
    // Set(...)`, which throws on a non-iterable and would blank the page.
    if (!Array.isArray(out.hideStatuses)) {
      out.hideStatuses = [...NEWS_FILTER_DEFAULTS.hideStatuses]
    }
    return out
  } catch {
    return { ...NEWS_FILTER_DEFAULTS }
  }
}

export function saveNewsFilters(f: PersistedNewsFilters): void {
  try {
    localStorage.setItem(NEWS_FILTER_KEY, JSON.stringify(f))
  } catch {
    /* private window / quota exceeded / site data blocked — view is not
       remembered, which is strictly better than throwing out of a render. */
  }
}

/** True when nothing is narrowed, i.e. the "Reset filters" button is pointless. */
export function newsFiltersAreDefault(f: PersistedNewsFilters): boolean {
  const d = NEWS_FILTER_DEFAULTS
  return (
    f.activeStatus === d.activeStatus &&
    f.search === d.search &&
    f.cveFilter === d.cveFilter &&
    f.kevOnly === d.kevOnly &&
    f.rceOnly === d.rceOnly &&
    f.redTeamOnly === d.redTeamOnly &&
    f.affectsEngagement === d.affectsEngagement &&
    f.strongOnly === d.strongOnly &&
    f.maxAgeDays === d.maxAgeDays &&
    f.sort === d.sort &&
    f.hideStatuses.length === d.hideStatuses.length &&
    d.hideStatuses.every(h => f.hideStatuses.includes(h))
  )
}
