import type { FindingsResponse } from './types'

/**
 * Which severity/source breakdown a page should show, and what its headline
 * number means.
 *
 * `/findings/search` returns two sets of counts that differ on TWO axes:
 *
 *   by_severity / by_source                 GLOBAL, raw rows, IGNORES the filters
 *   problems_by_severity / _by_source       FILTERED, one entry per problem
 *
 * The global pair is deliberate — the Findings Explorer needs every source to
 * keep a filter chip even after a filter narrows the set, so those counts must
 * not shrink. But any panel that describes "what the current filters matched"
 * has to use the filtered pair, and two pages were not:
 *
 *   Dashboard.tsx  passed engagement_id, then charted by_severity — so a
 *                  filtered total (838) sat above a chart summing to the whole
 *                  dataset (840), and worse with several active engagements.
 *   Reports.tsx    said "Live findings count based on current filters" and then
 *                  rendered by_severity, which ignores them. Filtering to
 *                  severity=critical still listed every severity.
 *
 * Both now call this. Falling back to the global pair keeps the pages working
 * against an older API that has not got the filtered fields yet, rather than
 * rendering empty charts.
 */
export interface FindingFacets {
  /** Severity → count. Filtered and per-problem when the API provides it. */
  bySeverity: Record<string, number>
  /** Source → count. Filtered and per-problem when the API provides it. */
  bySource: Record<string, number>
  /** Distinct underlying problems matching the filter. */
  problems: number
  /** Raw matching rows — one per virtual host, so >= problems. Drives pagination. */
  rows: number
  /** True when rows and problems differ, i.e. some problem spans several hosts. */
  isRolledUp: boolean
  /** True when the counts above respect the query filters. */
  isFiltered: boolean
}

export function findingFacets(data?: Pick<FindingsResponse, 'total' | 'aggregations'>): FindingFacets {
  const agg = data?.aggregations
  const rows = data?.total ?? 0

  const filteredSeverity = agg?.problems_by_severity
  const filteredSource = agg?.problems_by_source
  const isFiltered = !!filteredSeverity

  const bySeverity = filteredSeverity ?? agg?.by_severity ?? {}
  const bySource = filteredSource ?? agg?.by_source ?? {}

  // distinct_problems is authoritative when present. Summing bySeverity would
  // double-count nothing, but it would silently disagree with the server if a
  // severity were ever absent from the facet.
  const problems = agg?.distinct_problems ?? rows

  return {
    bySeverity,
    bySource,
    problems,
    rows,
    isRolledUp: problems !== rows,
    isFiltered,
  }
}
