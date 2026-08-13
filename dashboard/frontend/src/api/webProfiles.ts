import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * Named web scan depth profiles, served from knowledge/web_profiles.yaml via
 * the BFF. Where port profiles control how WIDE a network sweep goes, these
 * control how DEEP a web scan digs — crawl depth, wordlist size, which stages
 * run, and which nuclei severities are in play.
 */
export interface WebProfile {
  id: string
  label: string
  description: string
  /** Tools that run, e.g. ['wafw00f','katana','nuclei'] */
  stages: string[]
  stage_count: number
  wordlist: string
  max_paths: number
  crawl_depth: number
  nuclei_severity: string
  nuclei_tags: string
}

export interface WebProfilesResponse {
  profiles: WebProfile[]
  default: string
  /** true when web_profiles.yaml could not be read (missing /knowledge mount) */
  degraded: boolean
  known_stages: string[]
}

/** Sentinel meaning "use the individual form fields verbatim". Not a server profile. */
export const CUSTOM_WEB_PROFILE = 'custom'

export function useWebProfiles() {
  return useQuery({
    queryKey: ['web-profiles'],
    queryFn: () => apiFetch<WebProfilesResponse>('/web-profiles'),
    staleTime: 5 * 60_000,
  })
}

/** One-line summary for a tooltip, e.g. "5 stages · big wordlist · depth 5". */
export function describeWebProfile(p: WebProfile): string {
  const bits = [`${p.stage_count} stage${p.stage_count === 1 ? '' : 's'}`]
  if (p.wordlist) bits.push(`${p.wordlist} wordlist`)
  bits.push(`depth ${p.crawl_depth}`)
  if (p.nuclei_severity) bits.push(p.nuclei_severity)
  return bits.join(' · ')
}
