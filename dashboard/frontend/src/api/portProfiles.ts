import { useQuery } from '@tanstack/react-query'
import { apiFetch } from './client'

/**
 * Named port scope profiles, served from knowledge/port_profiles.yaml via the
 * BFF.  The port strings live server-side (top-1000 alone is ~3.8KB) so the UI
 * only ever holds ids, labels and counts — it never duplicates the lists.
 */
export interface PortProfile {
  id: string
  label: string
  description: string
  ports: string
  port_count: number
}

export interface PortProfilesResponse {
  profiles: PortProfile[]
  /** id of the profile to preselect when the operator hasn't chosen one */
  default: string
  /** true when port_profiles.yaml could not be read (missing /knowledge mount) */
  degraded: boolean
}

/** Sentinel meaning "use the free-text ports field verbatim". Not a server profile. */
export const CUSTOM_PROFILE = 'custom'

export function usePortProfiles() {
  return useQuery({
    queryKey: ['port-profiles'],
    queryFn: () => apiFetch<PortProfilesResponse>('/port-profiles'),
    // Backed by a read-only bind mount that changes rarely.
    staleTime: 5 * 60_000,
  })
}

/** Human-readable scope summary, e.g. "Top 1000 ports (1,000 ports)". */
export function describeProfile(p: PortProfile): string {
  return `${p.label} (${p.port_count.toLocaleString()} ports)`
}
