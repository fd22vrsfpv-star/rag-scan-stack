import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'
import type { Credential } from '@/lib/types'
import { POLL } from '@/lib/polling'

export function useCredentials(filters: {
  engagement_id?: string; credential_type?: string; status?: string; domain?: string
} = {}) {
  const params = new URLSearchParams()
  if (filters.engagement_id) params.set('engagement_id', filters.engagement_id)
  if (filters.credential_type) params.set('credential_type', filters.credential_type)
  if (filters.status) params.set('status', filters.status)
  if (filters.domain) params.set('domain', filters.domain)
  return useQuery({
    queryKey: ['credentials', filters],
    queryFn: () => apiFetch<{ credentials: Credential[] }>(`/credential-vault?${params}`),
    refetchInterval: POLL.SLOW,
  })
}

export function useCreateCredential() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (data: Partial<Credential>) =>
      apiFetch<Credential>('/credential-vault', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  })
}

export function useUpdateCredential() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...data }: { id: string } & Partial<Credential>) =>
      apiFetch<Credential>(`/credential-vault/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  })
}

export function useDeleteCredential() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => apiFetch(`/credential-vault/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['credentials'] }),
  })
}

/** Credentials DISCOVERED by scans (credential_findings), served by /credentials.
 *
 * Distinct from /credential-vault, which is the manually-curated store with
 * rotation/expiry tracking. A credential-check run that recovered
 * msfadmin:msfadmin wrote 7 rows here while the Credential Vault tab — whose own
 * help text claims it "stores discovered credentials" — queried only the vault
 * and showed nothing. Two stores, one of them invisible.
 */
export interface DiscoveredCredential {
  id: string
  ip?: string
  port?: number
  protocol?: string
  username?: string
  valid_cred?: boolean
  severity?: string
  source?: string
  status?: string
  discovered_at?: string
}

export function useDiscoveredCredentials(limit = 500) {
  return useQuery({
    queryKey: ['discovered-credentials', limit],
    queryFn: () => apiFetch<{ credentials: DiscoveredCredential[]; count?: number }>(
      `/credentials?limit=${limit}`),
    refetchInterval: POLL.SLOW,
  })
}
