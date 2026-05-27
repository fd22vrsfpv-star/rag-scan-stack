import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface ApiKeyEntry {
  key: string
  masked_value: string
  updated_at: string | null
}

export interface ApiKeysResponse {
  keys: ApiKeyEntry[]
}

export function useApiKeys() {
  return useQuery({
    queryKey: ['api-keys'],
    queryFn: () => apiFetch<ApiKeysResponse>('/settings/keys'),
    staleTime: 30_000,
  })
}

export function useUpsertApiKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ keyName, value }: { keyName: string; value: string }) =>
      apiFetch<{ ok: boolean; key: string }>(`/settings/keys/${keyName}`, {
        method: 'PUT',
        body: JSON.stringify({ value }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-keys'] })
    },
  })
}

export function useDeleteApiKey() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (keyName: string) =>
      apiFetch<{ ok: boolean; key: string }>(`/settings/keys/${keyName}`, {
        method: 'DELETE',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['api-keys'] })
    },
  })
}
