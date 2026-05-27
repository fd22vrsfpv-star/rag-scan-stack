import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface ZapAddon {
  id: string
  name: string
  version?: string
  description?: string
  status?: string
  url?: string
}

export interface ZapAddonsResponse {
  installed: ZapAddon[]
  available: ZapAddon[]
  installed_count: number
  available_count: number
}

export function useZapAddons() {
  return useQuery({
    queryKey: ['zap-addons'],
    queryFn: () => apiFetch<ZapAddonsResponse>('/zap/addons'),
    staleTime: 30_000,
  })
}

export function useInstallAddon() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (addon_id: string) =>
      apiFetch<{ ok: boolean; addon_id: string }>('/zap/addons/install', {
        method: 'POST',
        body: JSON.stringify({ addon_id }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['zap-addons'] })
    },
  })
}

export function useUninstallAddon() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (addon_id: string) =>
      apiFetch<{ ok: boolean; addon_id: string }>('/zap/addons/uninstall', {
        method: 'POST',
        body: JSON.stringify({ addon_id }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['zap-addons'] })
    },
  })
}
