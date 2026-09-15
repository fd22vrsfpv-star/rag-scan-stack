import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from './client'

export interface ReconnectWatcherSettings {
  enabled: boolean
  poll_interval: number
  min_attempt_interval: number
}

export function useReconnectWatcherSettings() {
  return useQuery({
    queryKey: ['reconnect-watcher-settings'],
    queryFn: () => apiFetch<ReconnectWatcherSettings>('/settings/reconnect-watcher'),
  })
}

export function useUpdateReconnectWatcherSettings() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (settings: Partial<ReconnectWatcherSettings>) =>
      apiFetch<{ ok: boolean; updated: string[] }>('/settings/reconnect-watcher', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(settings),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['reconnect-watcher-settings'] })
    },
  })
}
