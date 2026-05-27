import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { wsClient } from '@/api/ws'
import type { WSEvent } from '@/lib/types'

export function useWebSocket() {
  const qc = useQueryClient()

  useEffect(() => {
    wsClient.connect()

    const unsub = wsClient.subscribe((event: WSEvent) => {
      switch (event.type) {
        case 'job_status':
          qc.invalidateQueries({ queryKey: ['scans'] })
          break
        case 'scan_completed':
          // Scan finished — assets, ports, findings all may have new data
          qc.invalidateQueries({ queryKey: ['scans'] })
          qc.invalidateQueries({ queryKey: ['assets'] })
          qc.invalidateQueries({ queryKey: ['findings'] })
          qc.invalidateQueries({ queryKey: ['asset-ports'] })
          qc.invalidateQueries({ queryKey: ['report-summary'] })
          qc.invalidateQueries({ queryKey: ['content-extractions'] })
          qc.invalidateQueries({ queryKey: ['content-summary'] })
          qc.invalidateQueries({ queryKey: ['opsec-timeline'] })
          break
        case 'finding_critical':
        case 'finding_high':
          qc.invalidateQueries({ queryKey: ['findings'] })
          qc.invalidateQueries({ queryKey: ['assets'] })
          break
        case 'ingest_completed':
          // ETL ingest finished — new assets/ports/findings available
          qc.invalidateQueries({ queryKey: ['assets'] })
          qc.invalidateQueries({ queryKey: ['asset-ports'] })
          qc.invalidateQueries({ queryKey: ['findings'] })
          break
      }
    })

    return () => {
      unsub()
    }
  }, [qc])
}
