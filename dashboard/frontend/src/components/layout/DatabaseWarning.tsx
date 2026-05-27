import { useHealth } from '@/api/reports'
import { Database, AlertTriangle, X, Settings } from 'lucide-react'
import { useState } from 'react'

export function DatabaseWarning() {
  const { data: health } = useHealth()
  const [dismissed, setDismissed] = useState(false)

  // Check if there's a dual postgres warning
  const dualPostgresWarning = health?.warnings?.find(w => w.type === 'dual_postgres')

  // Don't show if no warning or user dismissed it
  if (!dualPostgresWarning || dismissed) {
    return null
  }

  return (
    <div className="bg-amber-600/20 border-b border-amber-600/30 px-4 py-3">
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 flex-1">
          <AlertTriangle className="h-4 w-4 text-amber-400" />
          <Database className="h-4 w-4 text-amber-400" />
          <div className="flex-1">
            <p className="text-sm font-medium text-amber-200">
              Database Configuration Conflict
            </p>
            <p className="text-xs text-amber-300/90 mb-2">
              {dualPostgresWarning.message}
            </p>
            <p className="text-xs text-amber-400/80">
              Go to <a href="/settings" className="underline hover:no-underline font-medium">Settings → Database</a> to switch modes or <a href="/services" className="underline hover:no-underline font-medium">Services</a> to stop database proxy containers.
            </p>
          </div>
        </div>
        <a
          href="/settings"
          className="flex items-center gap-1 px-2 py-1 rounded text-xs font-medium bg-amber-500/20 text-amber-300 hover:bg-amber-500/30 transition-colors"
        >
          <Settings className="h-3 w-3" />
          Fix
        </a>
        <button
          onClick={() => setDismissed(true)}
          className="text-amber-400 hover:text-amber-300 transition-colors ml-2"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}