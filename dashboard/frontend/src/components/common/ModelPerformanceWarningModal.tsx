import { AlertTriangle, Zap, X, CheckCircle, AlertCircle } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { ModelPerformanceWarning } from '@/api/agents'

interface ModelPerformanceWarningModalProps {
  onClose: () => void
  onContinue: () => void
  warning: ModelPerformanceWarning
  isLoading?: boolean
}

export function ModelPerformanceWarningModal({
  onClose,
  onContinue,
  warning,
  isLoading = false,
}: ModelPerformanceWarningModalProps) {
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'error':
        return <AlertTriangle className="h-5 w-5 text-red-500" />
      case 'warning':
        return <AlertCircle className="h-5 w-5 text-yellow-500" />
      default:
        return <CheckCircle className="h-5 w-5 text-blue-500" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'error':
        return 'border-red-500/30 bg-red-500/10'
      case 'warning':
        return 'border-yellow-500/30 bg-yellow-500/10'
      default:
        return 'border-blue-500/30 bg-blue-500/10'
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black bg-opacity-50"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative w-full max-w-lg mx-4 bg-card border border-border rounded-lg shadow-xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <div className="flex items-center gap-3">
            {getSeverityIcon(warning.severity)}
            <h3 className="text-lg font-medium text-foreground">
              AI Agent Model Performance Check
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md hover:bg-muted text-muted-foreground hover:text-foreground"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="px-6 py-4 space-y-4">
          {/* Current Model Info */}
          <div className={cn('rounded-lg border p-4', getSeverityColor(warning.severity))}>
            <div className="flex items-center gap-2 mb-2">
              <Zap className="h-4 w-4" />
              <span className="font-medium text-sm">Current Model: {warning.current_model}</span>
            </div>
            {warning.estimated_memory_gb && (
              <div className="text-xs text-muted-foreground">
                Estimated Memory: {warning.estimated_memory_gb.toFixed(1)}GB
              </div>
            )}
            {warning.gpu_memory_usage && warning.gpu_memory_total && (
              <div className="text-xs text-muted-foreground">
                GPU Memory: {warning.gpu_memory_usage.toFixed(1)}GB / {warning.gpu_memory_total.toFixed(1)}GB
                ({Math.round((warning.gpu_memory_usage / warning.gpu_memory_total) * 100)}%)
              </div>
            )}
          </div>

          {/* Warnings */}
          {warning.warnings && warning.warnings.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium text-foreground flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-yellow-500" />
                Performance Concerns
              </h4>
              <ul className="space-y-1">
                {warning.warnings.map((warn, idx) => (
                  <li key={idx} className="text-sm text-muted-foreground pl-6 relative">
                    <span className="absolute left-2 top-1.5 w-1.5 h-1.5 bg-yellow-500 rounded-full" />
                    {warn}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommendations */}
          {warning.recommendations && warning.recommendations.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-sm font-medium text-foreground flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                Recommendations
              </h4>
              <ul className="space-y-1">
                {warning.recommendations.map((rec, idx) => (
                  <li key={idx} className="text-sm text-muted-foreground pl-6 relative">
                    <span className="absolute left-2 top-1.5 w-1.5 h-1.5 bg-green-500 rounded-full" />
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Info message for no warnings */}
          {!warning.has_warnings && (
            <div className="text-sm text-muted-foreground">
              Your current model appears to be optimized for agent-based scans. No performance concerns detected.
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-border">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm border border-border rounded-md hover:bg-muted text-foreground"
            disabled={isLoading}
          >
            Cancel
          </button>
          <button
            onClick={onContinue}
            disabled={isLoading}
            className={cn(
              'px-4 py-2 text-sm rounded-md disabled:opacity-50',
              warning.severity === 'error'
                ? 'bg-red-600 hover:bg-red-700 text-white'
                : warning.severity === 'warning'
                  ? 'bg-yellow-600 hover:bg-yellow-700 text-white'
                  : 'bg-primary hover:bg-primary/90 text-primary-foreground',
            )}
          >
            {isLoading ? 'Starting...' : warning.has_warnings ? 'Continue Anyway' : 'Start Session'}
          </button>
        </div>
      </div>
    </div>
  )
}