import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/api/client'
import { useAssignToScope, useMoveToScope } from '@/api/findings'
import { Globe, X, ArrowRight } from 'lucide-react'

interface ScopeAssignModalProps {
  targets: { target: string; target_type?: string }[]
  fromScope?: string // If set, performs a MOVE (remove from this scope, add to new)
  onClose: () => void
  onSuccess?: () => void
  label?: string
}

export function ScopeAssignModal({ targets, fromScope, onClose, onSuccess, label }: ScopeAssignModalProps) {
  const [scopeName, setScopeName] = useState('')
  const assign = useAssignToScope()
  const move = useMoveToScope()
  const isMoving = !!fromScope

  // Fetch existing scopes for quick-pick
  const { data: scopesData } = useQuery({
    queryKey: ['scope-names'],
    queryFn: () => apiFetch<{ names: { name: string; target_count: number }[] }>('/scope/names'),
  })
  const scopes = (scopesData?.names ?? [])
    .map(s => ({ name: s.name, count: s.target_count }))
    .filter(s => s.name !== fromScope) // Don't show the source scope as a destination

  const handleAssign = () => {
    if (!scopeName.trim()) return
    if (isMoving) {
      move.mutate(
        { fromScope: fromScope!, toScope: scopeName.trim(), targets: targets.map(t => t.target) },
        { onSuccess: () => { onSuccess?.(); onClose() } },
      )
    } else {
      assign.mutate(
        { scopeName: scopeName.trim(), targets },
        { onSuccess: () => { onSuccess?.(); onClose() } },
      )
    }
  }

  const isPending = assign.isPending || move.isPending

  return (
    <div className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center" onClick={onClose}>
      <div className="bg-card border border-border rounded-lg p-4 w-96 max-h-[80vh] overflow-y-auto shadow-xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Globe className="h-4 w-4 text-primary" />
            {isMoving ? 'Move to Scope' : 'Assign to Scope'}
          </h3>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>

        {isMoving && (
          <div className="flex items-center gap-2 text-xs mb-3 px-2 py-1.5 bg-amber-500/10 border border-amber-500/30 rounded">
            <span className="font-mono text-amber-300">{fromScope}</span>
            <ArrowRight className="h-3 w-3 text-muted-foreground" />
            <span className="font-mono text-primary">{scopeName || '...'}</span>
          </div>
        )}

        <p className="text-xs text-muted-foreground mb-3">
          {label || `${targets.length} item(s) selected`}
        </p>

        {/* Scope name input */}
        <input
          placeholder="Scope name (e.g. customer_apps)"
          value={scopeName}
          onChange={e => setScopeName(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleAssign()}
          className="w-full bg-background rounded-md px-3 py-2 text-sm border border-border outline-none focus:border-primary mb-3"
          autoFocus
        />

        {/* Quick-pick existing scopes */}
        {scopes.length > 0 && (
          <div className="mb-3">
            <span className="text-[10px] text-muted-foreground">Existing scopes:</span>
            <div className="flex flex-wrap gap-1.5 mt-1 max-h-32 overflow-y-auto">
              {scopes.map(s => (
                <button
                  key={s.name}
                  onClick={() => setScopeName(s.name)}
                  className={`px-2 py-0.5 text-xs rounded border transition-colors ${
                    scopeName === s.name
                      ? 'border-primary bg-primary/10 text-primary'
                      : 'border-border bg-muted text-muted-foreground hover:border-primary/50'
                  }`}
                >
                  {s.name} ({s.count})
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Preview targets */}
        <div className="mb-3">
          <span className="text-[10px] text-muted-foreground">Targets to {isMoving ? 'move' : 'assign'}:</span>
          <div className="bg-background rounded border border-border p-2 mt-1 max-h-24 overflow-y-auto">
            {targets.slice(0, 20).map((t, i) => (
              <div key={i} className="text-xs font-mono truncate">{t.target}</div>
            ))}
            {targets.length > 20 && <div className="text-xs text-muted-foreground">+{targets.length - 20} more</div>}
          </div>
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="px-3 py-1.5 text-xs rounded border border-border bg-background hover:bg-accent">
            Cancel
          </button>
          <button
            onClick={handleAssign}
            disabled={!scopeName.trim() || isPending}
            className="px-3 py-1.5 text-xs rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {isPending ? (isMoving ? 'Moving...' : 'Assigning...') : isMoving ? `Move to "${scopeName || '...'}"` : `Assign to "${scopeName || '...'}"` }
          </button>
        </div>

        {(assign.error || move.error) && <p className="text-xs text-red-500 mt-2">{String(assign.error || move.error)}</p>}
      </div>
    </div>
  )
}
