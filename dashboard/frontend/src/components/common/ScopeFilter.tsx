import { useScopeNames } from '@/api/scope'
import { Globe } from 'lucide-react'

interface ScopeFilterProps {
  value: string
  onChange: (scope: string) => void
  className?: string
}

export function ScopeFilter({ value, onChange, className }: ScopeFilterProps) {
  // useScopeNames is already engagement-aware:
  // - with engagement selected: returns that engagement's scopes
  // - without engagement: returns all global scopes
  const { data } = useScopeNames()
  const scopes = data?.names ?? []

  return (
    <div className={`flex items-center gap-1.5 ${className || ''}`}>
      <Globe className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
      <select
        value={value}
        onChange={e => onChange(e.target.value)}
        className="bg-muted rounded-md px-2 py-1 text-xs border border-border outline-none focus:border-primary max-w-[200px]"
      >
        <option value="">All Scopes</option>
        {scopes.map(s => (
          <option key={s.name} value={s.name}>
            {s.name} ({s.target_count})
          </option>
        ))}
      </select>
    </div>
  )
}
