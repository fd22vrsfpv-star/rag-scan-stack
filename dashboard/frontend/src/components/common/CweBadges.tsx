import { cn } from '@/lib/utils'

const CWE_VULN_LABELS: Record<string, string> = {
  '78': 'cmdi', '77': 'cmdi', '94': 'cmdi',
  '89': 'sqli', '564': 'sqli',
  '79': 'xss', '80': 'xss',
  '22': 'lfi', '23': 'lfi', '36': 'lfi', '73': 'lfi',
  '918': 'ssrf',
  '611': 'xxe',
  '502': 'deser',
  '434': 'upload',
  '287': 'auth', '306': 'auth',
  '862': 'idor', '639': 'idor',
  '352': 'csrf',
  '798': 'secret', '259': 'secret', '321': 'secret',
  '90': 'ldap', '943': 'nosql',
}

function parseCwes(cwe: string | string[] | undefined | null): string[] {
  if (!cwe) return []
  if (Array.isArray(cwe)) return cwe.flatMap(c => parseCwes(c))
  return String(cwe).split(/[,;]\s*/).map(s => s.trim()).filter(Boolean)
}

function cweId(raw: string): string {
  const m = raw.match(/CWE-(\d+)/)
  return m ? m[1] : ''
}

export function CweBadges({ cwe, inline, className }: { cwe?: string | string[] | null; inline?: boolean; className?: string }) {
  const items = parseCwes(cwe)
  if (!items.length) return null

  return (
    <div className={cn('flex flex-wrap gap-0.5', inline ? 'inline-flex ml-1' : '', className)}>
      {items.slice(0, 4).map((c, i) => {
        const id = cweId(c)
        const label = id ? CWE_VULN_LABELS[id] : null
        const display = c.includes('CWE-') ? c.split(':')[0].trim() : c
        return (
          <span key={`${c}-${i}`}
            className="px-1.5 py-0 rounded text-[9px] border border-purple-500/30 bg-purple-500/10 text-purple-400"
            title={label ? `${display} (${label})` : display}>
            {display}{label ? ` ${label}` : ''}
          </span>
        )
      })}
      {items.length > 4 && <span className="text-[9px] text-muted-foreground">+{items.length - 4}</span>}
    </div>
  )
}
