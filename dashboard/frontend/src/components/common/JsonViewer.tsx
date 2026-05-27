import { useState } from 'react'
import { ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'

export function JsonViewer({ data, maxHeight = '300px' }: { data: unknown; maxHeight?: string }) {
  const [expanded, setExpanded] = useState(false)
  const [copied, setCopied] = useState(false)
  const json = JSON.stringify(data, null, 2)

  const handleCopy = () => {
    navigator.clipboard.writeText(json)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="border border-border rounded-md">
      <div className="flex items-center justify-between px-3 py-1.5 bg-muted/50">
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground"
        >
          {expanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
          <span>JSON</span>
        </button>
        <button onClick={handleCopy} className="text-muted-foreground hover:text-foreground">
          {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
        </button>
      </div>
      {expanded && (
        <pre
          className="px-3 py-2 text-[11px] font-mono overflow-auto bg-background"
          style={{ maxHeight }}
        >
          {json}
        </pre>
      )}
    </div>
  )
}
