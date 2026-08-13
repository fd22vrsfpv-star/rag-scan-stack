import { useRef, useState } from 'react'
import { useWebImportFormats, useImportWebScan, type WebImportResult } from '@/api/webScanImport'
import { cn } from '@/lib/utils'
import { Upload, FileUp, CheckCircle2, AlertCircle } from 'lucide-react'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-600/15 text-red-400',
  high: 'bg-red-500/10 text-red-400',
  medium: 'bg-orange-500/10 text-orange-400',
  low: 'bg-yellow-500/10 text-yellow-400',
  info: 'bg-blue-500/10 text-blue-400',
}

/**
 * Upload a web scan report from another tool (ZAP, Nikto, Burp, Nuclei).
 *
 * The tool is auto-detected from the file's contents, so the operator doesn't
 * have to classify it — but an override is offered for unusual exports.
 */
export function WebScanImportPanel() {
  const { data: formats } = useWebImportFormats()
  const importScan = useImportWebScan()
  const inputRef = useRef<HTMLInputElement>(null)
  const [tool, setTool] = useState('')          // '' = auto-detect
  const [dragging, setDragging] = useState(false)
  const [result, setResult] = useState<WebImportResult | null>(null)
  const [error, setError] = useState('')

  const submit = async (file: File) => {
    setError('')
    setResult(null)
    try {
      setResult(await importScan.mutateAsync({ file, tool: tool || undefined }))
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const file = e.dataTransfer.files?.[0]
    if (file) submit(file)
  }

  const maxMb = formats ? Math.round(formats.max_bytes / (1024 * 1024)) : null

  return (
    <div className="bg-card border border-border rounded-lg p-3 space-y-2">
      <h3 className="text-sm font-semibold flex items-center gap-1.5">
        <FileUp className="h-4 w-4" /> Import a web scan report
      </h3>
      <p className="text-xs text-muted-foreground">
        Drop a report from another tool and its findings are normalized into this
        stack. The scanner is detected from the file contents, so the filename
        doesn&apos;t matter. Re-importing the same report is safe — findings
        deduplicate against what&apos;s already stored.
      </p>

      <div className="flex items-center gap-2 flex-wrap">
        <label className="text-xs text-muted-foreground">Parser:</label>
        <select
          value={tool}
          onChange={e => setTool(e.target.value)}
          className="bg-muted rounded px-2 py-1 text-xs border border-border"
        >
          <option value="">Auto-detect</option>
          {(formats?.tools ?? []).map(t => (
            <option key={t.id} value={t.id}>{t.label} ({t.formats.join('/')})</option>
          ))}
        </select>
        {maxMb && <span className="text-[10px] text-muted-foreground">max {maxMb}MB</span>}
      </div>

      <div
        onDragOver={e => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        className={cn(
          'border-2 border-dashed rounded-lg p-5 text-center cursor-pointer transition-colors',
          dragging ? 'border-primary bg-primary/5' : 'border-border hover:border-primary/50',
        )}
      >
        <Upload className="h-5 w-5 mx-auto text-muted-foreground mb-1" />
        <p className="text-xs">
          {importScan.isPending
            ? 'Importing…'
            : 'Drop a report here, or click to choose a file'}
        </p>
        <p className="text-[10px] text-muted-foreground mt-1">
          {(formats?.tools ?? []).map(t => `${t.label} ${t.formats.join('/')}`).join(' · ')}
        </p>
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          accept=".xml,.json,.jsonl,.txt"
          onChange={e => {
            const f = e.target.files?.[0]
            if (f) submit(f)
            e.target.value = ''      // allow re-selecting the same file
          }}
        />
      </div>

      {error && (
        <div className="flex items-start gap-1.5 text-xs text-red-400">
          <AlertCircle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
          <span className="break-words">{error}</span>
        </div>
      )}

      {result && (
        <div className="space-y-1.5">
          <div className="flex items-center gap-1.5 text-xs text-green-400">
            <CheckCircle2 className="h-3.5 w-3.5" />
            Imported as <strong>{result.tool}</strong>
            {result.stats.format && ` (${result.stats.format})`} —
            <strong>{result.stats.inserted}</strong> new finding
            {result.stats.inserted === 1 ? '' : 's'}
          </div>
          <div className="flex flex-wrap gap-1">
            {Object.entries(result.stats.by_severity ?? {}).map(([sev, n]) => (
              <span key={sev} className={cn(
                'px-1.5 py-0.5 rounded text-[10px]',
                SEVERITY_COLORS[sev] ?? 'bg-muted text-muted-foreground',
              )}>
                {sev}: {n}
              </span>
            ))}
          </div>
          {/* Skips are normal, not failures — say so plainly. */}
          <p className="text-[10px] text-muted-foreground">
            {result.stats.skipped_duplicate > 0 &&
              `${result.stats.skipped_duplicate} already known. `}
            {!!result.stats.skipped_false_positive &&
              `${result.stats.skipped_false_positive} marked false-positive by the scanner. `}
            {!!result.stats.skipped_no_url &&
              `${result.stats.skipped_no_url} had no URL. `}
            {result.stats.errors?.length > 0 &&
              `${result.stats.errors.length} row(s) failed to insert.`}
          </p>
        </div>
      )}
    </div>
  )
}
