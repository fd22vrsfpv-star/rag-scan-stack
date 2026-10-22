import { cn } from '@/lib/utils'
import { apiUrl } from '@/api/client'

function openScreenshotPopup(src: string) {
  const w = Math.min(1440, window.screen.width - 100)
  const h = Math.min(900, window.screen.height - 100)
  const left = (window.screen.width - w) / 2
  const top = (window.screen.height - h) / 2
  window.open(src, '_blank', `width=${w},height=${h},left=${left},top=${top},toolbar=no,menubar=no,scrollbars=yes,resizable=yes`)
}

/** Standard thumbnail with filename — for grids and detail panels */
/** Colour by HTTP class: 2xx ok, 3xx redirect, 4xx client, 5xx server. */
function statusTone(code?: number) {
  if (!code) return 'text-muted-foreground'
  if (code < 300) return 'text-emerald-400'
  if (code < 400) return 'text-sky-400'
  if (code < 500) return 'text-amber-400'
  return 'text-red-400'
}

export function ScreenshotThumbnail({ path, filename, statusCode, title }: {
  path: string
  filename: string
  /** GoWitness `response_code` for this capture, when it still has a record.
   *  Undefined means "unknown", which is rendered as nothing — a screenshot
   *  with no surviving report must not borrow another page's status. */
  statusCode?: number
  title?: string
}) {
  const src = apiUrl(`/screenshots/${path}`)

  return (
    <button
      onClick={() => openScreenshotPopup(src)}
      className="block border border-border rounded overflow-hidden hover:border-primary transition-colors text-left w-full group"
      title={title ? `${title} — ${filename}` : filename}
    >
      {/* The page preview itself. Fixed height + object-top so every tile is
          the same size and shows the top of the page, which is the part that
          identifies it. `alt` stays short: when the image cannot load, a long
          filename rendered as alt text is what made these tiles look like a
          wall of text rather than a broken image. */}
      <img
        src={src}
        alt=""
        className="w-full h-28 object-cover object-top bg-muted"
        loading="lazy"
      />
      <div className="px-2 py-1 bg-muted group-hover:text-foreground flex items-center gap-1.5">
        {statusCode ? (
          <span className={cn('text-[10px] font-semibold tabular-nums', statusTone(statusCode))}>
            {statusCode}
          </span>
        ) : null}
        <span className="text-[10px] text-muted-foreground truncate">
          {title || filename}
        </span>
      </div>
    </button>
  )
}

/** Micro thumbnail for inline display in table rows — 48x30px clickable preview */
export function MicroScreenshot({ path, alt }: { path: string; alt?: string }) {
  const src = apiUrl(`/screenshots/${path}`)

  return (
    <button
      onClick={e => { e.stopPropagation(); openScreenshotPopup(src) }}
      className="inline-block border border-border rounded overflow-hidden hover:border-primary transition-colors shrink-0"
      title={alt || 'Click to view screenshot'}
    >
      <img src={src} alt={alt || ''} className="w-12 h-8 object-cover object-top" loading="lazy" />
    </button>
  )
}
