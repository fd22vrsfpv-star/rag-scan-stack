import { apiUrl } from '@/api/client'

function openScreenshotPopup(src: string) {
  const w = Math.min(1440, window.screen.width - 100)
  const h = Math.min(900, window.screen.height - 100)
  const left = (window.screen.width - w) / 2
  const top = (window.screen.height - h) / 2
  window.open(src, '_blank', `width=${w},height=${h},left=${left},top=${top},toolbar=no,menubar=no,scrollbars=yes,resizable=yes`)
}

/** Standard thumbnail with filename — for grids and detail panels */
export function ScreenshotThumbnail({ path, filename }: { path: string; filename: string }) {
  const src = `${apiUrl}/screenshots/${path}`

  return (
    <button
      onClick={() => openScreenshotPopup(src)}
      className="block border border-border rounded overflow-hidden hover:border-primary transition-colors text-left w-full group"
    >
      <img src={src} alt={filename} className="w-full h-auto" loading="lazy" />
      <div className="px-2 py-1 text-[10px] text-muted-foreground truncate bg-muted group-hover:text-foreground">{filename}</div>
    </button>
  )
}

/** Micro thumbnail for inline display in table rows — 48x30px clickable preview */
export function MicroScreenshot({ path, alt }: { path: string; alt?: string }) {
  const src = `${apiUrl}/screenshots/${path}`

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
