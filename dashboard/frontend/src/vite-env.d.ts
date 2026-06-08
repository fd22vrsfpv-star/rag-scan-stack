/// <reference types="vite/client" />

// Ambient module shim for `react-qr-code`.  The package ships type
// declarations at types/index.d.ts but its package.json `exports` field
// doesn't surface them under bundler resolution, so TS7016 ("implicit
// any") fires at the import site even with skipLibCheck=true.  This
// shim declares the minimal prop shape the dashboard uses (only `value`
// is required; the rest are passed through to the underlying SVG).
declare module 'react-qr-code' {
  import { ComponentType, SVGProps } from 'react'
  // Spread SVGProps<SVGSVGElement> so callers can pass through any SVG
  // attribute (viewBox, role, etc.) the package forwards to its <svg>.
  export interface QRCodeProps extends SVGProps<SVGSVGElement> {
    value: string
    size?: number
    level?: 'L' | 'M' | 'Q' | 'H'
    bgColor?: string
    fgColor?: string
    title?: string
  }
  const QRCode: ComponentType<QRCodeProps>
  export default QRCode
}
