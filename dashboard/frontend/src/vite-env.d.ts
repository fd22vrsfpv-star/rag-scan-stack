/// <reference types="vite/client" />

// Ambient module shim for `react-qr-code`.  The package ships type
// declarations at types/index.d.ts but its package.json `exports` field
// doesn't surface them under bundler resolution, so TS7016 ("implicit
// any") fires at the import site even with skipLibCheck=true.  Uses
// SVGProps<SVGSVGElement> so callers can pass through any SVG attribute.
declare module 'react-qr-code' {
  import { ComponentType, SVGProps } from 'react'
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
