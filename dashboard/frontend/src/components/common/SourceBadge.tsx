const SOURCE_COLORS: Record<string, string> = {
  // Recon tools
  subfinder: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  dnsx: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  httpx: 'bg-green-500/15 text-green-300 border-green-500/30',
  tlsx: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  whatweb: 'bg-teal-500/15 text-teal-300 border-teal-500/30',
  crtsh: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
  asnmap: 'bg-violet-500/15 text-violet-300 border-violet-500/30',
  // Scan tools
  nmap: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  masscan: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  portscan: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  nuclei: 'bg-red-500/15 text-red-300 border-red-500/30',
  nikto: 'bg-red-500/15 text-red-300 border-red-500/30',
  // Web tools
  gobuster: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30',
  katana: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  gowitness: 'bg-pink-500/15 text-pink-300 border-pink-500/30',
  playwright: 'bg-purple-500/15 text-purple-300 border-purple-500/30',
  zap: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
  ffuf: 'bg-lime-500/15 text-lime-300 border-lime-500/30',
  // OSINT
  wafw00f: 'bg-sky-500/15 text-sky-300 border-sky-500/30',
  gau: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30',
  waybackurls: 'bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30',
  trufflehog: 'bg-red-500/15 text-red-300 border-red-500/30',
  amass: 'bg-blue-500/15 text-blue-300 border-blue-500/30',
  censys: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/30',
  // Credentials
  brutus: 'bg-red-500/15 text-red-300 border-red-500/30',
  hashcat: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  // Metadata
  exif: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30',
  pdf: 'bg-amber-500/15 text-amber-300 border-amber-500/30',
  // Subdomain takeover + JS endpoints
  subzy: 'bg-red-500/15 text-red-300 border-red-500/30',
  golinkfinder: 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  // Service enumeration
  'email-enum': 'bg-pink-500/15 text-pink-300 border-pink-500/30',
  'dns-enum': 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  'service-enum': 'bg-violet-500/15 text-violet-300 border-violet-500/30',
  // Security audit tools
  'ssh-audit': 'bg-cyan-500/15 text-cyan-300 border-cyan-500/30',
  sslscan: 'bg-teal-500/15 text-teal-300 border-teal-500/30',
  testssl: 'bg-teal-500/15 text-teal-300 border-teal-500/30',
  sslyze: 'bg-teal-500/15 text-teal-300 border-teal-500/30',
  vulscan: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  vulners: 'bg-orange-500/15 text-orange-300 border-orange-500/30',
  burpsuite: 'bg-rose-500/15 text-rose-300 border-rose-500/30',
  // Other
  manual: 'bg-gray-500/15 text-gray-300 border-gray-500/30',
  'content-recon': 'bg-purple-500/15 text-purple-300 border-purple-500/30',
}

const DEFAULT_COLOR = 'bg-zinc-500/15 text-zinc-300 border-zinc-500/30'

export function SourceBadge({ source, className }: { source: string; className?: string }) {
  const color = SOURCE_COLORS[source] || DEFAULT_COLOR
  return (
    <span className={`inline-block px-1.5 py-0.5 rounded text-[11px] font-mono font-medium border ${color} ${className || ''}`}>
      {source}
    </span>
  )
}
