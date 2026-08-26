import { useCustomerHosts } from '@/api/recon'
import { cn } from '@/lib/utils'

/**
 * "Customer" indicator — marks a host as a customer-owned site (detected by
 * TLS cert / CNAME registrable-domain mismatch, or confirmed into customer_scope).
 * Renders nothing for non-customer hosts. Backed by a single cached
 * /recon/customer-hosts fetch, so it can be dropped into any host row.
 */
export function CustomerBadge({ host, className }: { host?: string | null; className?: string }) {
  const { data } = useCustomerHosts()
  if (!host) return null
  const h = host.replace(/^https?:\/\//, '').split('/')[0].split(':')[0].trim().toLowerCase()
  const info = data?.hosts?.[h]
  if (!info) return null
  const title = info.owner_domain
    ? `Customer-owned site — owner ${info.owner_domain}${info.registrant_org ? ` (${info.registrant_org})` : ''}`
    : 'Customer-owned site (out of scope)'
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium',
        'border border-purple-500/40 bg-purple-500/10 text-purple-400',
        className,
      )}
    >
      Customer
    </span>
  )
}
