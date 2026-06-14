import { NavLink, useLocation } from 'react-router-dom'
import { useUIStore, ALPHA_ROUTES } from '@/stores/ui'
import {
  LayoutDashboard, Network, Rocket, Activity, Bot, Server, Search, Swords, Workflow,
  FileText, MessageSquare, Wrench, BookOpen, Settings, ChevronLeft, ChevronRight, Shield, Globe2, Wifi,
  Briefcase, Crosshair, ShieldAlert, Flag, FlaskConical, Info, GitCompare, ChevronDown, Cloud, RefreshCw, Brain, Users, Newspaper,
} from 'lucide-react'
import { cn } from '@/lib/utils'
import { useEffect } from 'react'
import type { LucideIcon } from 'lucide-react'

interface NavItem {
  to: string
  icon: LucideIcon
  label: string
}

interface NavGroup {
  id: string
  icon: LucideIcon
  label: string
  children: NavItem[]
}

type NavEntry = NavItem | NavGroup

function isGroup(entry: NavEntry): entry is NavGroup {
  return 'children' in entry
}

const NAV_GROUPS: NavEntry[] = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },

  {
    id: 'operations', icon: Briefcase, label: 'Operations',
    children: [
      { to: '/engagements', icon: Briefcase, label: 'Engagements' },
      { to: '/scans/launch', icon: Rocket, label: 'Launch Scan' },
      { to: '/scans', icon: Activity, label: 'Scan Monitor' },
      { to: '/pipelines', icon: Workflow, label: 'Pipelines' },
      { to: '/agents', icon: Bot, label: 'AI Agents' },
      { to: '/agent-sessions', icon: Bot, label: 'Agent Sessions' },
    ],
  },
  {
    id: 'infrastructure', icon: Network, label: 'Infrastructure',
    children: [
      { to: '/services', icon: Network, label: 'Services' },
      { to: '/nodes', icon: Wifi, label: 'Remote Nodes' },
      // Targeted Recon moved into Scan Launcher > Smart Recon tab
    ],
  },
  {
    id: 'intelligence', icon: Search, label: 'Intelligence',
    children: [
      { to: '/assets', icon: Server, label: 'Assets' },
      { to: '/findings', icon: Search, label: 'Findings' },
      { to: '/follow-ups', icon: Flag, label: 'Follow-Ups' },
      { to: '/recommendations', icon: Crosshair, label: 'Recommendations' },
      { to: '/attack-map', icon: Workflow, label: 'Attack Map' },
      { to: '/recon', icon: Globe2, label: 'Recon' },
      { to: '/users', icon: Users, label: 'Users' },
      { to: '/delta', icon: GitCompare, label: 'Delta Compare' },
      { to: '/cloud-posture', icon: Cloud, label: 'Cloud Posture' },
      { to: '/content-intel', icon: Brain, label: 'Content Intel' },
      { to: '/news', icon: Newspaper, label: 'News' },
    ],
  },
  {
    id: 'offensive', icon: Swords, label: 'Offensive',
    children: [
      { to: '/exploits', icon: Swords, label: 'Exploits' },
      { to: '/api-tester', icon: FlaskConical, label: 'API Tester' },
      { to: '/opsec', icon: ShieldAlert, label: 'OpSec' },
    ],
  },
  {
    id: 'reporting', icon: FileText, label: 'Reporting',
    children: [
      { to: '/reports', icon: FileText, label: 'Reports' },
      { to: '/feedback', icon: MessageSquare, label: 'Feedback' },
    ],
  },
  {
    id: 'system', icon: Settings, label: 'System',
    children: [
      { to: '/maintenance', icon: Wrench, label: 'Maintenance' },
      { to: '/knowledge', icon: BookOpen, label: 'Knowledge Base' },
      { to: '/settings/kb-overrides', icon: Wrench, label: 'KB Overrides' },
      { to: '/settings', icon: Settings, label: 'Settings' },
      { to: '/sync', icon: RefreshCw, label: 'Sync' },
      { to: '/about', icon: Info, label: 'About' },
    ],
  },
]

function findGroupForPath(path: string): string | null {
  for (const entry of NAV_GROUPS) {
    if (isGroup(entry)) {
      for (const child of entry.children) {
        if (path === child.to || (child.to !== '/' && path.startsWith(child.to))) {
          return entry.id
        }
      }
    }
  }
  return null
}

function groupHasActiveChild(group: NavGroup, path: string): boolean {
  return group.children.some(
    c => path === c.to || (c.to !== '/' && path.startsWith(c.to))
  )
}

export function Sidebar() {
  const { sidebarCollapsed, toggleSidebar, openNavGroups, toggleNavGroup, openNavGroup, alphaTestingEnabled } = useUIStore()
  const location = useLocation()

  // Auto-open group containing active route
  useEffect(() => {
    const groupId = findGroupForPath(location.pathname)
    if (groupId) openNavGroup(groupId)
  }, [location.pathname, openNavGroup])

  return (
    <aside
      className={cn(
        'flex flex-col border-r border-border bg-card transition-all duration-200',
        sidebarCollapsed ? 'w-16' : 'w-56',
      )}
    >
      <div className="flex items-center gap-2 px-4 py-4 border-b border-border">
        <Shield className="h-6 w-6 text-primary shrink-0" />
        {!sidebarCollapsed && (
          <span className="font-bold text-sm tracking-tight">Pentest Dashboard</span>
        )}
      </div>

      <nav className="flex-1 py-2 px-2 overflow-y-auto">
        {NAV_GROUPS.map((entry) => {
          if (!isGroup(entry)) {
            // Standalone item (Dashboard)
            const { to, icon: Icon, label } = entry
            return (
              <NavLink
                key={to}
                to={to}
                end={to === '/'}
                className={({ isActive }) =>
                  cn(
                    'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors',
                    isActive
                      ? 'bg-primary/10 text-primary font-medium'
                      : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                  )
                }
              >
                <Icon className="h-4 w-4 shrink-0" />
                {!sidebarCollapsed && <span>{label}</span>}
              </NavLink>
            )
          }

          // Group
          const { id, icon: GroupIcon, label, children } = entry
          const isOpen = openNavGroups.includes(id)
          const hasActive = groupHasActiveChild(entry, location.pathname)

          return (
            <div key={id} className="mt-1">
              {/* Separator */}
              <div className="border-t border-border/50 mx-1 mb-1" />

              {/* Group header */}
              <button
                onClick={() => {
                  if (sidebarCollapsed) {
                    // Expand sidebar and open this group
                    toggleSidebar()
                    if (!isOpen) toggleNavGroup(id)
                  } else {
                    toggleNavGroup(id)
                  }
                }}
                className={cn(
                  'flex items-center w-full gap-3 px-3 py-1.5 rounded-md text-xs font-semibold uppercase tracking-wider transition-colors',
                  hasActive
                    ? 'text-primary/80'
                    : 'text-muted-foreground/60 hover:text-muted-foreground',
                )}
              >
                <GroupIcon className="h-4 w-4 shrink-0" />
                {!sidebarCollapsed && (
                  <>
                    <span className="flex-1 text-left">{label}</span>
                    <ChevronDown
                      className={cn(
                        'h-3 w-3 shrink-0 transition-transform duration-200',
                        !isOpen && '-rotate-90',
                      )}
                    />
                  </>
                )}
              </button>

              {/* Children */}
              {!sidebarCollapsed && isOpen && (
                <div className="space-y-0.5 mt-0.5">
                  {children.filter(c => alphaTestingEnabled || !ALPHA_ROUTES.has(c.to)).map(({ to, icon: Icon, label: childLabel }) => (
                    <NavLink
                      key={to}
                      to={to}
                      end={to === '/scans'}
                      className={({ isActive }) =>
                        cn(
                          'flex items-center gap-3 pl-8 pr-3 py-1.5 rounded-md text-sm transition-colors',
                          isActive
                            ? 'bg-primary/10 text-primary font-medium'
                            : 'text-muted-foreground hover:bg-accent hover:text-foreground',
                        )
                      }
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      <span>{childLabel}</span>
                    </NavLink>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </nav>

      <button
        onClick={toggleSidebar}
        className="flex items-center justify-center py-3 border-t border-border text-muted-foreground hover:text-foreground"
      >
        {sidebarCollapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
      </button>
    </aside>
  )
}
