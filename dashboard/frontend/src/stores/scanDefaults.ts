import { create } from 'zustand'
import { persist } from 'zustand/middleware'

// ── Profile types ───────────────────────────────────

export interface ProfileDefaults {
  defaultPorts: string
  defaultRate: string
  gobusterWordlist: string
  gobusterExtensions: string
  zapAttackStrength: string
  zapSpiderEnabled: boolean
}

export interface ScanProfile {
  name: string
  description: string
  builtin: boolean
  defaults: ProfileDefaults
  toolOverrides: Record<string, Record<string, string>>
}

// ── Built-in presets ────────────────────────────────

const PENTEST_PROFILE: ScanProfile = {
  name: 'pentest',
  description: 'Standard penetration testing — balanced speed and coverage',
  builtin: true,
  defaults: {
    defaultPorts: '--top-ports 100',
    defaultRate: '1000',
    gobusterWordlist: 'medium',
    gobusterExtensions: 'php,html,txt',
    zapAttackStrength: 'MEDIUM',
    zapSpiderEnabled: true,
  },
  toolOverrides: {
    masscan: { ports: '0-65535' },
  },
}

const REDTEAM_PROFILE: ScanProfile = {
  name: 'redteam',
  description: 'Low-and-slow stealth — reduced rates, minimal footprint, IDS/WAF evasion. Based on red team best practices for avoiding Snort/Suricata detection.',
  builtin: true,
  defaults: {
    defaultPorts: '80,443,8080,8443,22,3389,445,3306,5432',
    defaultRate: '100',
    gobusterWordlist: 'small',
    gobusterExtensions: 'php,html',
    zapAttackStrength: 'LOW',
    zapSpiderEnabled: false,
  },
  toolOverrides: {
    // Port scanning — stay under IDS rate thresholds (~500pps triggers Snort)
    masscan: { rate: '100' },
    nmap: { rate: '100', ports: '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443' },
    'nmap-tcp': { rate: '100', ports: '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080,8443' },
    full: { rate: '100' },
    naabu: { rate: '50' },
    // Vulnerability scanning — template-spray, low concurrency, critical only
    nuclei: { severity: 'high,critical', rate: '20' },
    // Web brute-force — low threads, small wordlists to avoid WAF rate-limiting
    gobuster: { wordlist: 'small', timeout_sec: '900' },
    ffuf: { rate: '10' },
    // Web crawling — shallow depth, low rate
    katana: { depth: '2' },
    httpx: { rate: '20' },
    // Content recon — conservative, passive-focused
    'content-recon': { spider_depth: '2', max_playwright_urls: '15', run_gobuster: 'false', screenshot_all: 'false' },
    // Web pipeline — skip noisy tools
    pipeline: { wordlist: 'small', max_paths: '20' },
    // Browser scan — longer timeout, passive ZAP
    playwright: { timeout: '60', zap_spider: 'false', zap_active_scan: 'false' },
    // Nikto — add pause between requests
    nikto: { tuning: '1234' },
    // OSINT — these are mostly passive, keep defaults
  },
}

const BUILTIN_PROFILES: Record<string, ScanProfile> = {
  pentest: PENTEST_PROFILE,
  redteam: REDTEAM_PROFILE,
}

// ── Store interface ─────────────────────────────────

interface ScanDefaults {
  // Global (non-profile) settings
  defaultTargets: string
  defaultScope: string
  exploitProxy: string
  exploitProxyEnabled: boolean
  chatSystemPrompt: string
  llmBackend: string

  // Profile-managed settings (read from active profile)
  defaultPorts: string
  defaultRate: string
  gobusterWordlist: string
  gobusterExtensions: string
  zapAttackStrength: string
  zapSpiderEnabled: boolean
  toolOverrides: Record<string, Record<string, string>>

  // Profile management
  activeProfile: string
  profiles: Record<string, ScanProfile>

  // Actions
  setDefaults(d: Partial<Record<string, unknown>>): void
  setToolOverride(scanId: string, key: string, value: string): void
  clearToolOverride(scanId: string, key: string): void
  clearAllToolOverrides(): void
  setActiveProfile(name: string): void
  saveProfile(name: string, description: string): void
  deleteProfile(name: string): void
}

export const useScanDefaultsStore = create<ScanDefaults>()(
  persist(
    (set, get) => ({
      // Global settings
      defaultTargets: '',
      defaultScope: '',
      exploitProxy: '',
      exploitProxyEnabled: false,
      chatSystemPrompt: 'Always use your tools to query real scan data before answering. Prioritize findings, assets, and recon results already collected in the dashboard over general knowledge. Reference specific ports, CVEs, and severities from actual scan output.',
      llmBackend: '',  // empty = use env var default

      // Profile-managed (initialized from pentest preset)
      defaultPorts: PENTEST_PROFILE.defaults.defaultPorts,
      defaultRate: PENTEST_PROFILE.defaults.defaultRate,
      gobusterWordlist: PENTEST_PROFILE.defaults.gobusterWordlist,
      gobusterExtensions: PENTEST_PROFILE.defaults.gobusterExtensions,
      zapAttackStrength: PENTEST_PROFILE.defaults.zapAttackStrength,
      zapSpiderEnabled: PENTEST_PROFILE.defaults.zapSpiderEnabled,
      toolOverrides: {},

      // Profile state
      activeProfile: 'pentest',
      profiles: { ...BUILTIN_PROFILES },

      // Actions
      setDefaults: (d) => set(d as Partial<ScanDefaults>),

      setToolOverride: (scanId, key, value) =>
        set((state) => {
          const newOverrides = {
            ...state.toolOverrides,
            [scanId]: { ...state.toolOverrides[scanId], [key]: value },
          }
          // Auto-save to active profile if custom
          const profiles = { ...state.profiles }
          const p = profiles[state.activeProfile]
          if (p && !p.builtin) {
            profiles[state.activeProfile] = { ...p, toolOverrides: newOverrides }
          }
          return { toolOverrides: newOverrides, profiles }
        }),

      clearToolOverride: (scanId, key) =>
        set((state) => {
          const scanOverrides = { ...state.toolOverrides[scanId] }
          delete scanOverrides[key]
          const toolOverrides = { ...state.toolOverrides }
          if (Object.keys(scanOverrides).length === 0) {
            delete toolOverrides[scanId]
          } else {
            toolOverrides[scanId] = scanOverrides
          }
          return { toolOverrides }
        }),

      clearAllToolOverrides: () => set({ toolOverrides: {} }),

      setActiveProfile: (name) => {
        const state = get()
        const profile = state.profiles[name] || BUILTIN_PROFILES[name]
        if (!profile) return
        set({
          activeProfile: name,
          defaultPorts: profile.defaults.defaultPorts,
          defaultRate: profile.defaults.defaultRate,
          gobusterWordlist: profile.defaults.gobusterWordlist,
          gobusterExtensions: profile.defaults.gobusterExtensions,
          zapAttackStrength: profile.defaults.zapAttackStrength,
          zapSpiderEnabled: profile.defaults.zapSpiderEnabled,
          toolOverrides: { ...profile.toolOverrides },
        })
      },

      saveProfile: (name, description) =>
        set((state) => {
          const profile: ScanProfile = {
            name,
            description,
            builtin: false,
            defaults: {
              defaultPorts: state.defaultPorts,
              defaultRate: state.defaultRate,
              gobusterWordlist: state.gobusterWordlist,
              gobusterExtensions: state.gobusterExtensions,
              zapAttackStrength: state.zapAttackStrength,
              zapSpiderEnabled: state.zapSpiderEnabled,
            },
            toolOverrides: { ...state.toolOverrides },
          }
          return {
            activeProfile: name,
            profiles: { ...state.profiles, [name]: profile },
          }
        }),

      deleteProfile: (name) =>
        set((state) => {
          if (BUILTIN_PROFILES[name]) return state // Can't delete built-in
          const profiles = { ...state.profiles }
          delete profiles[name]
          // If deleting active profile, switch to pentest
          const activeProfile = state.activeProfile === name ? 'pentest' : state.activeProfile
          const fallback = profiles[activeProfile] || PENTEST_PROFILE
          return {
            profiles,
            activeProfile,
            defaultPorts: fallback.defaults.defaultPorts,
            defaultRate: fallback.defaults.defaultRate,
            gobusterWordlist: fallback.defaults.gobusterWordlist,
            gobusterExtensions: fallback.defaults.gobusterExtensions,
            zapAttackStrength: fallback.defaults.zapAttackStrength,
            zapSpiderEnabled: fallback.defaults.zapSpiderEnabled,
            toolOverrides: { ...fallback.toolOverrides },
          }
        }),
    }),
    {
      name: 'scan-defaults',
      version: 5,
      migrate: (persisted: unknown, version: number) => {
        const state = persisted as Record<string, unknown>
        if (version < 1 && !state.chatSystemPrompt) {
          state.chatSystemPrompt = 'Always use your tools to query real scan data before answering. Prioritize findings, assets, and recon results already collected in the dashboard over general knowledge. Reference specific ports, CVEs, and severities from actual scan output.'
        }
        if (version < 2 && !state.toolOverrides) {
          state.toolOverrides = {}
        }
        if (version < 3) {
          // Migrate to profile system — preserve existing settings as pentest profile
          state.activeProfile = 'pentest'
          state.profiles = { ...BUILTIN_PROFILES }
        }
        if (version < 5) {
          // Update default ports: nmap→top-ports 100, masscan→0-65535
          state.defaultPorts = '--top-ports 100'
          state.profiles = { ...BUILTIN_PROFILES }
          // Apply pentest profile toolOverrides (masscan→0-65535)
          state.toolOverrides = { masscan: { ports: '0-65535' } }
        }
        return state
      },
    },
  ),
)
