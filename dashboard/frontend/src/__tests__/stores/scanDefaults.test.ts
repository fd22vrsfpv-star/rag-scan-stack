import { describe, it, expect, beforeEach } from 'vitest'
import { useScanDefaultsStore } from '@/stores/scanDefaults'

describe('useScanDefaultsStore', () => {
  beforeEach(() => {
    // Reset to initial pentest profile state
    useScanDefaultsStore.getState().setActiveProfile('pentest')
    useScanDefaultsStore.setState({ toolOverrides: {} })
  })

  it('default profile is pentest', () => {
    expect(useScanDefaultsStore.getState().activeProfile).toBe('pentest')
  })

  it('pentest profile has expected defaults', () => {
    const state = useScanDefaultsStore.getState()
    expect(state.defaultPorts).toBe('--top-ports 100')
    expect(state.defaultRate).toBe('1000')
    expect(state.zapSpiderEnabled).toBe(true)
  })

  it('setActiveProfile switches to redteam defaults', () => {
    useScanDefaultsStore.getState().setActiveProfile('redteam')
    const state = useScanDefaultsStore.getState()
    expect(state.activeProfile).toBe('redteam')
    expect(state.defaultRate).toBe('100')
    expect(state.zapSpiderEnabled).toBe(false)
    expect(state.zapAttackStrength).toBe('LOW')
  })

  it('setActiveProfile back to pentest restores pentest defaults', () => {
    useScanDefaultsStore.getState().setActiveProfile('redteam')
    useScanDefaultsStore.getState().setActiveProfile('pentest')
    const state = useScanDefaultsStore.getState()
    expect(state.activeProfile).toBe('pentest')
    expect(state.defaultRate).toBe('1000')
    expect(state.zapAttackStrength).toBe('MEDIUM')
  })

  it('setToolOverride sets an override for a scan', () => {
    useScanDefaultsStore.getState().setToolOverride('nmap', 'rate', '500')
    const overrides = useScanDefaultsStore.getState().toolOverrides
    expect(overrides.nmap).toBeDefined()
    expect(overrides.nmap.rate).toBe('500')
  })

  it('clearToolOverride removes a specific override key', () => {
    useScanDefaultsStore.getState().setToolOverride('nmap', 'rate', '500')
    useScanDefaultsStore.getState().setToolOverride('nmap', 'ports', '80,443')
    useScanDefaultsStore.getState().clearToolOverride('nmap', 'rate')
    const overrides = useScanDefaultsStore.getState().toolOverrides
    expect(overrides.nmap.rate).toBeUndefined()
    expect(overrides.nmap.ports).toBe('80,443')
  })

  it('clearToolOverride removes the scan key entirely when last override is cleared', () => {
    useScanDefaultsStore.getState().setToolOverride('nmap', 'rate', '500')
    useScanDefaultsStore.getState().clearToolOverride('nmap', 'rate')
    const overrides = useScanDefaultsStore.getState().toolOverrides
    expect(overrides.nmap).toBeUndefined()
  })

  it('clearAllToolOverrides empties overrides', () => {
    useScanDefaultsStore.getState().setToolOverride('nmap', 'rate', '500')
    useScanDefaultsStore.getState().setToolOverride('nuclei', 'severity', 'critical')
    useScanDefaultsStore.getState().clearAllToolOverrides()
    expect(useScanDefaultsStore.getState().toolOverrides).toEqual({})
  })

  it('setActiveProfile to unknown name does nothing', () => {
    useScanDefaultsStore.getState().setActiveProfile('nonexistent')
    expect(useScanDefaultsStore.getState().activeProfile).toBe('pentest')
  })
})
