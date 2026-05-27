import { describe, it, expect } from 'vitest'
import { BUILD_VERSION, SEVERITY_LEVELS, SCAN_CATEGORIES } from '@/lib/constants'

// SCAN_FIELDS is also exported — import it to test scan field entries
import { SCAN_FIELDS } from '@/lib/constants'

describe('constants', () => {
  describe('BUILD_VERSION', () => {
    it('is a non-empty string', () => {
      expect(typeof BUILD_VERSION).toBe('string')
      expect(BUILD_VERSION.length).toBeGreaterThan(0)
    })

    it('matches date-based format (YYYY.MM.DD-N)', () => {
      expect(BUILD_VERSION).toMatch(/^\d{4}\.\d{2}\.\d{2}-\d+$/)
    })
  })

  describe('SEVERITY_LEVELS', () => {
    it('contains critical, high, medium, low, info', () => {
      expect(SEVERITY_LEVELS).toContain('critical')
      expect(SEVERITY_LEVELS).toContain('high')
      expect(SEVERITY_LEVELS).toContain('medium')
      expect(SEVERITY_LEVELS).toContain('low')
      expect(SEVERITY_LEVELS).toContain('info')
    })

    it('has at least 5 levels', () => {
      expect(SEVERITY_LEVELS.length).toBeGreaterThanOrEqual(5)
    })
  })

  describe('SCAN_FIELDS', () => {
    it('has entries for nmap', () => {
      expect(SCAN_FIELDS.nmap).toBeDefined()
      expect(Array.isArray(SCAN_FIELDS.nmap)).toBe(true)
      expect(SCAN_FIELDS.nmap.length).toBeGreaterThan(0)
    })

    it('has entries for masscan', () => {
      expect(SCAN_FIELDS.masscan).toBeDefined()
      expect(SCAN_FIELDS.masscan.length).toBeGreaterThan(0)
    })

    it('has entries for nuclei', () => {
      expect(SCAN_FIELDS.nuclei).toBeDefined()
      expect(SCAN_FIELDS.nuclei.length).toBeGreaterThan(0)
    })

    it('nmap fields include target', () => {
      const targetField = SCAN_FIELDS.nmap.find(f => f.key === 'target')
      expect(targetField).toBeDefined()
      expect(targetField!.type).toBe('text')
    })
  })

  describe('SCAN_CATEGORIES', () => {
    it('has Port Scanning category', () => {
      const portCat = SCAN_CATEGORIES.find(c => c.name === 'Port Scanning')
      expect(portCat).toBeDefined()
      expect(portCat!.scans.length).toBeGreaterThan(0)
    })

    it('has Recon category', () => {
      const reconCat = SCAN_CATEGORIES.find(c => c.name === 'Recon')
      expect(reconCat).toBeDefined()
    })
  })
})
