import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(d: string | Date): string {
  return new Date(d).toLocaleString()
}

export function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + '...' : s
}
