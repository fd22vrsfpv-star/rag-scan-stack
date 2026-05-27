/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        background: '#0a0a0a',
        foreground: '#fafafa',
        card: '#111111',
        border: '#27272a',
        primary: { DEFAULT: '#3b82f6', foreground: '#ffffff' },
        muted: { DEFAULT: '#1c1c1e', foreground: '#a1a1aa' },
        accent: { DEFAULT: '#1c1c1e', foreground: '#fafafa' },
        destructive: { DEFAULT: '#ef4444', foreground: '#ffffff' },
      },
    },
  },
  plugins: [],
}
