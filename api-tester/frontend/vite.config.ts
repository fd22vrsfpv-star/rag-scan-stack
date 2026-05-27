import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    proxy: {
      '/api-collections': 'http://localhost:8090',
      '/api-test': 'http://localhost:8090',
      '/api-param-configs': 'http://localhost:8090',
    },
  },
})
