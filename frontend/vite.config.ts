import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    host: '0.0.0.0',
    proxy: {
      '/api': 'http://localhost:8080',
      '/t': 'http://localhost:8080',
      '/r': 'http://localhost:8080',
      '/f': 'http://localhost:8080',
      '/k': 'http://localhost:8080',
      '/healthz': 'http://localhost:8080',
      '/admin': 'http://localhost:8080'
    }
  }
})
