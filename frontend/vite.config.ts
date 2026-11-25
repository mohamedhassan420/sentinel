import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  // "@/..." in imports means "frontend/src/..."
  resolve: { alias: { '@': path.resolve(import.meta.dirname, 'src') } },
  // In development the React app runs on its own port, so requests to /api
  // are passed on to the Python backend.
  server: { proxy: { '/api': 'http://localhost:8000' } },
})
