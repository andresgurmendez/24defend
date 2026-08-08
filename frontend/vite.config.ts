import path from 'node:path'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
//
// No dev proxy: the backend has CORSMiddleware (allow_credentials=True,
// explicit origins) so the SPA talks directly to VITE_API_BASE_URL — see
// .env.development (local backend, not prod — PR #14 review finding #5)
// and .env.production.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
})
