import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],

  // Dev server: proxy /api requests to the FastAPI backend
  // This avoids CORS issues during local development.
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false,
      },
    },
  },

  // Production build settings
  build: {
    outDir: 'dist',
    sourcemap: false,   // Set to true if you want source maps in prod
  },
})
