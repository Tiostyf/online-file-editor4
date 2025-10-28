import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'https://online-file-editor4.onrender.com',
        changeOrigin: true
      }
    }
  },
  define: {
    'process.env': {}
  }
})