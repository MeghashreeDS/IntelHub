import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  define: {
    'process.env': {}
  },
  plugins: [react()],
  server: {
    host: '0.0.0.0', // This makes it accessible from other devices
    port: 5173      // Keep the default port or change if needed
  }
})
