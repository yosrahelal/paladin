import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/json-rpc': {
        target: 'http://localhost:3555',
        secure: false
      }
    }
  }
})
