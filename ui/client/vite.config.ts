import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// https://vitejs.dev/config/
export default defineConfig(({ mode }) => ({
  base: '/ui',
  plugins: [react()],
  server: {
    port: mode === 'node3' ? 3003 : mode === 'node2' ? 3002 : 3000,
    proxy: {
      '/': {
        target:
          mode === 'node2'
            ? 'http://localhost:3557'
            : mode === 'node1'
            ? 'http://localhost:3556'
            : 'http://localhost:3555',
        secure: false,
        bypass: (req, _resolveConfig, _options) =>
          req.method === 'POST' ? undefined : req.url,
      },
    },
  },
}));
