import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import fs from 'fs'
import path from 'path'

// Controleer of lokale certificaten bestaan (gegenereerd door mkcert)
const keyPath = path.resolve(__dirname, 'localhost+2-key.pem')
const certPath = path.resolve(__dirname, 'localhost+2.pem')
const useHttps = fs.existsSync(keyPath) && fs.existsSync(certPath)

export default defineConfig({
  plugins: [vue()],
  server: {
    https: useHttps ? {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath)
    } : false,
    port: 5173,
    strictPort: true
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true
  }
})
