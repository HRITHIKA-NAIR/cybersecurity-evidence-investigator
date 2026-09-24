import react from '@vitejs/plugin-react'
import process from 'node:process'
import { defineConfig, loadEnv } from 'vite'
import { validatePublicConfig } from './scripts/public-config.mjs'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  validatePublicConfig({ ...loadEnv(mode, process.cwd(), ''), ...process.env })
  return { plugins: [react()] }
})
