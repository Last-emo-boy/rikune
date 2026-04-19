import { execSync, spawn } from 'child_process'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const PROJECT_ROOT = path.resolve(__dirname, '../../..')
const COMPOSE_FILE = path.join(PROJECT_ROOT, 'docker-compose.hybrid.yml')

export function isDockerAvailable(): boolean {
  try {
    execSync('docker ps', { stdio: 'ignore' })
    return true
  } catch {
    return false
  }
}

export function buildAnalyzerImage(): void {
  execSync('docker build -t rikune:latest .', { cwd: PROJECT_ROOT, stdio: 'inherit' })
}

export function startAnalyzer(): void {
  execSync(`docker compose -f "${COMPOSE_FILE}" up -d`, { cwd: PROJECT_ROOT, stdio: 'inherit' })
}

export function stopAnalyzer(): void {
  try {
    execSync(`docker compose -f "${COMPOSE_FILE}" down`, { cwd: PROJECT_ROOT, stdio: 'ignore' })
  } catch {}
}

export function analyzerLogs(): string {
  try {
    return execSync(`docker compose -f "${COMPOSE_FILE}" logs analyzer`, { cwd: PROJECT_ROOT, encoding: 'utf-8' })
  } catch {
    return ''
  }
}
