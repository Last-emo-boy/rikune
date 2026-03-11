import path from 'path'
import { fileURLToPath } from 'url'

const moduleDir = path.dirname(fileURLToPath(import.meta.url))
const packageRoot = path.resolve(moduleDir, '..')

export function getPackageRoot(): string {
  return packageRoot
}

export function resolvePackagePath(...segments: string[]): string {
  return path.join(packageRoot, ...segments)
}
