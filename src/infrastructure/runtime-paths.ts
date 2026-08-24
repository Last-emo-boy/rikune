import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

function resolvePackageRoot(): string {
  // This module lives at src/infrastructure during development and at
  // dist/infrastructure after compilation. In both layouts, ../.. is the
  // Rikune package root. Never prefer process.cwd(): npm consumers run Rikune
  // from their own project directory, which may also contain a package.json.
  const candidate = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..')
  const manifestPath = path.join(candidate, 'package.json')

  let packageName: unknown
  try {
    packageName = JSON.parse(fs.readFileSync(manifestPath, 'utf8')).name
  } catch (error) {
    throw new Error(
      `Unable to resolve the Rikune package root from ${manifestPath}: ${error instanceof Error ? error.message : String(error)}`
    )
  }

  if (packageName !== 'rikune') {
    throw new Error(
      `Resolved package root has unexpected package name ${String(packageName)} at ${manifestPath}`
    )
  }
  return candidate
}

const packageRoot = resolvePackageRoot()

export function getPackageRoot(): string {
  return packageRoot
}

export function resolvePackagePath(...segments: string[]): string {
  return path.join(packageRoot, ...segments)
}
