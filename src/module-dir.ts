/**
 * ESM/CJS compatible __dirname resolution.
 * 
 * ts-jest transpileModule does not support import.meta syntax.
 * This utility provides __dirname without using import.meta.
 */
import path from 'path'

/**
 * Get the directory name of the current module.
 * Works in both CJS (ts-jest) and ESM (production) contexts.
 * 
 * In CJS context (ts-jest): __dirname is available globally.
 * In ESM context: we use a fallback based on process.cwd() + known project structure.
 */
export function getModuleDirname(fallback?: string): string {
  // In CJS/ts-jest context, __dirname is available
  if (typeof __dirname !== 'undefined') return __dirname
  // Fallback
  return fallback ?? process.cwd()
}

/**
 * Resolve a path relative to the project root.
 */
export function resolveFromProjectRoot(...segments: string[]): string {
  // __dirname in src/ points to e.g. dist/ or src/, go up one level for project root
  const root = typeof __dirname !== 'undefined'
    ? path.resolve(__dirname, '..')
    : process.cwd()
  return path.resolve(root, ...segments)
}
