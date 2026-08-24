/**
 * Ghidra Headless configuration and validation
 * Handles detection, validation, and configuration of Ghidra installation
 */

import fs from 'fs'
import path from 'path'
import { spawnSync } from 'child_process'
import { getPythonCommand } from '../utils/shared-helpers.js'
import { CACHE_TTL_7_DAYS } from '../constants/cache-ttl.js'
import { logger } from '../logger.js'
import { buildRawCommandLine, decodeProcessStreams } from '../process-output.js'
import { resolvePackagePath } from '../runtime-paths.js'
import { config, getDefaultGhidraLogRoot, getDefaultGhidraProjectRoot } from '../config.js'

export interface GhidraConfig {
  installDir: string
  analyzeHeadlessPath: string
  scriptsDir: string
  projectRoot: string
  logRoot: string
  minJavaVersion: number
  version?: string
  isValid: boolean
}

export interface JavaRuntimeProbe {
  available: boolean
  source: 'JAVA_HOME' | 'PATH' | 'none'
  command: string
  version?: string
  major_version?: number
  version_ok: boolean
  error?: string
}

export interface GhidraHealthStatus {
  ok: boolean
  checked_at: string
  install_dir: string
  analyze_headless_path: string
  scripts_dir: string
  project_root: string
  log_root: string
  version?: string
  checks: {
    install_dir_exists: boolean
    analyze_headless_exists: boolean
    scripts_dir_exists: boolean
    launch_ok: boolean
    pyghidra_available: boolean
    java_available: boolean
    java_version_ok: boolean
  }
  launch_probe?: {
    raw_cmd: string
    exit_code: number | null
    timed_out: boolean
    stdout: string
    stderr: string
    stdout_encoding: string
    stderr_encoding: string
  }
  pyghidra_probe?: {
    command: string
    available: boolean
    version?: string
    error?: string
  }
  java_probe?: JavaRuntimeProbe
  errors: string[]
  warnings: string[]
}

export interface ProcessInvocation {
  command: string
  args: string[]
  windowsVerbatimArguments?: boolean
}

function getWindowsCommandInterpreter(requireExisting = process.platform === 'win32'): string {
  const envCandidates = [process.env.ComSpec, process.env.COMSPEC].filter(
    (value): value is string => Boolean(value && value.trim())
  )

  for (const candidate of envCandidates) {
    if (!requireExisting || fs.existsSync(candidate)) {
      return candidate
    }
  }

  const systemRootCandidates = [process.env.SystemRoot, process.env.SYSTEMROOT].filter(
    (value): value is string => Boolean(value && value.trim())
  )

  for (const systemRoot of systemRootCandidates) {
    const candidate = path.join(systemRoot, 'System32', 'cmd.exe')
    if (fs.existsSync(candidate)) {
      return candidate
    }
  }

  return 'cmd.exe'
}

function probePyGhidra(timeoutMs: number): {
  command: string
  available: boolean
  version?: string
  error?: string
} {
  const pythonCommand = getPythonCommand()
  const probeCode =
    'import importlib.util,sys;spec=importlib.util.find_spec("pyghidra");' +
    'print("PYGHIDRA_MISSING" if spec is None else "PYGHIDRA_OK")'

  try {
    const result = spawnSync(pythonCommand, ['-c', probeCode], {
      timeout: timeoutMs,
      windowsHide: true,
      encoding: 'utf8',
    })

    if (result.error) {
      return {
        command: pythonCommand,
        available: false,
        error: result.error.message,
      }
    }

    const stdout = String(result.stdout || '').trim()
    if (stdout.includes('PYGHIDRA_OK')) {
      const versionProbe = spawnSync(
        pythonCommand,
        ['-c', 'import pyghidra; print(getattr(pyghidra, "__version__", "unknown"))'],
        {
          timeout: timeoutMs,
          windowsHide: true,
          encoding: 'utf8',
        }
      )
      const version = String(versionProbe.stdout || '').trim() || 'unknown'
      return {
        command: pythonCommand,
        available: true,
        version,
      }
    }

    return {
      command: pythonCommand,
      available: false,
      error: 'pyghidra package not found in active Python environment.',
    }
  } catch (error) {
    return {
      command: pythonCommand,
      available: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

export function probePyGhidraAvailability(timeoutMs: number = 5000): {
  command: string
  available: boolean
  version?: string
  error?: string
} {
  return probePyGhidra(timeoutMs)
}

function parseJavaMajorVersion(versionText: string): number | null {
  const match =
    versionText.match(/version\s+"(\d+)(?:\.(\d+))?/i) ||
    versionText.match(/\b(\d+)\.(\d+)\.(\d+)\b/)
  if (!match) {
    return null
  }
  const primary = Number(match[1])
  if (!Number.isFinite(primary)) {
    return null
  }
  if (primary === 1 && typeof match[2] === 'string') {
    const legacy = Number(match[2])
    return Number.isFinite(legacy) ? legacy : null
  }
  return primary
}

function getJavaExecutableFromHome(javaHome: string): string | null {
  const candidates =
    process.platform === 'win32'
      ? [path.join(javaHome, 'bin', 'java.exe'), path.join(javaHome, 'java.exe')]
      : [path.join(javaHome, 'bin', 'java'), path.join(javaHome, 'java')]

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate
    }
  }

  return null
}

export function probeJavaRuntime(
  timeoutMs: number = 5000,
  minJavaVersion: number = config.workers.ghidra.minJavaVersion
): JavaRuntimeProbe {
  const javaHome = process.env.JAVA_HOME?.trim()
  const javaFromHome = javaHome ? getJavaExecutableFromHome(javaHome) : null
  const javaCommand = javaFromHome || 'java'
  const source: JavaRuntimeProbe['source'] = javaFromHome
    ? 'JAVA_HOME'
    : javaHome
      ? 'JAVA_HOME'
      : 'PATH'

  try {
    const result = spawnSync(javaCommand, ['-version'], {
      timeout: timeoutMs,
      windowsHide: true,
      encoding: 'utf8',
    })

    if (result.error) {
      return {
        available: false,
        source: javaHome ? 'JAVA_HOME' : 'none',
        command: javaCommand,
        version_ok: false,
        error: result.error.message,
      }
    }

    const combined =
      `${String(result.stderr || '').trim()}\n${String(result.stdout || '').trim()}`.trim()
    const major = parseJavaMajorVersion(combined)
    const versionLine = combined
      .split(/\r?\n/)
      .map((line) => line.trim())
      .find((line) => /version|openjdk|java/i.test(line))

    return {
      available: true,
      source,
      command: javaCommand,
      version: versionLine || undefined,
      major_version: major || undefined,
      version_ok: typeof major === 'number' ? major >= minJavaVersion : false,
      error: typeof major === 'number' ? undefined : 'Unable to parse Java version output.',
    }
  } catch (error) {
    return {
      available: false,
      source: javaHome ? 'JAVA_HOME' : 'none',
      command: javaCommand,
      version_ok: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

export function getConfiguredGhidraProjectRoot(): string {
  const configured = config.workers.ghidra.projectRoot?.trim()
  return path.resolve(configured || getDefaultGhidraProjectRoot())
}

export function getConfiguredGhidraLogRoot(): string {
  const configured = config.workers.ghidra.logRoot?.trim()
  return path.resolve(configured || getDefaultGhidraLogRoot())
}

function sampleSha256(sampleId: string): string {
  const sha256 = sampleId.startsWith('sha256:') ? sampleId.slice('sha256:'.length) : sampleId
  if (!/^[a-f0-9]{64}$/.test(sha256)) {
    throw new Error('Ghidra sample scope requires a lowercase canonical SHA-256.')
  }
  return sha256
}

function fsyncDirectory(directory: string): void {
  const descriptor = fs.openSync(directory, 'r')
  try {
    fs.fsyncSync(descriptor)
  } finally {
    fs.closeSync(descriptor)
  }
}

function lstatIfExists(candidate: string): fs.Stats | null {
  try {
    return fs.lstatSync(candidate)
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw error
  }
}

function migrateLegacySampleScopedDirectory(root: string, sha256: string): string {
  const bucket1 = sha256.slice(0, 2)
  const bucket2 = sha256.slice(2, 4)
  const direct = path.join(root, sha256)
  const legacy = path.join(root, bucket1, bucket2, sha256)
  const rootStat = fs.lstatSync(root)
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('Ghidra sample root failed trusted-root validation.')
  }
  const rootReal = path.resolve(fs.realpathSync.native(root))
  const validateDirectory = (candidate: string, label: string): fs.Stats | null => {
    const stat = lstatIfExists(candidate)
    if (!stat) return null
    const real = path.resolve(fs.realpathSync.native(candidate))
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      (real !== rootReal && !real.startsWith(`${rootReal}${path.sep}`))
    ) {
      throw new Error(`${label} Ghidra sample directory failed trusted-root validation.`)
    }
    return stat
  }
  const directStat = validateDirectory(direct, 'Direct')
  const legacyStat = validateDirectory(legacy, 'Legacy')
  if (!legacyStat) return direct
  for (const component of [path.join(root, bucket1), path.join(root, bucket1, bucket2)]) {
    const stat = fs.lstatSync(component)
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new Error('Legacy Ghidra bucket failed trusted-root validation.')
    }
  }
  if (directStat) {
    throw new Error(`Both direct and legacy Ghidra sample directories exist for ${sha256}.`)
  }
  fs.renameSync(legacy, direct)
  fsyncDirectory(root)
  fsyncDirectory(path.dirname(legacy))
  for (const directory of [path.dirname(legacy), path.dirname(path.dirname(legacy))]) {
    try {
      if (fs.readdirSync(directory).length === 0) fs.rmdirSync(directory)
    } catch {
      // Non-empty legacy buckets remain valid containers for other samples.
    }
  }
  return direct
}

/**
 * Enumerate and migrate every legacy <aa>/<bb>/<sha256> sample directory.
 * Direct <sha256> paths are the only layout used after this startup migration.
 */
export function migrateLegacyGhidraSampleDirectories(root: string): number {
  const resolvedRoot = path.resolve(root)
  const rootStat = fs.lstatSync(resolvedRoot)
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    throw new Error('Ghidra migration root must be a real directory.')
  }
  let migrated = 0
  for (const first of fs.readdirSync(resolvedRoot, { withFileTypes: true })) {
    if (!/^[a-f0-9]{2}$/.test(first.name)) continue
    if (!first.isDirectory() || first.isSymbolicLink()) {
      throw new Error('Legacy Ghidra first-level bucket must be a real directory.')
    }
    const firstPath = path.join(resolvedRoot, first.name)
    for (const second of fs.readdirSync(firstPath, { withFileTypes: true })) {
      if (!/^[a-f0-9]{2}$/.test(second.name)) continue
      if (!second.isDirectory() || second.isSymbolicLink()) {
        throw new Error('Legacy Ghidra second-level bucket must be a real directory.')
      }
      const secondPath = path.join(firstPath, second.name)
      for (const candidate of fs.readdirSync(secondPath, { withFileTypes: true })) {
        if (!/^[a-f0-9]{64}$/.test(candidate.name)) continue
        if (
          candidate.name.slice(0, 2) !== first.name ||
          candidate.name.slice(2, 4) !== second.name
        ) {
          throw new Error('Legacy Ghidra sample directory is stored under the wrong hash bucket.')
        }
        migrateLegacySampleScopedDirectory(resolvedRoot, candidate.name)
        migrated++
      }
    }
  }
  return migrated
}

export function getSampleScopedGhidraProjectRoot(sampleId: string): string {
  return migrateLegacySampleScopedDirectory(
    getConfiguredGhidraProjectRoot(),
    sampleSha256(sampleId)
  )
}

export function getSampleScopedGhidraLogRoot(sampleId: string): string {
  return migrateLegacySampleScopedDirectory(getConfiguredGhidraLogRoot(), sampleSha256(sampleId))
}

function looksLikeAnalyzeHeadlessHelp(stdout: string, stderr: string): boolean {
  const combined = `${stdout}\n${stderr}`.toLowerCase()
  const hasToolMarker = combined.includes('analyzeheadless')
  const hasUsageSignal =
    combined.includes('usage') ||
    combined.includes('-import') ||
    combined.includes('-process') ||
    combined.includes('-scriptpath')
  return hasToolMarker && hasUsageSignal
}

/**
 * Quote argument for Windows cmd.exe command line.
 * Keeps special characters literal, including &, (), and spaces.
 */
export function quoteForWindowsCmd(value: string): string {
  if (value.length === 0) {
    return '""'
  }

  // In cmd.exe quoted context, double quotes are escaped by doubling.
  const escaped = value.replace(/"/g, '""')
  return `"${escaped}"`
}

/**
 * Build explicit cmd.exe invocation for .bat/.cmd entry points on Windows.
 * Avoids `shell: true` and path-splitting issues on special characters.
 */
export function buildWindowsBatchInvocation(
  command: string,
  args: string[],
  platform: NodeJS.Platform = process.platform
): ProcessInvocation {
  const commandLine = [quoteForWindowsCmd(command), ...args.map(quoteForWindowsCmd)].join(' ')
  // cmd.exe /s /c requires one outer quote pair around the full command line;
  // without this, paths containing '&' are split and fail to execute.
  const wrappedCommandLine = `"${commandLine}"`
  return {
    command: getWindowsCommandInterpreter(platform === 'win32' && process.platform === 'win32'),
    args: ['/d', '/s', '/c', wrappedCommandLine],
    windowsVerbatimArguments: true,
  }
}

/**
 * Build portable process invocation.
 * On Windows batch scripts we explicitly route through cmd.exe.
 */
export function buildProcessInvocation(
  command: string,
  args: string[],
  platform: NodeJS.Platform = process.platform
): ProcessInvocation {
  if (platform === 'win32' && /\.(bat|cmd)$/i.test(command)) {
    return buildWindowsBatchInvocation(command, args, platform)
  }

  return {
    command,
    args: [...args],
  }
}

/**
 * Detect Ghidra installation from environment variable or common paths
 */
export function detectGhidraInstallation(): string | null {
  // 1. Check explicit environment variables
  const envCandidates = [
    ['GHIDRA_INSTALL_DIR', process.env.GHIDRA_INSTALL_DIR],
    ['GHIDRA_PATH', process.env.GHIDRA_PATH],
  ] as const

  for (const [envName, envPath] of envCandidates) {
    if (envPath && fs.existsSync(envPath)) {
      logger.info({ path: envPath, env: envName }, `Found Ghidra installation from ${envName}`)
      return envPath
    }
  }

  // 2. Check common installation paths
  const commonPaths = [
    '/opt/ghidra',
    '/usr/local/ghidra',
    'C:\\Program Files\\ghidra',
    'C:\\ghidra',
    path.join(process.env.HOME || '', 'ghidra'),
  ]

  for (const commonPath of commonPaths) {
    if (fs.existsSync(commonPath)) {
      logger.info({ path: commonPath }, 'Found Ghidra installation at common path')
      return commonPath
    }
  }

  logger.warn('Ghidra installation not found')
  return null
}

/**
 * Validate Ghidra installation directory
 */
export function validateGhidraInstallation(installDir: string): boolean {
  try {
    // Check if directory exists
    if (!fs.existsSync(installDir)) {
      logger.error({ installDir }, 'Ghidra installation directory does not exist')
      return false
    }

    // Check for analyzeHeadless script
    const analyzeHeadlessPath = getAnalyzeHeadlessPath(installDir)
    if (!fs.existsSync(analyzeHeadlessPath)) {
      logger.error(
        { installDir, analyzeHeadlessPath },
        'analyzeHeadless script not found in Ghidra installation'
      )
      return false
    }

    // Check if script is executable (Unix-like systems)
    if (process.platform !== 'win32') {
      try {
        fs.accessSync(analyzeHeadlessPath, fs.constants.X_OK)
      } catch {
        logger.error({ analyzeHeadlessPath }, 'analyzeHeadless script is not executable')
        return false
      }
    }

    logger.info({ installDir }, 'Ghidra installation validated successfully')
    return true
  } catch (error) {
    logger.error({ error, installDir }, 'Error validating Ghidra installation')
    return false
  }
}

/**
 * Get path to analyzeHeadless script based on platform
 */
export function getAnalyzeHeadlessPath(installDir: string): string {
  const supportDir = path.join(installDir, 'support')

  if (process.platform === 'win32') {
    return path.join(supportDir, 'analyzeHeadless.bat')
  } else {
    return path.join(supportDir, 'analyzeHeadless')
  }
}

function readGhidraVersionFromProperties(installDir: string): string | null {
  const propertiesPath = path.join(installDir, 'Ghidra', 'application.properties')
  if (!fs.existsSync(propertiesPath)) {
    return null
  }

  try {
    const content = fs.readFileSync(propertiesPath, 'utf8')
    const versionMatch = content.match(/^application\.version=(.+)$/m)
    if (!versionMatch?.[1]) {
      return null
    }
    const version = versionMatch[1].trim()
    return version.length > 0 ? version : null
  } catch (error) {
    logger.warn(
      { error, propertiesPath },
      'Failed to read Ghidra version from application.properties'
    )
    return null
  }
}

/**
 * Get Ghidra version from installation
 */
export function getGhidraVersion(installDir: string): string | null {
  try {
    const versionFromProperties = readGhidraVersionFromProperties(installDir)
    if (versionFromProperties) {
      return versionFromProperties
    }

    const analyzeHeadlessPath = getAnalyzeHeadlessPath(installDir)

    const invocation = buildProcessInvocation(analyzeHeadlessPath, ['-help'])
    const result = spawnSync(invocation.command, invocation.args, {
      timeout: 5000,
      windowsHide: true,
      windowsVerbatimArguments: invocation.windowsVerbatimArguments === true,
    })
    const decoded = decodeProcessStreams(result.stdout, result.stderr)

    if (result.error || result.status !== 0) {
      logger.warn(
        {
          raw_cmd: buildRawCommandLine(invocation.command, invocation.args),
          error: result.error?.message,
          status: result.status,
          stderr: decoded.stderr.text.trim(),
          stderr_encoding: decoded.stderr.encoding,
        },
        'Failed to get Ghidra version'
      )
      return null
    }

    const output = decoded.stdout.text

    // Parse version from output (format: "Ghidra Version X.Y.Z")
    const versionMatch = output.match(/Ghidra\s+Version\s+(\d+\.\d+(?:\.\d+)?)/i)
    if (versionMatch) {
      return versionMatch[1]
    }

    logger.warn('Could not parse Ghidra version from output')
    return null
  } catch (error) {
    logger.warn({ error }, 'Failed to get Ghidra version')
    return null
  }
}

/**
 * Ensure Ghidra scripts directory exists
 */
export function ensureScriptsDirectory(baseDir?: string): string {
  const scriptsDir = resolveScriptsDirectory(baseDir)

  if (!fs.existsSync(scriptsDir)) {
    fs.mkdirSync(scriptsDir, { recursive: true })
    logger.info({ scriptsDir }, 'Created Ghidra scripts directory')
  }

  return scriptsDir
}

function resolveScriptsDirectory(baseDir?: string): string {
  return path.resolve(baseDir || resolvePackagePath('src', 'plugins', 'ghidra', 'scripts'))
}

/**
 * Initialize Ghidra configuration
 */
export function initializeGhidraConfig(installDir?: string): GhidraConfig {
  const projectRoot = getConfiguredGhidraProjectRoot()
  const logRoot = getConfiguredGhidraLogRoot()

  // Detect installation directory
  const detectedInstallDir = installDir || detectGhidraInstallation()

  if (!detectedInstallDir) {
    logger.warn('Ghidra installation not detected. Ghidra features will be disabled.')
    return {
      installDir: '',
      analyzeHeadlessPath: '',
      scriptsDir: '',
      projectRoot,
      logRoot,
      minJavaVersion: config.workers.ghidra.minJavaVersion,
      isValid: false,
    }
  }

  // Validate installation
  const isValid = validateGhidraInstallation(detectedInstallDir)

  if (!isValid) {
    logger.error('Ghidra installation validation failed. Ghidra features will be disabled.')
    return {
      installDir: detectedInstallDir,
      analyzeHeadlessPath: '',
      scriptsDir: '',
      projectRoot,
      logRoot,
      minJavaVersion: config.workers.ghidra.minJavaVersion,
      isValid: false,
    }
  }

  // Get paths and version
  const analyzeHeadlessPath = getAnalyzeHeadlessPath(detectedInstallDir)
  // Resolution is intentionally read-only. Bootstrap creates the directory
  // only after the baked static backend contract has been validated.
  const scriptsDir = resolveScriptsDirectory()
  const version = getGhidraVersion(detectedInstallDir)

  const resolvedConfig: GhidraConfig = {
    installDir: detectedInstallDir,
    analyzeHeadlessPath,
    scriptsDir,
    projectRoot,
    logRoot,
    minJavaVersion: config.workers.ghidra.minJavaVersion,
    version: version || undefined,
    isValid: true,
  }

  logger.info(
    {
      installDir: resolvedConfig.installDir,
      version: resolvedConfig.version,
      scriptsDir: resolvedConfig.scriptsDir,
      projectRoot: resolvedConfig.projectRoot,
      logRoot: resolvedConfig.logRoot,
    },
    'Ghidra configuration initialized'
  )

  return resolvedConfig
}

/**
 * Perform mutable Ghidra directory preparation explicitly during server
 * bootstrap. Importing this module remains read-only, so a baked static image
 * can validate its exact lock and backend identity first.
 */
export function prepareGhidraRuntimeDirectories(): void {
  const initialized = initializeGhidraConfig()
  Object.assign(ghidraConfig, initialized)
  if (ghidraConfig.scriptsDir) fs.mkdirSync(ghidraConfig.scriptsDir, { recursive: true })
  const projectRoot = getConfiguredGhidraProjectRoot()
  const logRoot = getConfiguredGhidraLogRoot()
  fs.mkdirSync(projectRoot, { recursive: true })
  fs.mkdirSync(logRoot, { recursive: true })
  migrateLegacyGhidraSampleDirectories(projectRoot)
  migrateLegacyGhidraSampleDirectories(logRoot)
}

/**
 * Generate unique project key for Ghidra project
 * Format: <timestamp>_<random>
 * Ensures uniqueness for concurrent analyses
 *
 * Requirements: 8.1, 8.7
 */
export function generateProjectKey(): string {
  const timestamp = Date.now()
  const random = Math.random().toString(36).substring(2, 10)
  return `${timestamp}_${random}`
}

/**
 * Create Ghidra project directory
 * Creates isolated project space to avoid concurrent conflicts
 *
 * Requirements: 8.1, 8.7
 *
 * @param ghidraWorkspaceDir - Base Ghidra workspace directory (from workspace manager)
 * @param projectKey - Unique project key (optional, will be generated if not provided)
 * @returns Object with project path and project key
 */
export function createGhidraProject(
  ghidraWorkspaceDir: string,
  projectKey?: string
): { projectPath: string; projectKey: string } {
  // Generate project key if not provided
  const key = projectKey || generateProjectKey()
  const parentDir = path.resolve(ghidraWorkspaceDir)
  if (!fs.existsSync(parentDir)) {
    fs.mkdirSync(parentDir, { recursive: true })
    logger.info({ ghidraWorkspaceDir: parentDir }, 'Created Ghidra project parent directory')
  }

  // Create project directory: workspace/ghidra/project_<key>/
  const projectPath = path.join(parentDir, `project_${key}`)

  // Create directory if it doesn't exist
  if (!fs.existsSync(projectPath)) {
    fs.mkdirSync(projectPath, { recursive: true })
    logger.info({ projectPath, projectKey: key }, 'Created Ghidra project directory')
  }

  return {
    projectPath,
    projectKey: key,
  }
}

/**
 * Clean up old Ghidra projects
 * Removes project directories older than specified age
 *
 * @param ghidraWorkspaceDir - Base Ghidra workspace directory
 * @param maxAgeMs - Maximum age in milliseconds (default: 7 days)
 * @returns Number of projects cleaned up
 */
export function cleanupOldGhidraProjects(
  ghidraWorkspaceDir: string,
  maxAgeMs: number = CACHE_TTL_7_DAYS
): number {
  if (!fs.existsSync(ghidraWorkspaceDir)) {
    return 0
  }

  const cutoffTime = Date.now() - maxAgeMs
  let cleanedCount = 0

  try {
    const entries = fs.readdirSync(ghidraWorkspaceDir, { withFileTypes: true })

    for (const entry of entries) {
      // Only process project directories (format: project_<key>)
      if (!entry.isDirectory() || !entry.name.startsWith('project_')) {
        continue
      }

      const projectPath = path.join(ghidraWorkspaceDir, entry.name)

      try {
        const stats = fs.statSync(projectPath)

        // Check if project is older than cutoff time
        if (stats.mtimeMs < cutoffTime) {
          // Delete old project directory
          fs.rmSync(projectPath, { recursive: true, force: true })
          cleanedCount++
          logger.info({ projectPath }, 'Cleaned up old Ghidra project')
        }
      } catch (error) {
        logger.warn({ error, projectPath }, 'Failed to clean up Ghidra project')
      }
    }
  } catch (error) {
    logger.error({ error, ghidraWorkspaceDir }, 'Failed to cleanup Ghidra projects')
  }

  return cleanedCount
}

/**
 * Perform a lightweight Ghidra environment health check.
 * This verifies path resolution and attempts a short `analyzeHeadless -help` launch.
 */
export function checkGhidraHealth(timeoutMs: number = 8000): GhidraHealthStatus {
  const checkedAt = new Date().toISOString()
  const errors: string[] = []
  const warnings: string[] = []

  const installDir = ghidraConfig.installDir || detectGhidraInstallation() || ''
  const analyzeHeadlessPath = installDir ? getAnalyzeHeadlessPath(installDir) : ''
  const scriptsDir = ghidraConfig.scriptsDir || ensureScriptsDirectory()
  const projectRoot = ghidraConfig.projectRoot || getConfiguredGhidraProjectRoot()
  const logRoot = ghidraConfig.logRoot || getConfiguredGhidraLogRoot()

  const installDirExists = Boolean(installDir && fs.existsSync(installDir))
  const analyzeHeadlessExists = Boolean(analyzeHeadlessPath && fs.existsSync(analyzeHeadlessPath))
  const scriptsDirExists = Boolean(scriptsDir && fs.existsSync(scriptsDir))
  const pyghidraProbe = probePyGhidra(Math.min(timeoutMs, 5000))
  const pyghidraAvailable = pyghidraProbe.available === true
  const javaProbe = probeJavaRuntime(Math.min(timeoutMs, 5000), ghidraConfig.minJavaVersion)
  const javaAvailable = javaProbe.available === true
  const javaVersionOk = javaProbe.version_ok === true

  if (!installDirExists) {
    errors.push('Ghidra install directory was not found. Set GHIDRA_PATH or GHIDRA_INSTALL_DIR.')
  }
  if (!analyzeHeadlessExists) {
    errors.push('analyzeHeadless script was not found in the Ghidra install directory.')
  }
  if (!scriptsDirExists) {
    errors.push('Ghidra script directory does not exist.')
  }
  if (!pyghidraAvailable) {
    warnings.push(
      'PyGhidra is unavailable in current Python environment; Python post-scripts may fail and Java fallback will be used.'
    )
  }
  if (!javaAvailable) {
    warnings.push(
      'No usable Java runtime was detected from JAVA_HOME or PATH. Set JAVA_HOME to a Java 21+ installation if Ghidra launch fails.'
    )
  } else if (!javaVersionOk) {
    warnings.push(
      `Detected Java runtime appears older than the recommended Java ${ghidraConfig.minJavaVersion}+ baseline for Ghidra ${ghidraConfig.version || '12.x'}.`
    )
  }

  let launchOk = false
  let launchProbe:
    | {
        raw_cmd: string
        exit_code: number | null
        timed_out: boolean
        stdout: string
        stderr: string
        stdout_encoding: string
        stderr_encoding: string
      }
    | undefined
  if (installDirExists && analyzeHeadlessExists) {
    try {
      const invocation = buildProcessInvocation(analyzeHeadlessPath, ['-help'])
      const result = spawnSync(invocation.command, invocation.args, {
        timeout: timeoutMs,
        windowsHide: true,
        windowsVerbatimArguments: invocation.windowsVerbatimArguments === true,
      })
      const decoded = decodeProcessStreams(result.stdout, result.stderr)
      const timedOut =
        (result.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT' ||
        Boolean(result.error?.message && result.error.message.includes('ETIMEDOUT'))

      launchProbe = {
        raw_cmd: buildRawCommandLine(invocation.command, invocation.args),
        exit_code: result.status ?? null,
        timed_out: timedOut,
        stdout: decoded.stdout.text.trim(),
        stderr: decoded.stderr.text.trim(),
        stdout_encoding: decoded.stdout.encoding,
        stderr_encoding: decoded.stderr.encoding,
      }

      if (result.error) {
        if (timedOut) {
          errors.push(`analyzeHeadless launch probe timed out after ${timeoutMs}ms.`)
        } else {
          errors.push(`Failed to launch analyzeHeadless: ${result.error.message}`)
        }
      } else if (result.status !== 0) {
        const stdoutText = decoded.stdout.text.trim()
        const stderrText = decoded.stderr.text.trim()
        if (looksLikeAnalyzeHeadlessHelp(stdoutText, stderrText)) {
          launchOk = true
          warnings.push(
            `analyzeHeadless returned non-zero exit code (${result.status}) but help output was detected.`
          )
        } else {
          if (!javaAvailable) {
            errors.push(
              'analyzeHeadless launch failed and no usable Java runtime was detected. Set JAVA_HOME or verify the bundled Ghidra runtime.'
            )
          } else if (!javaVersionOk) {
            errors.push(
              `analyzeHeadless launch failed and the detected Java runtime is older than Java ${ghidraConfig.minJavaVersion}.`
            )
          }
          errors.push(
            `analyzeHeadless returned non-zero exit code (${result.status}). ${stderrText}`.trim()
          )
        }
      } else {
        launchOk = true
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      errors.push(`Ghidra launch check failed: ${message}`)
    }
  }

  if (!ghidraConfig.isValid) {
    warnings.push('Global ghidraConfig is marked invalid; decompiler tools will fail until fixed.')
  }

  return {
    ok: errors.length === 0,
    checked_at: checkedAt,
    install_dir: installDir,
    analyze_headless_path: analyzeHeadlessPath,
    scripts_dir: scriptsDir,
    project_root: projectRoot,
    log_root: logRoot,
    version: ghidraConfig.version,
    checks: {
      install_dir_exists: installDirExists,
      analyze_headless_exists: analyzeHeadlessExists,
      scripts_dir_exists: scriptsDirExists,
      launch_ok: launchOk,
      pyghidra_available: pyghidraAvailable,
      java_available: javaAvailable,
      java_version_ok: javaVersionOk,
    },
    launch_probe: launchProbe,
    pyghidra_probe: pyghidraProbe,
    java_probe: javaProbe,
    errors,
    warnings,
  }
}

/**
 * Global Ghidra configuration instance
 */
export const ghidraConfig: GhidraConfig = {
  installDir: '',
  analyzeHeadlessPath: '',
  scriptsDir: resolveScriptsDirectory(),
  projectRoot: getConfiguredGhidraProjectRoot(),
  logRoot: getConfiguredGhidraLogRoot(),
  minJavaVersion: config.workers.ghidra.minJavaVersion,
  isValid: false,
}
