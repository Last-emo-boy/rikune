import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export const ANALYZER_WSL_FILESYSTEM_ERROR =
  'Rikune Analyzer custody roots must use the WSL2 Linux filesystem; Windows-mounted DrvFS transports are unsupported.'
export const ANALYZER_WSL2_REQUIRED_ERROR =
  'Rikune Analyzer requires a verified WSL2 kernel; WSL1 and unverified WSL kernels are unsupported.'

export interface AnalyzerCustodyRoot {
  name: string
  path: string
}

export interface LinuxMountInfoEntry {
  mountId: string
  mountPoint: string
  filesystemType: string
  source: string
  superOptions: string
}

interface AnalyzerFilesystemProbe {
  platform?: NodeJS.Platform
  environment?: NodeJS.ProcessEnv
  kernelRelease?: string
  kernelVersion?: string
  containerized?: boolean
  mountInfo?: string
  existsSync?: (candidate: string) => boolean
  realpathSync?: (candidate: string) => string
  mountIdForPath?: (candidate: string) => string
}

const MOUNTINFO_ESCAPE = /\\(040|011|012|134)/gu
const MOUNTINFO_CHARACTERS: Record<string, string> = {
  '040': ' ',
  '011': '\t',
  '012': '\n',
  '134': '\\',
}
const UNSUPPORTED_WSL_FILESYSTEM_TYPES = new Set([
  'drvfs',
  '9p',
  'plan9',
  'virtio-plan9',
  'virtiofs',
])

function decodeMountInfoValue(value: string): string {
  return value.replace(MOUNTINFO_ESCAPE, (_match, code: string) => MOUNTINFO_CHARACTERS[code]!)
}

export function parseLinuxMountInfo(content: string): LinuxMountInfoEntry[] {
  const entries: LinuxMountInfoEntry[] = []

  for (const line of content.split(/\r?\n/u)) {
    if (!line.trim()) continue
    const fields = line.trim().split(' ')
    const separatorIndex = fields.indexOf('-')
    if (separatorIndex < 6 || separatorIndex + 3 >= fields.length) continue
    if (!/^\d+$/u.test(fields[0]!)) continue

    entries.push({
      mountId: fields[0]!,
      mountPoint: decodeMountInfoValue(fields[4]!),
      filesystemType: fields[separatorIndex + 1]!,
      source: decodeMountInfoValue(fields[separatorIndex + 2]!),
      superOptions: fields[separatorIndex + 3]!,
    })
  }

  return entries
}

function readProcFile(filePath: string): string {
  try {
    return fs.readFileSync(filePath, 'utf8')
  } catch {
    return ''
  }
}

function isContainerized(probe: AnalyzerFilesystemProbe): boolean {
  if (probe.containerized !== undefined) return probe.containerized
  const exists = probe.existsSync ?? fs.existsSync
  if (exists('/.dockerenv') || exists('/run/.containerenv')) return true
  return /docker|containerd|kubepods|podman|lxc/iu.test(readProcFile('/proc/1/cgroup'))
}

function getKernelIdentity(probe: AnalyzerFilesystemProbe): string {
  return [
    probe.kernelRelease ?? os.release(),
    probe.kernelVersion ?? readProcFile('/proc/version'),
  ].join('\n')
}

function isDirectWsl(probe: AnalyzerFilesystemProbe): boolean {
  const environment = probe.environment ?? process.env
  const kernelIdentity = getKernelIdentity(probe)
  const wslIdentity =
    Boolean(environment.WSL_DISTRO_NAME || environment.WSL_INTEROP) ||
    /microsoft|wsl/iu.test(kernelIdentity)
  return wslIdentity && !isContainerized(probe)
}

function isVerifiedWsl2(probe: AnalyzerFilesystemProbe): boolean {
  return /microsoft-standard|wsl2/iu.test(getKernelIdentity(probe))
}

function resolveExistingAncestor(configuredPath: string, probe: AnalyzerFilesystemProbe): string {
  const exists = probe.existsSync ?? fs.existsSync
  const realpath = probe.realpathSync ?? fs.realpathSync.native
  let candidate = path.resolve(configuredPath)

  while (!exists(candidate)) {
    const parent = path.dirname(candidate)
    if (parent === candidate) {
      throw new Error(`Unable to resolve an existing ancestor for ${configuredPath}`)
    }
    candidate = parent
  }

  return realpath(candidate)
}

function containsPath(mountPoint: string, candidate: string): boolean {
  if (mountPoint === '/') return candidate.startsWith('/')
  return candidate === mountPoint || candidate.startsWith(`${mountPoint}/`)
}

function resolveMountId(candidate: string, probe: AnalyzerFilesystemProbe): string {
  if (probe.mountIdForPath) {
    const mountId = probe.mountIdForPath(candidate)
    if (/^\d+$/u.test(mountId)) return mountId
    throw new Error(`${ANALYZER_WSL_FILESYSTEM_ERROR} Invalid mount ID for ${candidate}.`)
  }

  let descriptor: number | undefined
  try {
    descriptor = fs.openSync(
      candidate,
      fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW
    )
    const fdInfo = fs.readFileSync(`/proc/self/fdinfo/${descriptor}`, 'utf8')
    const match = fdInfo.match(/^mnt_id:\s+(\d+)\s*$/mu)
    if (!match) {
      throw new Error('fdinfo did not expose mnt_id')
    }
    return match[1]!
  } catch (error) {
    throw new Error(
      `${ANALYZER_WSL_FILESYSTEM_ERROR} Unable to resolve the effective mount ID for ${candidate}: ${
        error instanceof Error ? error.message : String(error)
      }`
    )
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor)
  }
}

function findMount(
  entries: readonly LinuxMountInfoEntry[],
  candidate: string,
  mountId: string
): LinuxMountInfoEntry | undefined {
  const entry = entries.find((candidateEntry) => candidateEntry.mountId === mountId)
  return entry && containsPath(entry.mountPoint, candidate) ? entry : undefined
}

function isUnsupportedWslMount(entry: LinuxMountInfoEntry): boolean {
  return UNSUPPORTED_WSL_FILESYSTEM_TYPES.has(entry.filesystemType.toLowerCase())
}

/**
 * Enforce the WSL custody boundary before any Analyzer bootstrap component can
 * create a directory or file. The nearest existing ancestor is canonicalized
 * so non-existent descendants and symlinked ancestors are checked against the
 * effective mount rather than the configured path string.
 */
export function assertSupportedAnalyzerFilesystem(
  roots: readonly AnalyzerCustodyRoot[],
  probe: AnalyzerFilesystemProbe = {}
): void {
  if ((probe.platform ?? process.platform) !== 'linux' || !isDirectWsl(probe)) return
  if (!isVerifiedWsl2(probe)) throw new Error(ANALYZER_WSL2_REQUIRED_ERROR)

  let mountInfo: string
  try {
    mountInfo = probe.mountInfo ?? fs.readFileSync('/proc/self/mountinfo', 'utf8')
  } catch (error) {
    throw new Error(
      `${ANALYZER_WSL_FILESYSTEM_ERROR} Unable to verify /proc/self/mountinfo: ${
        error instanceof Error ? error.message : String(error)
      }`
    )
  }

  const mounts = parseLinuxMountInfo(mountInfo)
  for (const root of roots) {
    const existingAncestor = resolveExistingAncestor(root.path, probe)
    const mountId = resolveMountId(existingAncestor, probe)
    const mount = findMount(mounts, existingAncestor, mountId)
    if (!mount) {
      throw new Error(
        `${ANALYZER_WSL_FILESYSTEM_ERROR} Unable to identify the mount for ${root.name}.`
      )
    }
    if (isUnsupportedWslMount(mount)) {
      throw new Error(
        `${ANALYZER_WSL_FILESYSTEM_ERROR} ${root.name} resolves to ${mount.mountPoint} (${mount.filesystemType}).`
      )
    }
  }
}
