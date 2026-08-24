#!/usr/bin/env node
// =============================================================================
// generate-docker.mjs  Plugin-driven Dockerfile & docker-compose generator
// =============================================================================
//
// Reads plugin systemDeps declarations from compiled dist/plugins/ and
// Dockerfile fragments from src/plugins/*/docker/*.dockerfile, then
// automatically derives the Docker image contents.
//
// Zero hardcoded feature maps  plugins are the single source of truth
// for env vars, build args, directories, volumes, and build stages.
//
// Usage:
//   node scripts/generate-docker.mjs                         # all plugins
//   node scripts/generate-docker.mjs --exclude=ghidra,angr   # skip some
//   node scripts/generate-docker.mjs --include=pe-analysis,malware,frida
//   node scripts/generate-docker.mjs --dry-run               # preview only
//
// =============================================================================

import { execFileSync } from 'child_process'
import { readFileSync, writeFileSync, readdirSync, existsSync, statSync, mkdirSync } from 'fs'
import { join, dirname, basename, resolve } from 'path'
import { fileURLToPath } from 'url'
import {
  STATIC_PROFILE_BOTH_PLUGINS,
  STATIC_PROFILE_LOCK_FILE,
  STATIC_WORKFLOW_STAGES,
  createStaticProfileLock,
} from './static-profile-lock.mjs'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..')
const RIKUNE_VERSION = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8')).version
const DEFAULT_DATA_ROOT = 'D:/Docker/rikune'
const DEFAULT_NO_PROXY =
  'localhost,127.0.0.1,deb.debian.org,security.debian.org,archive.ubuntu.com,security.ubuntu.com'

const PROFILES = {
  full: {
    id: 'full',
    displayName: 'Full Docker analysis stack',
    composeName: 'rikune',
    composeFile: 'docker-compose.yml',
    dockerfile: 'Dockerfile',
    image: 'rikune:latest',
    service: 'mcp-server',
    container: 'rikune',
    component: 'mcp-server',
    nodeRole: 'analyzer',
    runtimeMode: 'disabled',
    buildDynamicDeps: true,
    description:
      'Full Linux-side analysis stack. Runtime remains disabled until you opt into manual or remote-sandbox mode.',
  },
  static: {
    id: 'static',
    displayName: 'Static-only Docker analyzer',
    composeName: 'rikune-analyzer',
    composeFile: 'docker-compose.analyzer.yml',
    dockerfile: 'docker/Dockerfile.analyzer',
    image: 'rikune-analyzer:latest',
    service: 'analyzer',
    container: 'rikune-analyzer',
    component: 'analyzer',
    nodeRole: 'analyzer',
    runtimeMode: 'disabled',
    buildDynamicDeps: false,
    description:
      'Static-only Linux analyzer. No runtime endpoint is configured and dynamic execution plugins are disabled.',
  },
  hybrid: {
    id: 'hybrid',
    displayName: 'Hybrid Docker analyzer + Windows runtime',
    composeName: 'rikune-hybrid',
    composeFile: 'docker-compose.hybrid.yml',
    dockerfile: 'docker/Dockerfile.hybrid',
    image: 'rikune-analyzer:latest',
    service: 'analyzer',
    container: 'rikune-analyzer',
    component: 'analyzer',
    nodeRole: 'analyzer',
    runtimeMode: 'remote-sandbox',
    buildDynamicDeps: false,
    description:
      'Linux analyzer image with dynamic tools delegated to a Windows Host Agent / Runtime Node.',
  },
}

const EXECUTION_DOCKER_FEATURES = new Set(['dynamic-python', 'frida', 'gdb', 'qiling', 'wine'])
const BACKEND_PROFILES = {
  default: new Set(['default']),
  full: new Set(['default', 'optional']),
  optional: new Set(['default', 'optional']),
  heavy: new Set(['default', 'optional', 'heavy']),
  research: new Set(['default', 'optional', 'heavy', 'research', 'license-gated']),
  runtime: new Set(['default', 'optional', 'runtime']),
  gpu: new Set(['default', 'optional', 'gpu']),
  all: new Set(['default', 'optional', 'heavy', 'research', 'runtime', 'gpu', 'license-gated']),
}

// -----------------------------------------------------------------------------
// 1. Auto-discover plugins from dist/plugins/ (or src/plugins/ for names)
// -----------------------------------------------------------------------------

function discoverPluginIds() {
  const names = new Set()
  for (const base of [join(ROOT, 'dist', 'plugins'), join(ROOT, 'src', 'plugins')]) {
    if (!existsSync(base)) continue
    for (const name of readdirSync(base)
      .filter((name) => {
        if (name === 'sdk.ts' || name === 'sdk.js' || name.startsWith('.')) return false
        const full = join(base, name)
        return statSync(full).isDirectory()
      })
      .sort()) {
      names.add(name)
    }
  }
  if (names.size > 0) return [...names].sort()
  console.error('  x Neither dist/plugins/ nor src/plugins/ found.')
  process.exit(1)
}

// -----------------------------------------------------------------------------
// 1b. Auto-discover plugins that have Python workers/ directories
// -----------------------------------------------------------------------------

function discoverPluginWorkerDirs(activePluginIds = null) {
  const srcPlugins = join(ROOT, 'src', 'plugins')
  if (!existsSync(srcPlugins)) return []
  return readdirSync(srcPlugins)
    .filter((name) => {
      if (name === 'sdk.ts' || name.startsWith('.')) return false
      if (activePluginIds && !activePluginIds.has(name)) return false
      const workersDir = join(srcPlugins, name, 'workers')
      return (
        existsSync(workersDir) &&
        statSync(workersDir).isDirectory() &&
        readdirSync(workersDir).some((f) => f.endsWith('.py'))
      )
    })
    .sort()
}

// -----------------------------------------------------------------------------
// 1c. Auto-discover plugins that have data/ directories with files
// -----------------------------------------------------------------------------

function discoverPluginDataDirs(activePluginIds = null) {
  const srcPlugins = join(ROOT, 'src', 'plugins')
  if (!existsSync(srcPlugins)) return []
  const result = []
  for (const name of readdirSync(srcPlugins).sort()) {
    if (name === 'sdk.ts' || name.startsWith('.')) continue
    if (activePluginIds && !activePluginIds.has(name)) continue
    const dataDir = join(srcPlugins, name, 'data')
    if (!existsSync(dataDir) || !statSync(dataDir).isDirectory()) continue
    const files = readdirSync(dataDir)
      .filter((f) => !f.startsWith('.'))
      .sort()
    if (files.length > 0) result.push({ plugin: name, files })
  }
  return result.sort((a, b) => a.plugin.localeCompare(b.plugin))
}

// -----------------------------------------------------------------------------
// 1d. Auto-discover Docker fragment files from src/plugins/*/docker/*.dockerfile
// -----------------------------------------------------------------------------

function discoverDockerFragments() {
  const srcPlugins = join(ROOT, 'src', 'plugins')
  if (!existsSync(srcPlugins)) return new Map()

  const fragments = new Map()

  for (const pluginName of readdirSync(srcPlugins).sort()) {
    if (pluginName === 'sdk.ts' || pluginName.startsWith('.')) continue
    const dockerDir = join(srcPlugins, pluginName, 'docker')
    if (!existsSync(dockerDir) || !statSync(dockerDir).isDirectory()) continue

    for (const file of readdirSync(dockerDir).sort()) {
      if (!file.endsWith('.dockerfile')) continue
      const feature = basename(file, '.dockerfile')
      const content = readFileSync(join(dockerDir, file), 'utf-8').replace(/\r\n/g, '\n')
      const parsed = parseDockerFragment(content)
      fragments.set(feature, { plugin: pluginName, ...parsed })
    }
  }
  return fragments
}

/**
 * Parse a Docker fragment file into sections.
 * Sections are delimited by: #===== ARGS =====, #===== STAGE =====, #===== RUNTIME =====
 */
function parseDockerFragment(content) {
  const sections = { args: '', stage: '', runtime: '' }
  let current = null

  for (const line of content.split('\n')) {
    const marker = line.match(/^#=====\s*(ARGS|STAGE|RUNTIME)\s*=====\s*$/i)
    if (marker) {
      current = marker[1].toLowerCase()
      continue
    }
    if (current && sections[current] !== undefined) {
      sections[current] += line + '\n'
    }
  }

  // Trim trailing newlines but keep content
  for (const key of Object.keys(sections)) {
    sections[key] = sections[key].replace(/\n+$/, '')
  }
  return sections
}

function assertPinnedExternalImages(dockerfile) {
  const declaredStages = new Set()
  const pinnedImagePattern = /^[^@\s]+:[^@\s]+@sha256:[a-f0-9]{64}$/

  for (const [index, line] of dockerfile.split('\n').entries()) {
    const match = line.match(/^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$/i)
    if (!match) continue

    const image = match[1]
    const isInternalStage = declaredStages.has(image.toLowerCase())
    if (!isInternalStage && image !== 'scratch' && !pinnedImagePattern.test(image)) {
      throw new Error(
        `External FROM must use an immutable tag@sha256 OCI index digest at line ${index + 1}: ${image}`
      )
    }
    if (match[2]) declaredStages.add(match[2].toLowerCase())
  }
}

function assertVerifiedDirectDownloads(dockerfile) {
  const normalized = dockerfile.replace(/\\\r?\n[ \t]*/g, ' ')
  const outputOptionPattern = /(?:^|\s)(?:-o|-O|-qO|--output)(?:=|\s+)/
  const verificationPattern =
    /^printf\s+['"]%s {2}%s\\n['"]\s+['"][a-f0-9]{64}['"]\s+.+\|\s*sha256sum\s+-c\s+-\s*$/

  for (const [index, line] of normalized.split('\n').entries()) {
    if (!line.startsWith('RUN ')) continue

    const commandPattern = /\b(?:curl|wget)\b/g
    let match
    while ((match = commandPattern.exec(line)) !== null) {
      const semicolon = line.indexOf(';', match.index)
      const andThen = line.indexOf('&&', match.index)
      const commandEnd = [semicolon, andThen]
        .filter((position) => position >= 0)
        .reduce((minimum, position) => Math.min(minimum, position), line.length)
      const command = line.slice(match.index, commandEnd)
      if (!outputOptionPattern.test(command)) continue

      const separatorLength = line.startsWith('&&', commandEnd) ? 2 : 1
      const nextSeparatorCandidates = [
        line.indexOf(';', commandEnd + separatorLength),
        line.indexOf('&&', commandEnd + separatorLength),
      ].filter((position) => position >= 0)
      const verificationEnd =
        nextSeparatorCandidates.length > 0 ? Math.min(...nextSeparatorCandidates) : line.length
      const verification = line.slice(commandEnd + separatorLength, verificationEnd).trim()
      if (!verificationPattern.test(verification)) {
        throw new Error(
          `Direct download must be immediately followed by SHA256 verification before consumption at RUN line ${index + 1}: ${command}`
        )
      }

      commandPattern.lastIndex = verificationEnd
    }
  }
}

function assertStaticPythonSupplyChain(dockerfile) {
  const normalized = dockerfile.replace(/\\\r?\n[ \t]*/g, ' ')
  for (const [index, line] of normalized.split('\n').entries()) {
    if (!line.startsWith('RUN ')) continue
    for (const command of line.slice('RUN '.length).split(/\s*(?:&&|;)\s*/)) {
      if (!/\bpip(?:3)?\s+install\b/.test(command)) continue
      if (/--upgrade(?:\s|$)/.test(command)) {
        throw new Error(
          `Static profile must not upgrade Python packages during image generation at RUN line ${index + 1}: ${command}`
        )
      }
      if (!/--require-hashes(?:\s|$)/.test(command)) {
        throw new Error(
          `Static profile Python install must use --require-hashes at RUN line ${index + 1}: ${command}`
        )
      }
    }
  }

  const forbiddenOptionalDependencies = [
    { pattern: /requirements-qiling/i, name: 'requirements-qiling' },
    { pattern: /requirements-gtirb/i, name: 'requirements-gtirb' },
    { pattern: /\/opt\/(?:rikune-venvs\/)?gtirb/i, name: 'GTIRB install stage' },
  ]
  for (const { pattern, name } of forbiddenOptionalDependencies) {
    if (pattern.test(dockerfile)) {
      throw new Error(
        `Static profile must not include non-release optional Python dependency: ${name}`
      )
    }
  }
}

function assertNoBundledQilingInstall(dockerfile) {
  const normalized = dockerfile.replace(/\\\r?\n[ \t]*/g, ' ')
  const forbiddenQilingInstall =
    /requirements-qiling|\bpip(?:3)?\s+install\b[^\n]*(?:\bqiling\b)|\/opt\/qiling-venv/i
  if (forbiddenQilingInstall.test(normalized)) {
    throw new Error(
      'Generated profiles must not bundle Qiling while its supported dependency chain is below the release vulnerability baseline'
    )
  }
}

function assertDockerSupplyChain(dockerfile, requireHashedPython) {
  assertPinnedExternalImages(dockerfile)
  assertVerifiedDirectDownloads(dockerfile)
  assertNoBundledQilingInstall(dockerfile)
  if (requireHashedPython) assertStaticPythonSupplyChain(dockerfile)
}

// -----------------------------------------------------------------------------
// 1e. Auto-discover plugin scripts/ directories exposed as MCP resources
// -----------------------------------------------------------------------------

function discoverPluginScriptDirs(activePluginIds = null) {
  const srcPlugins = join(ROOT, 'src', 'plugins')
  if (!existsSync(srcPlugins)) return []

  return readdirSync(srcPlugins)
    .filter((name) => {
      if (name === 'sdk.ts' || name.startsWith('.')) return false
      if (activePluginIds && !activePluginIds.has(name)) return false
      const scriptsDir = join(srcPlugins, name, 'scripts')
      return (
        existsSync(scriptsDir) &&
        statSync(scriptsDir).isDirectory() &&
        readdirSync(scriptsDir).some((f) => !f.startsWith('.'))
      )
    })
    .sort()
}

// -----------------------------------------------------------------------------
// 2. Load systemDeps from source plugins, with dist as a compatibility fallback
// -----------------------------------------------------------------------------

function loadSourcePluginMetadata(sourceEntries) {
  if (sourceEntries.length === 0) return new Map()

  const marker = '__RIKUNE_SOURCE_PLUGIN_METADATA__'
  const loader = `
const entries = JSON.parse(process.argv[1])
const results = []
for (const entry of entries) {
  try {
    const mod = await import('file://' + entry.path.replace(/\\\\/g, '/'))
    const plugin = mod.default
    results.push({
      id: entry.id,
      plugin: {
        id: plugin?.id,
        executionDomain: plugin?.executionDomain ?? 'both',
        dependencies: plugin?.dependencies ?? [],
        systemDeps: plugin?.systemDeps ?? [],
      },
    })
  } catch (error) {
    results.push({
      id: entry.id,
      error: error instanceof Error ? error.message : String(error),
    })
  }
}
console.log('${marker}' + JSON.stringify(results))
`
  const output = execFileSync(
    process.execPath,
    ['--import', 'tsx', '--eval', loader, JSON.stringify(sourceEntries)],
    {
      cwd: ROOT,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }
  )
  const metadataLine = output.split('\n').findLast((line) => line.startsWith(marker))
  if (!metadataLine) throw new Error('Source metadata loader did not return its result marker')
  return new Map(JSON.parse(metadataLine.slice(marker.length)).map((entry) => [entry.id, entry]))
}

async function loadPluginMetadata(pluginIds) {
  const distDir = join(ROOT, 'dist', 'plugins')

  const result = new Map()
  let loaded = 0
  const failures = []
  const fallbackWarnings = []

  function normalizePluginMetadata(id, plugin) {
    return {
      id,
      executionDomain: plugin?.executionDomain ?? 'both',
      dependencies: Array.isArray(plugin?.dependencies) ? plugin.dependencies : [],
      systemDeps: plugin?.systemDeps ?? [],
    }
  }

  async function loadDistPlugin(indexPath) {
    return (await import(`file://${indexPath.replace(/\\/g, '/')}`)).default
  }

  const sourceEntries = pluginIds
    .map((id) => ({ id, path: join(ROOT, 'src', 'plugins', id, 'index.ts') }))
    .filter((entry) => existsSync(entry.path))
  let sourceMetadata = new Map()
  let sourceBatchError = null
  try {
    sourceMetadata = loadSourcePluginMetadata(sourceEntries)
  } catch (err) {
    sourceBatchError = err instanceof Error ? err.message : String(err)
  }

  for (const id of pluginIds) {
    const indexPath = join(distDir, id, 'index.js')
    const srcIndexPath = join(ROOT, 'src', 'plugins', id, 'index.ts')
    if (!existsSync(indexPath) && !existsSync(srcIndexPath)) {
      result.set(id, { id, executionDomain: 'both', dependencies: [], systemDeps: [] })
      continue
    }
    try {
      let plugin
      const sourceEntry = sourceMetadata.get(id)
      if (sourceEntry?.plugin) {
        plugin = sourceEntry.plugin
      } else if (existsSync(indexPath)) {
        const sourceError = sourceEntry?.error ?? sourceBatchError
        if (sourceError) fallbackWarnings.push(`${id}: source metadata failed: ${sourceError}`)
        plugin = await loadDistPlugin(indexPath)
      } else {
        throw new Error(sourceEntry?.error ?? sourceBatchError ?? 'Source metadata unavailable')
      }
      result.set(id, normalizePluginMetadata(id, plugin))
      if (plugin?.systemDeps?.length > 0) loaded++
    } catch (err) {
      failures.push(`${id}: ${err instanceof Error ? err.message : String(err)}`)
      result.set(id, { id, executionDomain: 'both', dependencies: [], systemDeps: [] })
    }
  }

  console.log(`  Scanned ${pluginIds.length} plugins, ${loaded} have systemDeps`)
  if (fallbackWarnings.length > 0) {
    console.log(`  Metadata source fallbacks (${fallbackWarnings.length}):`)
    for (const warning of fallbackWarnings.slice(0, 10)) console.log(`    - ${warning}`)
    if (fallbackWarnings.length > 10) console.log(`    ... ${fallbackWarnings.length - 10} more`)
  }
  if (failures.length > 0) {
    console.log(`  Metadata load warnings (${failures.length}):`)
    for (const failure of failures.slice(0, 10)) console.log(`    - ${failure}`)
    if (failures.length > 10) console.log(`    ... ${failures.length - 10} more`)
  }
  return result
}

async function expandPluginDependencies(pluginIds, metadata, allPluginIds) {
  const knownIds = new Set(allPluginIds)
  const selectedIds = new Set(pluginIds)
  let pendingIds = [...pluginIds]

  while (pendingIds.length > 0) {
    const missingMetadataIds = pendingIds.filter((id) => !metadata.has(id))
    if (missingMetadataIds.length > 0) {
      const loadedMetadata = await loadPluginMetadata(missingMetadataIds)
      for (const [id, pluginMetadata] of loadedMetadata) metadata.set(id, pluginMetadata)
    }

    const nextIds = []
    for (const id of pendingIds) {
      for (const dependencyId of metadata.get(id)?.dependencies ?? []) {
        if (!knownIds.has(dependencyId)) {
          throw new Error(`Plugin '${id}' depends on unknown plugin '${dependencyId}'.`)
        }
        if (!selectedIds.has(dependencyId)) {
          selectedIds.add(dependencyId)
          nextIds.push(dependencyId)
        }
      }
    }
    pendingIds = nextIds
  }

  return allPluginIds.filter((id) => selectedIds.has(id))
}

function prunePluginsWithMissingDependencies(pluginIds, metadata) {
  const selectedIds = new Set(pluginIds)
  const removed = []
  let changed = true

  while (changed) {
    changed = false
    for (const id of [...selectedIds]) {
      const missingDependency = (metadata.get(id)?.dependencies ?? []).find(
        (dependencyId) => !selectedIds.has(dependencyId)
      )
      if (missingDependency) {
        selectedIds.delete(id)
        removed.push({ id, missingDependency })
        changed = true
      }
    }
  }

  return {
    pluginIds: pluginIds.filter((id) => selectedIds.has(id)),
    removed,
  }
}

function depsForPluginIds(pluginIds, metadata, profile = PROFILES.full) {
  const result = new Map()
  for (const id of pluginIds) {
    const deps = metadata.get(id)?.systemDeps ?? []
    result.set(
      id,
      profile.buildDynamicDeps
        ? deps
        : deps.filter((dep) => !EXECUTION_DOCKER_FEATURES.has(dep.dockerFeature))
    )
  }
  return result
}

function backendProfileAllows(dep, backendProfile = 'default') {
  const route = dep.dockerInstallRoute
  const depProfile = dep.dockerInstallProfile ?? 'default'
  if (route === 'byo' || route === 'sidecar' || route === 'validation-only') return false
  if (route === 'profile-gated' && !BACKEND_PROFILES[backendProfile]?.has(depProfile)) return false
  return BACKEND_PROFILES[backendProfile]?.has(depProfile) ?? false
}

function filterDepsByBackendProfile(pluginDepMap, backendProfile = 'default') {
  const result = new Map()
  for (const [id, deps] of pluginDepMap) {
    result.set(
      id,
      deps.filter((dep) => {
        if (!dep.dockerFeature) return true
        return backendProfileAllows(dep, backendProfile)
      })
    )
  }
  return result
}

function classifyInstallRoute(feature, deps, fragments, backendProfile) {
  const routes = new Set(deps.map((dep) => dep.dockerInstallRoute).filter(Boolean))
  const profiles = new Set(deps.map((dep) => dep.dockerInstallProfile).filter(Boolean))
  const hasFragment = fragments.has(feature)
  const hasApt = deps.some((dep) => dep.aptPackages?.length > 0)
  const hasValidation = deps.some((dep) => dep.dockerValidation?.length > 0)
  const hasDockerDefault = deps.some((dep) => dep.envVar && dep.dockerDefault)
  const explicitRoute = routes.values().next().value
  const installProfile = profiles.values().next().value ?? 'default'

  if (
    explicitRoute === 'byo' ||
    explicitRoute === 'sidecar' ||
    explicitRoute === 'validation-only'
  ) {
    return { route: explicitRoute, installProfile, enabled: false }
  }
  if (explicitRoute === 'profile-gated' && !BACKEND_PROFILES[backendProfile]?.has(installProfile)) {
    return { route: 'profile-gated', installProfile, enabled: false }
  }
  if (hasFragment) return { route: explicitRoute ?? 'installed', installProfile, enabled: true }
  if (hasApt) return { route: explicitRoute ?? 'installed', installProfile, enabled: true }
  if (feature === 'dynamic-python')
    return { route: explicitRoute ?? 'installed', installProfile, enabled: true }
  if (hasValidation && hasDockerDefault) {
    return { route: explicitRoute ?? 'validation-only', installProfile, enabled: true }
  }
  return { route: explicitRoute ?? 'missing', installProfile, enabled: false }
}

function collectBackendInstallReport(pluginDepMap, fragments, backendProfile = 'default') {
  const byFeature = new Map()
  for (const [plugin, deps] of pluginDepMap) {
    for (const dep of deps) {
      if (!dep.dockerFeature) continue
      const route = dep.dockerInstallRoute ?? 'installed'
      const profile = dep.dockerInstallProfile ?? 'default'
      const key = `${dep.dockerFeature}:${route}:${profile}`
      const entry = byFeature.get(key) ?? {
        feature: dep.dockerFeature,
        plugins: new Set(),
        deps: [],
      }
      entry.plugins.add(plugin)
      entry.deps.push(dep)
      byFeature.set(key, entry)
    }
  }

  return [...byFeature.values()]
    .map((entry) => ({
      feature: entry.feature,
      plugins: [...entry.plugins].sort(),
      ...classifyInstallRoute(entry.feature, entry.deps, fragments, backendProfile),
    }))
    .sort((a, b) => {
      const byFeatureName = a.feature.localeCompare(b.feature)
      if (byFeatureName !== 0) return byFeatureName
      const byRoute = a.route.localeCompare(b.route)
      if (byRoute !== 0) return byRoute
      return a.installProfile.localeCompare(b.installProfile)
    })
}

function filterBuildPluginsForProfile(pluginIds, metadata, profile) {
  if (profile.buildDynamicDeps) return pluginIds
  return pluginIds.filter((id) => metadata.get(id)?.executionDomain !== 'dynamic')
}

function assertStaticProfileSelection(pluginIds, metadata) {
  const lock = createStaticProfileLock(pluginIds)
  const staticPlugins = pluginIds.filter((id) => metadata.get(id)?.executionDomain === 'static')
  const bothPlugins = pluginIds.filter(
    (id) => (metadata.get(id)?.executionDomain ?? 'both') === 'both'
  )
  const unexpectedDomains = pluginIds.filter(
    (id) => !['static', 'both'].includes(metadata.get(id)?.executionDomain ?? 'both')
  )
  if (staticPlugins.length !== 97) {
    throw new Error(
      `Static profile requires exactly 97 static plugins; received ${staticPlugins.length}`
    )
  }
  if (bothPlugins.join(',') !== STATIC_PROFILE_BOTH_PLUGINS.join(',')) {
    throw new Error(
      `Static profile requires exact both-domain plugins ${STATIC_PROFILE_BOTH_PLUGINS.join(',')}; received ${bothPlugins.join(',')}`
    )
  }
  if (unexpectedDomains.length > 0) {
    throw new Error(
      `Static profile contains non-static execution domains: ${unexpectedDomains.join(',')}`
    )
  }
  return lock
}

// -----------------------------------------------------------------------------
// 3. Collect Docker requirements from systemDeps (zero hardcoded maps)
// -----------------------------------------------------------------------------

function collectDockerRequirements(pluginDepMap) {
  const features = new Set()
  const aptPackages = new Set()
  const envVars = new Map()
  const extraEnv = new Map()
  const buildArgs = new Map()
  const directories = []
  const volumes = []
  const validationCmds = []

  for (const [, deps] of pluginDepMap) {
    for (const dep of deps) {
      if (dep.dockerFeature) features.add(dep.dockerFeature)
      if (dep.aptPackages) for (const pkg of dep.aptPackages) aptPackages.add(pkg)
      if (dep.envVar && dep.dockerDefault) envVars.set(dep.envVar, dep.dockerDefault)
      if (dep.dockerValidation) {
        for (const cmd of dep.dockerValidation) {
          if (!validationCmds.includes(cmd)) validationCmds.push(cmd)
        }
      }
      // New fields from extended PluginSystemDep
      if (dep.extraEnv) {
        for (const [k, v] of Object.entries(dep.extraEnv)) extraEnv.set(k, v)
      }
      if (dep.buildArgs) {
        for (const [k, v] of Object.entries(dep.buildArgs)) buildArgs.set(k, v)
      }
      if (dep.directories) {
        for (const d of dep.directories) {
          if (!directories.some((x) => x.path === d.path)) directories.push(d)
        }
      }
      if (dep.volumes) {
        for (const v of dep.volumes) {
          if (!volumes.some((x) => x.target === v.target)) volumes.push(v)
        }
      }
    }
  }

  // Implied: frida/pandare/yara-x need dynamic-python deps
  if (features.has('frida') || features.has('dynamic-python')) {
    features.add('dynamic-python')
  }

  return {
    features,
    aptPackages: [...aptPackages].sort(),
    envVars,
    extraEnv,
    buildArgs,
    directories,
    volumes,
    validationCmds,
  }
}

// -----------------------------------------------------------------------------
// 4. Process Dockerfile.template
// -----------------------------------------------------------------------------

function processTemplate(
  template,
  requirements,
  pluginWorkerIds,
  pluginDataEntries,
  pluginScriptIds,
  fragments,
  profile,
  staticProfileLock
) {
  const { features, aptPackages, envVars, extraEnv, directories, validationCmds } = requirements

  // 4a. Conditional blocks (only dynamic-python remains in template)
  const lines = template.replace(/\r\n/g, '\n').split('\n')
  const output = []
  const stack = []
  let enabled = true

  for (const line of lines) {
    const ifMatch = line.match(/^[ \t]*# @if (.+)$/)
    const endifMatch = line.match(/^[ \t]*# @endif (.+)$/)
    if (ifMatch) {
      stack.push(enabled)
      enabled = enabled && features.has(ifMatch[1].trim())
      continue
    }
    if (endifMatch) {
      enabled = stack.pop() ?? true
      continue
    }
    if (enabled) output.push(line)
  }

  let result = output.join('\n')
  result = result.replaceAll('{{RIKUNE_VERSION}}', RIKUNE_VERSION)
  result = result.replace(
    '{{STATIC_PROFILE_LOCK_COPY}}',
    profile.id === 'static'
      ? `COPY ${STATIC_PROFILE_LOCK_FILE} /app/${STATIC_PROFILE_LOCK_FILE}`
      : ''
  )
  result = result.replace(
    '{{STATIC_PROFILE_ENV}}',
    staticProfileLock
      ? `ENV RIKUNE_DOCKER_PROFILE=static \\
    RIKUNE_STATIC_PROFILE_LOCK_PATH=/app/${STATIC_PROFILE_LOCK_FILE} \\
    RUNTIME_MODE=disabled \\
    PLUGINS=${staticProfileLock.plugins.join(',')} \\
    STATIC_WORKFLOW_STAGES=${staticProfileLock.static_workflow_stages.join(',')} \\
${staticProfileLock.required_backends
  .flatMap((backend) => backend.environment)
  .filter((binding) => 'required' in binding && binding.required)
  .map((binding, index, bindings) =>
    index < bindings.length - 1
      ? `    ${binding.name}=${binding.value} \\`
      : `    ${binding.name}=${binding.value}`
  )
  .join('\n')}`
      : ''
  )
  result = result.replace(
    '{{STATIC_PROFILE_IMAGE_CONTRACT}}',
    staticProfileLock
      ? `RUN printf 'static\\n' > /app/.rikune-static-profile && \\
    chown root:root /app/.rikune-static-profile /app/${STATIC_PROFILE_LOCK_FILE} && \\
    chmod 0444 /app/.rikune-static-profile /app/${STATIC_PROFILE_LOCK_FILE}
LABEL org.opencontainers.image.rikune.profile="static"`
      : ''
  )
  result = result.replace(
    '{{STATIC_PROFILE_USER}}',
    staticProfileLock || profile.id === 'hybrid'
      ? `# The ${profile.id} image runs unprivileged by default. Runtime mounts must be owned by uid/gid 1000.
USER 1000:1000`
      : ''
  )
  result = result.replace(
    '{{FULL_STACK_VALIDATOR_COPY}}',
    profile.id === 'full'
      ? `COPY scripts/validate-docker-full-stack.sh /usr/local/bin/validate-docker-full-stack.sh
RUN chown root:root /usr/local/bin/validate-docker-full-stack.sh && \\
    chmod 0555 /usr/local/bin/validate-docker-full-stack.sh`
      : ''
  )

  // 4b. {{FEATURE_ARGS}} - global ARG declarations from fragments
  const featureArgLines = []
  for (const [feature, frag] of fragments) {
    if (features.has(feature) && frag.args) featureArgLines.push(frag.args)
  }
  result = result.replace('{{FEATURE_ARGS}}', featureArgLines.join('\n') || '')

  // 4c. {{BUILD_STAGES}} - build stages from fragments
  const stageLines = []
  for (const [feature, frag] of fragments) {
    if (features.has(feature) && frag.stage) stageLines.push(frag.stage)
  }
  result = result.replace('{{BUILD_STAGES}}', stageLines.join('\n\n') || '')

  // 4d. {{FEATURE_RUNTIME}} - runtime install/copy from fragments
  const runtimeLines = []
  for (const [feature, frag] of fragments) {
    if (features.has(feature) && frag.runtime) runtimeLines.push(frag.runtime)
  }
  result = result.replace('{{FEATURE_RUNTIME}}', runtimeLines.join('\n\n') || '')

  // 4e. {{RUNTIME_APT_PACKAGES}}
  const aptLines =
    aptPackages.length > 0 ? aptPackages.map((p) => `    ${p} \\`).join('\n') + '\n' : ''
  result = result.replace('{{RUNTIME_APT_PACKAGES}}', aptLines)

  // 4f. {{RUNTIME_ENV_VARS}} - merged from envVars + extraEnv (plugin-driven)
  const allEnv = new Map(envVars)
  for (const [k, v] of extraEnv) allEnv.set(k, v)
  allEnv.delete('SANDBOX_PYTHON_PATH') // already in base block
  // Remove vars that are set inline in fragment RUNTIME sections
  allEnv.delete('JAVA_HOME')
  allEnv.delete('JAVA_TOOL_OPTIONS')

  if (allEnv.size > 0) {
    const entries = [...allEnv.entries()]
    const envLines =
      entries
        .map(([k, v], i) => (i < entries.length - 1 ? `    ${k}=${v} \\` : `    ${k}=${v}`))
        .join('\n') + '\n'
    // Add trailing backslash to SANDBOX_PYTHON_PATH so ENV block continues
    result = result.replace(
      'SANDBOX_PYTHON_PATH=/usr/local/bin/python3\n{{RUNTIME_ENV_VARS}}',
      'SANDBOX_PYTHON_PATH=/usr/local/bin/python3 \\\n' + envLines
    )
  } else {
    result = result.replace('\n{{RUNTIME_ENV_VARS}}', '')
  }

  // 4g. {{VALIDATION_COMMANDS}}
  const allValidation = [
    'echo "[validate] Rikune Docker image"',
    ...validationCmds,
    'echo "[validate] All checks passed"',
  ].map((cmd) => `(${cmd})`)
  result = result.replace('{{VALIDATION_COMMANDS}}', `RUN ${allValidation.join(' && \\\n    ')}`)

  // 4h. {{EXTRA_DIRS}} / {{EXTRA_CHOWN}} - from plugin systemDeps directories
  const extraDirs = directories.map((d) => d.path)
  const extraChown = directories.filter((d) => d.chown).map((d) => `chown -R ${d.chown} ${d.path}`)
  result = result.replace('{{EXTRA_DIRS}}', extraDirs.join(' '))
  result = result.replace(
    '{{EXTRA_CHOWN}}',
    extraChown.length > 0 ? extraChown.map((c) => `    ${c} && \\`).join('\n') + '\n' : ''
  )

  // 4i. {{PLUGIN_WORKER_COPY}} / {{PLUGIN_WORKER_COPY_FROM}}
  if (pluginWorkerIds.length > 0) {
    const copyLines = pluginWorkerIds
      .map((id) => `COPY src/plugins/${id}/workers/ ./src/plugins/${id}/workers/`)
      .join('\n')
    result = result.replace('{{PLUGIN_WORKER_COPY}}', copyLines)

    const copyFromLines = pluginWorkerIds
      .map(
        (id) =>
          `COPY --from=python-base /app/src/plugins/${id}/workers/ ./src/plugins/${id}/workers/`
      )
      .join('\n')
    result = result.replace('{{PLUGIN_WORKER_COPY_FROM}}', copyFromLines)
  } else {
    result = result.replace('{{PLUGIN_WORKER_COPY}}\n', '')
    result = result.replace('{{PLUGIN_WORKER_COPY_FROM}}\n', '')
  }

  // 4j. {{PLUGIN_DATA_COPY}}
  if (pluginDataEntries.length > 0) {
    const dataLines = []
    for (const { plugin, files } of pluginDataEntries) {
      dataLines.push(`RUN mkdir -p ./src/plugins/${plugin}/data`)
      for (const f of files) {
        dataLines.push(`COPY src/plugins/${plugin}/data/${f} ./src/plugins/${plugin}/data/${f}`)
      }
    }
    result = result.replace('{{PLUGIN_DATA_COPY}}', dataLines.join('\n'))
  } else {
    result = result.replace('{{PLUGIN_DATA_COPY}}\n', '')
  }

  // 4k. {{PLUGIN_SCRIPT_COPY}}
  if (pluginScriptIds.length > 0) {
    const scriptLines = pluginScriptIds
      .map((id) => `COPY src/plugins/${id}/scripts/ ./src/plugins/${id}/scripts/`)
      .join('\n')
    result = result.replace('{{PLUGIN_SCRIPT_COPY}}', scriptLines)
  } else {
    result = result.replace('{{PLUGIN_SCRIPT_COPY}}\n', '')
  }

  const dockerfile = result.replace(/\n{3,}/g, '\n\n')
  assertDockerSupplyChain(dockerfile, profile.id === 'static')
  return dockerfile
}

// -----------------------------------------------------------------------------
// 5. Generate docker-compose.yml (all values from plugin systemDeps)
// -----------------------------------------------------------------------------

function makePluginsEnv(pluginIds) {
  return pluginIds.length > 0 ? pluginIds.join(',') : ''
}

function generateDockerCompose(
  requirements,
  buildPluginIds,
  runtimePluginIds,
  profile,
  backendProfile,
  staticProfileLock
) {
  const { features, envVars, extraEnv, buildArgs, volumes: pluginVolumes } = requirements

  // Build args from plugins. Proxy args are always set explicitly so Docker
  // Desktop cannot auto-inject an unusable 127.0.0.1 proxy into Linux builds.
  const allBuildArgs = new Map([
    ['HTTP_PROXY', '${RIKUNE_BUILD_HTTP_PROXY:-}'],
    ['HTTPS_PROXY', '${RIKUNE_BUILD_HTTPS_PROXY:-}'],
    ['http_proxy', '${RIKUNE_BUILD_HTTP_PROXY:-}'],
    ['https_proxy', '${RIKUNE_BUILD_HTTPS_PROXY:-}'],
    ['NO_PROXY', `\${RIKUNE_BUILD_NO_PROXY:-${DEFAULT_NO_PROXY}}`],
  ])
  for (const [k, v] of buildArgs) allBuildArgs.set(k, v)
  const buildArgsYaml =
    '\n' +
    [...allBuildArgs.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `        ${k}: "${v}"`)
      .join('\n')

  // Environment: base + plugin-declared
  const allEnv = new Map([
    ['NODE_ENV', 'production'],
    ['PYTHONUNBUFFERED', '1'],
    ['RIKUNE_DOCKER_PROFILE', profile.id],
    ['RIKUNE_BACKEND_PROFILE', backendProfile],
    ['NODE_ROLE', profile.nodeRole],
    ['RUNTIME_MODE', profile.runtimeMode],
    ['PLUGINS', makePluginsEnv(runtimePluginIds)],
    ['WORKSPACE_ROOT', '/app/workspaces'],
    ['DB_PATH', '/app/data/database.db'],
    ['CACHE_ROOT', '/app/cache'],
    ['HOME', '/tmp/rikune-home'],
    ['AUDIT_LOG_PATH', '/app/logs/audit.log'],
    ['XDG_CONFIG_HOME', '/tmp/rikune-home/.config'],
    ['XDG_CACHE_HOME', '/tmp/rikune-home/.cache'],
    ['LOG_LEVEL', 'info'],
    ['SANDBOX_PYTHON_PATH', '/usr/local/bin/python3'],
  ])
  if (profile.id === 'static') {
    allEnv.set('STATIC_WORKFLOW_STAGES', STATIC_WORKFLOW_STAGES.join(','))
  }
  for (const [k, v] of envVars) allEnv.set(k, v)
  for (const [k, v] of extraEnv) {
    if (k === 'JAVA_TOOL_OPTIONS' || k === 'JAVA_HOME') continue
    allEnv.set(k, v)
  }
  // Static Compose is another entrypoint into the exact OCI contract.  Its
  // environment must be derived from the same generated lock as the image,
  // overriding plugin defaults (for example the canonical UPX path).
  if (staticProfileLock) {
    for (const binding of staticProfileLock.required_backends.flatMap(
      (backend) => backend.environment
    )) {
      if ('must_be_unset' in binding && binding.must_be_unset) {
        allEnv.delete(binding.name)
      } else if ('required' in binding && binding.required) {
        allEnv.set(binding.name, binding.value)
      }
    }
  }
  if (profile.id === 'hybrid') {
    allEnv.set('RUNTIME_HOST_AGENT_ENDPOINT', '${RUNTIME_HOST_AGENT_ENDPOINT:-}')
    allEnv.set('RUNTIME_HOST_AGENT_API_KEY', '${RUNTIME_HOST_AGENT_API_KEY:-}')
    allEnv.set('RUNTIME_API_KEY', '${RUNTIME_API_KEY:-}')
    allEnv.set('RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP', '${RIKUNE_ALLOW_INSECURE_RUNTIME_HTTP:-false}')
  }

  const envLines = [...allEnv.entries()].map(([k, v]) => `      - ${k}=${v}`).join('\n')

  // Volumes: base + plugin-declared
  let volumeYaml = `      - ./samples:/samples:ro
      - "\${RIKUNE_DATA_ROOT:-${DEFAULT_DATA_ROOT}}/workspaces:/app/workspaces:rw"
      - "\${RIKUNE_DATA_ROOT:-${DEFAULT_DATA_ROOT}}/data:/app/data:rw"
      - "\${RIKUNE_DATA_ROOT:-${DEFAULT_DATA_ROOT}}/cache:/app/cache:rw"
      - "\${RIKUNE_DATA_ROOT:-${DEFAULT_DATA_ROOT}}/logs:/app/logs:rw"
      - "\${RIKUNE_DATA_ROOT:-${DEFAULT_DATA_ROOT}}/storage:/app/storage:rw"`
  for (const vol of pluginVolumes) {
    volumeYaml += `\n      - "${vol.source}:${vol.target}:${vol.mode || 'rw'}"`
  }
  volumeYaml += `
      - type: volume
        source: root-config
        target: /app/cache/home/.rikune`

  const namedVol = `  root-config:\n    driver: local\n  storage:\n    driver: local`

  const featureList = [...features].sort().join(', ') || 'none'

  return `# =============================================================================
# Docker Compose - Rikune (${profile.id})
# =============================================================================
# Auto-generated from plugin systemDeps.
# Profile: ${profile.displayName}
# Backend profile: ${backendProfile}
# Build plugins: ${buildPluginIds.length} | Runtime plugins: ${runtimePluginIds.length}
# Features: ${featureList}
# Regenerate: npm run docker:generate -- --profile=${profile.id}
# =============================================================================

name: ${profile.composeName}

services:
  ${profile.service}:
    image: ${profile.image}
    platform: linux/amd64
    build:
      context: .
      dockerfile: ${profile.dockerfile}
      args:${buildArgsYaml}
    container_name: ${profile.container}
    # A root operator can replace the entrypoint/user; deployment admission is the trust boundary.
    user: "1000:1000"
    stdin_open: true
    tty: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    mem_limit: 8g
    pids_limit: 512
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=512m
    deploy:
      resources:
        limits:
          memory: 8G
          cpus: '2'
          pids: 512
        reservations:
          memory: 2G
    volumes:
${volumeYaml}
    environment:
${envLines}
      # API File Server
      - API_ENABLED=true
      - API_PORT=18080
      - API_KEY=\${RIKUNE_API_KEY:?RIKUNE_API_KEY_required_when_API_ENABLED_true}
      - API_STORAGE_ROOT=/app/storage
      - API_MAX_FILE_SIZE=524288000
      - API_RETENTION_DAYS=30
    healthcheck:
      test: ["CMD", "node", "-e", "const http=require('http');const r=http.get('http://localhost:18080/api/v1/health',res=>{process.exit(res.statusCode===200?0:1)});r.on('error',()=>process.exit(1));r.setTimeout(5000,()=>process.exit(1))"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    ports:
      - "127.0.0.1:\${RIKUNE_API_PORT:-18080}:18080"
    extra_hosts:
      - "host.docker.internal:host-gateway"
    restart: unless-stopped
    labels:
      - "app=rikune"
      - "component=${profile.component}"
      - "security.isolation=high"

volumes:
${namedVol}
`
}

// -----------------------------------------------------------------------------
// 6. CLI
// -----------------------------------------------------------------------------

async function main() {
  const args = process.argv.slice(2)
  const flags = {}
  for (const arg of args) {
    const m = arg.match(/^--(\w[\w-]*)(?:=(.*))?$/)
    if (m) flags[m[1]] = m[2] ?? true
  }

  if (flags.help) {
    console.log(`
Rikune Docker Generator - builds deployment-profile Dockerfiles and Compose files

Usage:
  node scripts/generate-docker.mjs --profile=full
  node scripts/generate-docker.mjs --profile=static
  node scripts/generate-docker.mjs --profile=hybrid
  node scripts/generate-docker.mjs --all-profiles

Options:
  --profile=<name>  full | static | hybrid (default: full)
  --all-profiles    Generate full, static, and hybrid deployment files
  --include=<ids>   Include these plugins and their transitive plugin dependencies
  --exclude=<ids>   Exclude these plugins and cascade-remove dependent plugins
  --output=<dir>    Output directory (default: project root)
  --backend-profile=<name>  default | full | optional | heavy | research | runtime | gpu | all
  --dry-run         Preview profile resolution without writing files
  --help            Show this help
`)
    process.exit(0)
  }

  console.log('--- Rikune Docker Generator ---')
  const backendProfile = flags['backend-profile'] || 'default'
  if (!BACKEND_PROFILES[backendProfile]) {
    console.error(`  x Unknown backend profile '${backendProfile}'.`)
    process.exit(1)
  }

  const selectedProfiles = flags['all-profiles']
    ? [PROFILES.full, PROFILES.static, PROFILES.hybrid]
    : [PROFILES[flags.profile || 'full']]
  if (selectedProfiles.some((p) => !p)) {
    console.error(`  x Unknown profile '${flags.profile}'. Use full, static, or hybrid.`)
    process.exit(1)
  }

  const allPlugins = discoverPluginIds()
  console.log(`  Discovered ${allPlugins.length} plugins`)

  let selectedPluginIds = [...allPlugins]
  if (flags.include) {
    const include = new Set(flags.include.split(',').map((s) => s.trim()))
    selectedPluginIds = selectedPluginIds.filter((id) => include.has(id))
    console.log(`  --include: ${selectedPluginIds.length} selected`)
  }

  console.log('\n  Loading plugin metadata from src/ (dist fallback)...')
  const metadata = await loadPluginMetadata(selectedPluginIds)
  if (flags.include) {
    const explicitlySelected = new Set(selectedPluginIds)
    selectedPluginIds = await expandPluginDependencies(selectedPluginIds, metadata, allPlugins)
    const addedDependencies = selectedPluginIds.filter((id) => !explicitlySelected.has(id))
    if (addedDependencies.length > 0) {
      console.log(`  --include dependencies: added ${addedDependencies.join(', ')}`)
    }
  }
  if (flags.exclude) {
    const exclude = new Set(flags.exclude.split(',').map((s) => s.trim()))
    const before = selectedPluginIds.length
    selectedPluginIds = selectedPluginIds.filter((id) => !exclude.has(id))
    console.log(`  --exclude: removed ${before - selectedPluginIds.length}`)
  }
  const prunedSelection = prunePluginsWithMissingDependencies(selectedPluginIds, metadata)
  selectedPluginIds = prunedSelection.pluginIds
  for (const item of prunedSelection.removed) {
    console.log(`  --exclude cascade: removed ${item.id} (requires ${item.missingDependency})`)
  }
  console.log(
    `  Runtime selection base (${selectedPluginIds.length}): ${selectedPluginIds.join(', ')}`
  )

  const fragments = discoverDockerFragments()

  const templatePath = join(ROOT, 'docker', 'Dockerfile.template')
  if (!existsSync(templatePath)) {
    console.error(`  x Template not found: ${templatePath}`)
    process.exit(1)
  }

  const outputDir = flags.output ? resolve(ROOT, flags.output) : ROOT
  const template = readFileSync(templatePath, 'utf-8')

  for (const profile of selectedProfiles) {
    const buildPluginIds = filterBuildPluginsForProfile(selectedPluginIds, metadata, profile)
    const runtimePluginIds = profile.id === 'static' ? buildPluginIds : selectedPluginIds
    const staticProfileLock =
      profile.id === 'static' ? assertStaticProfileSelection(buildPluginIds, metadata) : null
    const rawDeps = depsForPluginIds(buildPluginIds, metadata, profile)
    const installReport = collectBackendInstallReport(rawDeps, fragments, backendProfile)
    const req = collectDockerRequirements(filterDepsByBackendProfile(rawDeps, backendProfile))
    const featureList = [...req.features].sort()

    console.log(`\n  Profile: ${profile.id} (${profile.displayName})`)
    console.log(`  ${profile.description}`)
    console.log(
      `  Build plugins (${buildPluginIds.length}): ${buildPluginIds.join(', ') || '(none)'}`
    )
    console.log(
      `  Runtime plugins (${runtimePluginIds.length}): ${runtimePluginIds.join(', ') || '(none)'}`
    )
    console.log(`  Features (${featureList.length}): ${featureList.join(', ') || '(none)'}`)
    console.log(`  apt: ${req.aptPackages.join(', ') || '(none)'}`)
    console.log(`  env: ${req.envVars.size} + ${req.extraEnv.size} extra vars`)
    console.log(
      `  buildArgs: ${req.buildArgs.size} (${[...req.buildArgs.keys()].join(', ') || 'none'})`
    )
    console.log(`  directories: ${req.directories.length}`)
    console.log(`  volumes: ${req.volumes.length}`)
    console.log(`  validation: ${req.validationCmds.length} commands`)
    console.log(`  Backend install profile: ${backendProfile}`)
    console.log('  Backend install routes:')
    for (const item of installReport) {
      const state = item.enabled ? 'enabled' : 'skipped'
      console.log(
        `    - ${item.feature}: ${item.route} (${item.installProfile}) ${state} [${item.plugins.join(', ')}]`
      )
    }

    const enabledFragments = [...fragments.entries()].filter(([f]) => req.features.has(f))
    console.log(`  Docker fragments (${enabledFragments.length}/${fragments.size}):`)
    for (const [feature, frag] of enabledFragments) {
      const parts = []
      if (frag.args) parts.push('args')
      if (frag.stage) parts.push('stage')
      if (frag.runtime) parts.push('runtime')
      console.log(`    + ${feature} (${frag.plugin}) [${parts.join(', ')}]`)
    }

    const activeSet = new Set(buildPluginIds)
    const pluginWorkerIds = discoverPluginWorkerDirs(activeSet)
    if (pluginWorkerIds.length > 0) {
      console.log(`  Plugin workers (${pluginWorkerIds.length}): ${pluginWorkerIds.join(', ')}`)
    }

    const pluginDataEntries = discoverPluginDataDirs(activeSet)
    if (pluginDataEntries.length > 0) {
      console.log(
        `  Plugin data: ${pluginDataEntries.map((e) => `${e.plugin} (${e.files.join(', ')})`).join('; ')}`
      )
    }

    const pluginScriptIds = discoverPluginScriptDirs(activeSet)
    if (pluginScriptIds.length > 0) {
      console.log(`  Plugin scripts (${pluginScriptIds.length}): ${pluginScriptIds.join(', ')}`)
    }

    if (flags['dry-run']) continue

    if (staticProfileLock) {
      const lockPath = join(outputDir, STATIC_PROFILE_LOCK_FILE)
      mkdirSync(dirname(lockPath), { recursive: true })
      writeFileSync(lockPath, `${JSON.stringify(staticProfileLock, null, 2)}\n`, 'utf-8')
      console.log(`  OK ${STATIC_PROFILE_LOCK_FILE} (${staticProfileLock.plugins.length} plugins)`)
    }

    const dockerfile = processTemplate(
      template,
      req,
      pluginWorkerIds,
      pluginDataEntries,
      pluginScriptIds,
      fragments,
      profile,
      staticProfileLock
    )
    const dockerfilePath = join(outputDir, profile.dockerfile)
    mkdirSync(dirname(dockerfilePath), { recursive: true })
    writeFileSync(dockerfilePath, dockerfile, 'utf-8')
    console.log(`  OK ${profile.dockerfile} (${dockerfile.split('\n').length} lines)`)

    const compose = generateDockerCompose(
      req,
      buildPluginIds,
      runtimePluginIds,
      profile,
      backendProfile,
      staticProfileLock
    )
    const composePath = join(outputDir, profile.composeFile)
    mkdirSync(dirname(composePath), { recursive: true })
    writeFileSync(composePath, compose, 'utf-8')
    console.log(`  OK ${profile.composeFile} (${compose.split('\n').length} lines)`)
  }

  if (flags['dry-run']) console.log('\n  [dry-run] No files written.')
  console.log('--- Done ---\n')
}

main().catch((err) => {
  console.error('Fatal:', err)
  process.exit(1)
})
