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

import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from 'fs'
import { join, dirname, basename } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..')
const DEFAULT_DATA_ROOT = 'D:/Docker/rikune'
const DEFAULT_NO_PROXY = 'localhost,127.0.0.1,deb.debian.org,security.debian.org,mirrors.aliyun.com,archive.ubuntu.com,security.ubuntu.com,aliyuncs.com'

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
    description: 'Full Linux-side analysis stack. Runtime remains disabled until you opt into manual or remote-sandbox mode.',
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
    description: 'Static-only Linux analyzer. No runtime endpoint is configured and dynamic execution plugins are disabled.',
  },
  hybrid: {
    id: 'hybrid',
    displayName: 'Hybrid Docker analyzer + Windows runtime',
    composeName: 'rikune-hybrid',
    composeFile: 'docker-compose.hybrid.yml',
    dockerfile: 'docker/Dockerfile.analyzer',
    image: 'rikune-analyzer:latest',
    service: 'analyzer',
    container: 'rikune-analyzer',
    component: 'analyzer',
    nodeRole: 'analyzer',
    runtimeMode: 'remote-sandbox',
    buildDynamicDeps: false,
    description: 'Linux analyzer image with dynamic tools delegated to a Windows Host Agent / Runtime Node.',
  },
}

const EXECUTION_DOCKER_FEATURES = new Set(['dynamic-python', 'frida', 'gdb', 'qiling', 'wine'])

// -----------------------------------------------------------------------------
// 1. Auto-discover plugins from dist/plugins/ (or src/plugins/ for names)
// -----------------------------------------------------------------------------

function discoverPluginIds() {
  for (const base of [join(ROOT, 'dist', 'plugins'), join(ROOT, 'src', 'plugins')]) {
    if (!existsSync(base)) continue
    return readdirSync(base)
      .filter(name => {
        if (name === 'sdk.ts' || name === 'sdk.js' || name.startsWith('.')) return false
        const full = join(base, name)
        return statSync(full).isDirectory()
      })
      .sort()
  }
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
    .filter(name => {
      if (name === 'sdk.ts' || name.startsWith('.')) return false
      if (activePluginIds && !activePluginIds.has(name)) return false
      const workersDir = join(srcPlugins, name, 'workers')
      return existsSync(workersDir) && statSync(workersDir).isDirectory() &&
        readdirSync(workersDir).some(f => f.endsWith('.py'))
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
  for (const name of readdirSync(srcPlugins)) {
    if (name === 'sdk.ts' || name.startsWith('.')) continue
    if (activePluginIds && !activePluginIds.has(name)) continue
    const dataDir = join(srcPlugins, name, 'data')
    if (!existsSync(dataDir) || !statSync(dataDir).isDirectory()) continue
    const files = readdirSync(dataDir).filter(f => !f.startsWith('.'))
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

  for (const pluginName of readdirSync(srcPlugins)) {
    if (pluginName === 'sdk.ts' || pluginName.startsWith('.')) continue
    const dockerDir = join(srcPlugins, pluginName, 'docker')
    if (!existsSync(dockerDir) || !statSync(dockerDir).isDirectory()) continue

    for (const file of readdirSync(dockerDir)) {
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

// -----------------------------------------------------------------------------
// 2. Load systemDeps from compiled plugins
// -----------------------------------------------------------------------------

async function loadPluginMetadata(pluginIds) {
  const distDir = join(ROOT, 'dist', 'plugins')
  if (!existsSync(distDir)) {
    console.error('  x dist/plugins/ not found. Run `npm run build` first.')
    process.exit(1)
  }

  const result = new Map()
  let loaded = 0

  for (const id of pluginIds) {
    const indexPath = join(distDir, id, 'index.js')
    if (!existsSync(indexPath)) {
      result.set(id, { id, executionDomain: 'both', systemDeps: [] })
      continue
    }
    try {
      const mod = await import(`file://${indexPath.replace(/\\/g, '/')}`)
      const plugin = mod.default
      result.set(id, {
        id,
        executionDomain: plugin?.executionDomain ?? 'both',
        systemDeps: plugin?.systemDeps ?? [],
      })
      if (plugin?.systemDeps?.length > 0) loaded++
    } catch {
      result.set(id, { id, executionDomain: 'both', systemDeps: [] })
    }
  }

  console.log(`  Scanned ${pluginIds.length} plugins, ${loaded} have systemDeps`)
  return result
}

function depsForPluginIds(pluginIds, metadata, profile = PROFILES.full) {
  const result = new Map()
  for (const id of pluginIds) {
    const deps = metadata.get(id)?.systemDeps ?? []
    result.set(id, profile.buildDynamicDeps
      ? deps
      : deps.filter(dep => !EXECUTION_DOCKER_FEATURES.has(dep.dockerFeature)))
  }
  return result
}

function filterBuildPluginsForProfile(pluginIds, metadata, profile) {
  if (profile.buildDynamicDeps) return pluginIds
  return pluginIds.filter(id => metadata.get(id)?.executionDomain !== 'dynamic')
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
          if (!directories.some(x => x.path === d.path)) directories.push(d)
        }
      }
      if (dep.volumes) {
        for (const v of dep.volumes) {
          if (!volumes.some(x => x.target === v.target)) volumes.push(v)
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

function processTemplate(template, requirements, pluginWorkerIds, pluginDataEntries, fragments) {
  const { features, aptPackages, envVars, extraEnv, directories, validationCmds } = requirements

  // 4a. Conditional blocks (only dynamic-python remains in template)
  const lines = template.replace(/\r\n/g, '\n').split('\n')
  const output = []
  const stack = []
  let enabled = true

  for (const line of lines) {
    const ifMatch = line.match(/^[ \t]*# @if (.+)$/)
    const endifMatch = line.match(/^[ \t]*# @endif (.+)$/)
    if (ifMatch)    { stack.push(enabled); enabled = enabled && features.has(ifMatch[1].trim()); continue }
    if (endifMatch) { enabled = stack.pop() ?? true; continue }
    if (enabled) output.push(line)
  }

  let result = output.join('\n')

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
  const aptLines = aptPackages.length > 0
    ? aptPackages.map(p => `    ${p} \\`).join('\n') + '\n'
    : ''
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
    const envLines = entries.map(([k, v], i) =>
      i < entries.length - 1 ? `    ${k}=${v} \\` : `    ${k}=${v}`
    ).join('\n') + '\n'
    // Add trailing backslash to SANDBOX_PYTHON_PATH so ENV block continues
    result = result.replace(
      'SANDBOX_PYTHON_PATH=/usr/local/bin/python3\n{{RUNTIME_ENV_VARS}}',
      'SANDBOX_PYTHON_PATH=/usr/local/bin/python3 \\\n' + envLines
    )
  } else {
    result = result.replace('\n{{RUNTIME_ENV_VARS}}', '')
  }

  // 4g. {{VALIDATION_COMMANDS}}
  const allValidation = ['echo "[validate] Rikune Docker image"', ...validationCmds, 'echo "[validate] All checks passed"']
  result = result.replace('{{VALIDATION_COMMANDS}}', `RUN ${allValidation.join(' && \\\n    ')}`)

  // 4h. {{EXTRA_DIRS}} / {{EXTRA_CHOWN}} - from plugin systemDeps directories
  const extraDirs = directories.map(d => d.path)
  const extraChown = directories.filter(d => d.chown).map(d => `chown -R ${d.chown} ${d.path}`)
  result = result.replace('{{EXTRA_DIRS}}', extraDirs.join(' '))
  result = result.replace('{{EXTRA_CHOWN}}', extraChown.length > 0
    ? extraChown.map(c => `    ${c} && \\`).join('\n') + '\n' : '')

  // 4i. {{PLUGIN_WORKER_COPY}} / {{PLUGIN_WORKER_COPY_FROM}}
  if (pluginWorkerIds.length > 0) {
    const copyLines = pluginWorkerIds
      .map(id => `COPY src/plugins/${id}/workers/ ./src/plugins/${id}/workers/`)
      .join('\n')
    result = result.replace('{{PLUGIN_WORKER_COPY}}', copyLines)

    const copyFromLines = pluginWorkerIds
      .map(id => `COPY --from=python-base /app/src/plugins/${id}/workers/ ./src/plugins/${id}/workers/`)
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

  return result.replace(/\n{3,}/g, '\n\n')
}

// -----------------------------------------------------------------------------
// 5. Generate docker-compose.yml (all values from plugin systemDeps)
// -----------------------------------------------------------------------------

function makePluginsEnv(pluginIds) {
  return pluginIds.length > 0 ? pluginIds.join(',') : ''
}

function generateDockerCompose(requirements, buildPluginIds, runtimePluginIds, profile) {
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
  const buildArgsYaml = '\n' + [...allBuildArgs.entries()].sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `        ${k}: "${v}"`).join('\n')

  // Environment: base + plugin-declared
  const allEnv = new Map([
    ['NODE_ENV', 'production'], ['PYTHONUNBUFFERED', '1'],
    ['NODE_ROLE', profile.nodeRole], ['RUNTIME_MODE', profile.runtimeMode],
    ['PLUGINS', makePluginsEnv(runtimePluginIds)],
    ['WORKSPACE_ROOT', '/app/workspaces'], ['DB_PATH', '/app/data/database.db'],
    ['CACHE_ROOT', '/app/cache'], ['AUDIT_LOG_PATH', '/app/logs/audit.log'],
    ['XDG_CONFIG_HOME', '/app/logs/.config'], ['XDG_CACHE_HOME', '/app/cache/xdg'],
    ['LOG_LEVEL', 'info'], ['SANDBOX_PYTHON_PATH', '/usr/local/bin/python3'],
  ])
  for (const [k, v] of envVars) allEnv.set(k, v)
  for (const [k, v] of extraEnv) {
    if (k === 'JAVA_TOOL_OPTIONS' || k === 'JAVA_HOME') continue
    allEnv.set(k, v)
  }
  if (profile.id === 'hybrid') {
    allEnv.set('RUNTIME_HOST_AGENT_ENDPOINT', '${RUNTIME_HOST_AGENT_ENDPOINT:-}')
    allEnv.set('RUNTIME_HOST_AGENT_API_KEY', '${RUNTIME_HOST_AGENT_API_KEY:-}')
    allEnv.set('RUNTIME_API_KEY', '${RUNTIME_API_KEY:-}')
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
        target: /root/.rikune`

  const namedVol = `  root-config:\n    driver: local\n  storage:\n    driver: local`

  const featureList = [...features].sort().join(', ') || 'none'

  return `# =============================================================================
# Docker Compose - Rikune (${profile.id})
# =============================================================================
# Auto-generated from plugin systemDeps.
# Profile: ${profile.displayName}
# Build plugins: ${buildPluginIds.length} | Runtime plugins: ${runtimePluginIds.length}
# Features: ${featureList}
# Regenerate: npm run docker:generate -- --profile=${profile.id}
# =============================================================================

name: ${profile.composeName}

services:
  ${profile.service}:
    image: ${profile.image}
    build:
      context: .
      dockerfile: ${profile.dockerfile}
      args:${buildArgsYaml}
    container_name: ${profile.container}
    stdin_open: true
    tty: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=512m
    deploy:
      resources:
        limits:
          memory: 8G
          cpus: '2'
        reservations:
          memory: 2G
    volumes:
${volumeYaml}
    environment:
${envLines}
      # API File Server
      - API_ENABLED=true
      - API_PORT=18080
      # - API_KEY=your-secret-key-here
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
      - "18080:18080"
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
  --include=<ids>   Only include these plugins (comma-separated)
  --exclude=<ids>   Exclude these plugins
  --output=<dir>    Output directory (default: project root)
  --dry-run         Preview profile resolution without writing files
  --help            Show this help
`)
    process.exit(0)
  }

  console.log('--- Rikune Docker Generator ---')

  const selectedProfiles = flags['all-profiles']
    ? [PROFILES.full, PROFILES.static, PROFILES.hybrid]
    : [PROFILES[flags.profile || 'full']]
  if (selectedProfiles.some(p => !p)) {
    console.error(`  x Unknown profile '${flags.profile}'. Use full, static, or hybrid.`)
    process.exit(1)
  }

  const allPlugins = discoverPluginIds()
  console.log(`  Discovered ${allPlugins.length} plugins`)

  let selectedPluginIds = [...allPlugins]
  if (flags.include) {
    const include = new Set(flags.include.split(',').map(s => s.trim()))
    selectedPluginIds = selectedPluginIds.filter(id => include.has(id))
    console.log(`  --include: ${selectedPluginIds.length} selected`)
  }
  if (flags.exclude) {
    const exclude = new Set(flags.exclude.split(',').map(s => s.trim()))
    const before = selectedPluginIds.length
    selectedPluginIds = selectedPluginIds.filter(id => !exclude.has(id))
    console.log(`  --exclude: removed ${before - selectedPluginIds.length}`)
  }
  console.log(`  Runtime selection base (${selectedPluginIds.length}): ${selectedPluginIds.join(', ')}`)

  console.log('\n  Loading plugin metadata from dist/...')
  const metadata = await loadPluginMetadata(selectedPluginIds)
  const fragments = discoverDockerFragments()

  const templatePath = join(ROOT, 'docker', 'Dockerfile.template')
  if (!existsSync(templatePath)) {
    console.error(`  x Template not found: ${templatePath}`)
    process.exit(1)
  }

  const outputDir = flags.output ? join(ROOT, flags.output) : ROOT
  const template = readFileSync(templatePath, 'utf-8')

  for (const profile of selectedProfiles) {
    const buildPluginIds = filterBuildPluginsForProfile(selectedPluginIds, metadata, profile)
    const runtimePluginIds = profile.id === 'static' ? buildPluginIds : selectedPluginIds
    const req = collectDockerRequirements(depsForPluginIds(buildPluginIds, metadata, profile))
    const featureList = [...req.features].sort()

    console.log(`\n  Profile: ${profile.id} (${profile.displayName})`)
    console.log(`  ${profile.description}`)
    console.log(`  Build plugins (${buildPluginIds.length}): ${buildPluginIds.join(', ') || '(none)'}`)
    console.log(`  Runtime plugins (${runtimePluginIds.length}): ${runtimePluginIds.join(', ') || '(none)'}`)
    console.log(`  Features (${featureList.length}): ${featureList.join(', ') || '(none)'}`)
    console.log(`  apt: ${req.aptPackages.join(', ') || '(none)'}`)
    console.log(`  env: ${req.envVars.size} + ${req.extraEnv.size} extra vars`)
    console.log(`  buildArgs: ${req.buildArgs.size} (${[...req.buildArgs.keys()].join(', ') || 'none'})`)
    console.log(`  directories: ${req.directories.length}`)
    console.log(`  volumes: ${req.volumes.length}`)
    console.log(`  validation: ${req.validationCmds.length} commands`)

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
      console.log(`  Plugin data: ${pluginDataEntries.map(e => `${e.plugin} (${e.files.join(', ')})`).join('; ')}`)
    }

    if (flags['dry-run']) continue

    const dockerfile = processTemplate(template, req, pluginWorkerIds, pluginDataEntries, fragments)
    writeFileSync(join(outputDir, profile.dockerfile), dockerfile, 'utf-8')
    console.log(`  OK ${profile.dockerfile} (${dockerfile.split('\n').length} lines)`)

    const compose = generateDockerCompose(req, buildPluginIds, runtimePluginIds, profile)
    writeFileSync(join(outputDir, profile.composeFile), compose, 'utf-8')
    console.log(`  OK ${profile.composeFile} (${compose.split('\n').length} lines)`)
  }

  if (flags['dry-run']) console.log('\n  [dry-run] No files written.')
  console.log('--- Done ---\n')
}

main().catch(err => { console.error('Fatal:', err); process.exit(1) })
