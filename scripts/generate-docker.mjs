#!/usr/bin/env node
// =============================================================================
// generate-docker.mjs — Plugin-driven Dockerfile & docker-compose generator
// =============================================================================
//
// Reads plugin systemDeps declarations from compiled dist/plugins/ and
// automatically derives the Docker image contents.  No hardcoded mappings —
// plugins are the single source of truth for their Docker requirements.
//
// Usage:
//   node scripts/generate-docker.mjs                         # all plugins
//   node scripts/generate-docker.mjs --exclude=ghidra,angr   # skip some
//   node scripts/generate-docker.mjs --include=pe-analysis,malware,frida
//   node scripts/generate-docker.mjs --dry-run               # preview only
//
// =============================================================================

import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..')

// ─────────────────────────────────────────────────────────────────────────────
// 1. Auto-discover plugins from dist/plugins/ (or src/plugins/ for names)
// ─────────────────────────────────────────────────────────────────────────────

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
  console.error('  ✗ Neither dist/plugins/ nor src/plugins/ found.')
  process.exit(1)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1b. Auto-discover plugins that have Python workers/ directories
// ─────────────────────────────────────────────────────────────────────────────

function discoverPluginWorkerDirs() {
  const srcPlugins = join(ROOT, 'src', 'plugins')
  if (!existsSync(srcPlugins)) return []
  return readdirSync(srcPlugins)
    .filter(name => {
      if (name === 'sdk.ts' || name.startsWith('.')) return false
      const workersDir = join(srcPlugins, name, 'workers')
      return existsSync(workersDir) && statSync(workersDir).isDirectory() &&
        readdirSync(workersDir).some(f => f.endsWith('.py'))
    })
    .sort()
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Load systemDeps from compiled plugins
// ─────────────────────────────────────────────────────────────────────────────

async function loadPluginDeps(pluginIds) {
  const distDir = join(ROOT, 'dist', 'plugins')
  if (!existsSync(distDir)) {
    console.error('  ✗ dist/plugins/ not found. Run `npm run build` first.')
    process.exit(1)
  }

  const result = new Map()
  let loaded = 0

  for (const id of pluginIds) {
    const indexPath = join(distDir, id, 'index.js')
    if (!existsSync(indexPath)) {
      result.set(id, [])
      continue
    }
    try {
      const mod = await import(`file://${indexPath.replace(/\\/g, '/')}`)
      const plugin = mod.default
      result.set(id, plugin?.systemDeps ?? [])
      if (plugin?.systemDeps?.length > 0) loaded++
    } catch {
      result.set(id, [])
    }
  }

  console.log(`  Scanned ${pluginIds.length} plugins, ${loaded} have systemDeps`)
  return result
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Collect Docker requirements from systemDeps (no hardcoded maps)
// ─────────────────────────────────────────────────────────────────────────────

function collectDockerRequirements(pluginDepMap) {
  const features = new Set()
  const aptPackages = new Set()
  const envVars = new Map()
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
    }
  }

  // Implied: frida/pandare/yara-x need dynamic-python deps
  if (features.has('frida') || features.has('dynamic-python')) {
    features.add('dynamic-python')
  }

  return { features, aptPackages: [...aptPackages].sort(), envVars, validationCmds }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Feature → structural Docker env/dirs
//    (infrastructure concerns tied to build stages, not individual deps)
// ─────────────────────────────────────────────────────────────────────────────

const FEATURE_EXTRA_ENV = {
  ghidra: { JAVA_HOME: '/opt/java/openjdk', JAVA_TOOL_OPTIONS: '""', GHIDRA_INSTALL_DIR: '/opt/ghidra', GHIDRA_PROJECT_ROOT: '/ghidra-projects', GHIDRA_LOG_ROOT: '/ghidra-logs' },
  capa:   { CAPA_PATH: '/usr/local/bin/capa', CAPA_RULES_PATH: '/opt/capa-rules', DIE_PATH: '/usr/bin/diec' },
  rizin:  { RIZIN_PATH: '/opt/rizin/bin/rizin' },
  retdec: { RETDEC_PATH: '/opt/retdec/bin/retdec-decompiler', RETDEC_INSTALL_DIR: '/opt/retdec' },
  upx:    { UPX_PATH: '/usr/local/bin/upx' },
  jadx:   { JADX_PATH: '/opt/jadx/bin/jadx' },
  vol3:   { VOLATILITY3_PATH: '/usr/local/bin/vol' },
  qiling: { QILING_PYTHON: '/opt/qiling-venv/bin/python', QILING_ROOTFS: '/opt/qiling-rootfs' },
  angr:   { ANGR_PYTHON: '/opt/angr-venv/bin/python' },
  'dynamic-python': { PANDA_PYTHON: '/usr/local/bin/python3', YARAX_PYTHON: '/usr/local/bin/python3' },
}

const FEATURE_DIRS = {
  ghidra: { dirs: ['/ghidra-projects', '/ghidra-logs'], chown: ['chown -R appuser:appuser /ghidra-projects', 'chown -R appuser:appuser /ghidra-logs'] },
  qiling: { dirs: ['/opt/qiling-rootfs'], chown: ['chown -R appuser:appuser /opt/qiling-rootfs'] },
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Process Dockerfile.template
// ─────────────────────────────────────────────────────────────────────────────

function processTemplate(template, requirements, pluginWorkerIds) {
  const { features, aptPackages, envVars, validationCmds } = requirements

  // 5a. Conditional blocks
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

  // 5b. {{RUNTIME_APT_PACKAGES}}
  const aptLines = aptPackages.length > 0
    ? aptPackages.map(p => `    ${p} \\`).join('\n') + '\n'
    : ''
  result = result.replace('{{RUNTIME_APT_PACKAGES}}', aptLines)

  // 5c. {{RUNTIME_ENV_VARS}}
  const allEnv = new Map(envVars)
  for (const [feat, vars] of Object.entries(FEATURE_EXTRA_ENV)) {
    if (features.has(feat)) for (const [k, v] of Object.entries(vars)) allEnv.set(k, v)
  }
  allEnv.delete('SANDBOX_PYTHON_PATH') // already in base block

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

  // 5d. {{VALIDATION_COMMANDS}}
  const allValidation = ['echo "[validate] Rikune Docker image"', ...validationCmds, 'echo "[validate] ✓ All checks passed"']
  result = result.replace('{{VALIDATION_COMMANDS}}', `RUN ${allValidation.join(' && \\\n    ')}`)

  // 5e. {{EXTRA_DIRS}} / {{EXTRA_CHOWN}}
  const extraDirs = [], extraChown = []
  for (const [feat, cfg] of Object.entries(FEATURE_DIRS)) {
    if (features.has(feat)) { extraDirs.push(...cfg.dirs); extraChown.push(...cfg.chown) }
  }
  result = result.replace('{{EXTRA_DIRS}}', extraDirs.join(' '))
  result = result.replace('{{EXTRA_CHOWN}}', extraChown.length > 0
    ? extraChown.map(c => `    ${c} && \\`).join('\n') + '\n' : '')

  // 5f. {{PLUGIN_WORKER_COPY}} / {{PLUGIN_WORKER_COPY_FROM}}
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

  return result.replace(/\n{3,}/g, '\n\n')
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Generate docker-compose.yml
// ─────────────────────────────────────────────────────────────────────────────

function generateDockerCompose(requirements, pluginIds) {
  const { features, envVars } = requirements

  const buildArgs = []
  if (features.has('capa'))   buildArgs.push('CAPA_RULES_VERSION: v9.3.1', 'CAPA_VERSION: "9.3.1"', 'DIE_VERSION: "3.10"', 'DIE_RELEASE_CHANNEL: "3.10"')
  if (features.has('upx'))    buildArgs.push('UPX_VERSION: "5.1.1"')
  if (features.has('rizin'))  buildArgs.push('RIZIN_VERSION: "0.8.2"')
  if (features.has('retdec')) buildArgs.push('RETDEC_VERSION: "5.0"')
  if (features.has('angr'))   buildArgs.push('ANGR_VERSION: "9.2.205"')
  if (features.has('jadx'))   buildArgs.push('JADX_VERSION: "1.5.1"')

  const allEnv = new Map([
    ['NODE_ENV', 'production'], ['PYTHONUNBUFFERED', '1'],
    ['WORKSPACE_ROOT', '/app/workspaces'], ['DB_PATH', '/app/data/database.db'],
    ['CACHE_ROOT', '/app/cache'], ['AUDIT_LOG_PATH', '/app/logs/audit.log'],
    ['XDG_CONFIG_HOME', '/app/logs/.config'], ['XDG_CACHE_HOME', '/app/cache/xdg'],
    ['LOG_LEVEL', 'info'], ['SANDBOX_PYTHON_PATH', '/usr/local/bin/python3'],
  ])
  for (const [k, v] of envVars) allEnv.set(k, v)
  for (const [feat, vars] of Object.entries(FEATURE_EXTRA_ENV)) {
    if (features.has(feat)) {
      for (const [k, v] of Object.entries(vars)) {
        if (k === 'JAVA_TOOL_OPTIONS' || k === 'JAVA_HOME') continue
        allEnv.set(k, v)
      }
    }
  }

  const envLines = [...allEnv.entries()].map(([k, v]) => `      - ${k}=${v}`).join('\n')
  const buildArgsYaml = buildArgs.length > 0
    ? '\n' + buildArgs.map(a => `        ${a}`).join('\n') : ''

  let volumeYaml = `      - ./samples:/samples:ro
      - "\${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/workspaces:/app/workspaces:rw"
      - "\${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/data:/app/data:rw"
      - "\${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/cache:/app/cache:rw"
      - "\${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/logs:/app/logs:rw"
      - "\${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/storage:/app/storage:rw"`
  if (features.has('ghidra')) volumeYaml += `
      - "\${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/ghidra-projects:/ghidra-projects:rw"
      - "\${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/ghidra-logs:/ghidra-logs:rw"`
  if (features.has('qiling')) volumeYaml += `
      - "\${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/qiling-rootfs:/opt/qiling-rootfs:ro"`
  volumeYaml += `
      - type: volume
        source: root-config
        target: /root/.rikune`

  let namedVol = `  root-config:\n    driver: local\n  storage:\n    driver: local`
  if (features.has('ghidra')) namedVol += `\n  ghidra-projects:\n    driver: local\n  ghidra-logs:\n    driver: local`

  const featureList = [...features].sort().join(', ') || 'none'

  return `# =============================================================================
# Docker Compose - Rikune
# =============================================================================
# Auto-generated from plugin systemDeps.
# Plugins: ${pluginIds.length} enabled | Features: ${featureList}
# Regenerate: npm run docker:generate
# =============================================================================

name: rikune

services:
  mcp-server:
    image: rikune:latest
    build:
      context: .
      dockerfile: Dockerfile
      args:${buildArgsYaml}
    container_name: rikune
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
      - "component=mcp-server"
      - "security.isolation=high"

volumes:
${namedVol}
`
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. CLI
// ─────────────────────────────────────────────────────────────────────────────

async function main() {
  const args = process.argv.slice(2)
  const flags = {}
  for (const arg of args) {
    const m = arg.match(/^--(\w[\w-]*)(?:=(.*))?$/)
    if (m) flags[m[1]] = m[2] ?? true
  }

  if (flags.help) {
    console.log(`
Rikune Docker Generator — builds Dockerfile + docker-compose.yml from plugin systemDeps

Plugins are the single source of truth.  The generator auto-discovers all
plugins, reads their systemDeps declarations, and derives the Docker image.

Usage:
  node scripts/generate-docker.mjs                         # all plugins
  node scripts/generate-docker.mjs --exclude=ghidra,angr   # skip heavy tools
  node scripts/generate-docker.mjs --include=pe-analysis,malware,frida
  node scripts/generate-docker.mjs --dry-run               # no file writes

Options:
  --include=<ids>    Only include these plugins (comma-separated)
  --exclude=<ids>    Exclude these plugins
  --output=<dir>     Output directory (default: project root)
  --dry-run          Preview features without writing files
  --help             Show this help
`)
    process.exit(0)
  }

  console.log('─── Rikune Docker Generator ───')

  const allPlugins = discoverPluginIds()
  console.log(`  Discovered ${allPlugins.length} plugins`)

  let pluginIds = [...allPlugins]
  if (flags.include) {
    const include = new Set(flags.include.split(',').map(s => s.trim()))
    pluginIds = pluginIds.filter(id => include.has(id))
    console.log(`  --include: ${pluginIds.length} selected`)
  }
  if (flags.exclude) {
    const exclude = new Set(flags.exclude.split(',').map(s => s.trim()))
    const before = pluginIds.length
    pluginIds = pluginIds.filter(id => !exclude.has(id))
    console.log(`  --exclude: removed ${before - pluginIds.length}`)
  }
  console.log(`  Active (${pluginIds.length}): ${pluginIds.join(', ')}`)

  console.log('\n  Loading systemDeps from dist/...')
  const pluginDepMap = await loadPluginDeps(pluginIds)

  const req = collectDockerRequirements(pluginDepMap)
  const featureList = [...req.features].sort()
  console.log(`\n  Features from plugins (${featureList.length}):`)
  for (const f of featureList) console.log(`    ✓ ${f}`)
  console.log(`  apt: ${req.aptPackages.join(', ') || '(none)'}`)
  console.log(`  env: ${req.envVars.size} vars`)
  console.log(`  validation: ${req.validationCmds.length} commands`)

  if (flags['dry-run']) {
    console.log('\n  [dry-run] No files written.')
    process.exit(0)
  }

  const templatePath = join(ROOT, 'docker', 'Dockerfile.template')
  if (!existsSync(templatePath)) {
    console.error(`  ✗ Template not found: ${templatePath}`)
    process.exit(1)
  }

  const pluginWorkerIds = discoverPluginWorkerDirs()
  if (pluginWorkerIds.length > 0) {
    console.log(`\n  Plugin workers (${pluginWorkerIds.length}): ${pluginWorkerIds.join(', ')}`)
  }

  const dockerfile = processTemplate(readFileSync(templatePath, 'utf-8'), req, pluginWorkerIds)
  const outputDir = flags.output ? join(ROOT, flags.output) : ROOT
  writeFileSync(join(outputDir, 'Dockerfile'), dockerfile, 'utf-8')
  console.log(`\n  ✓ Dockerfile (${dockerfile.split('\n').length} lines)`)

  const compose = generateDockerCompose(req, pluginIds)
  writeFileSync(join(outputDir, 'docker-compose.yml'), compose, 'utf-8')
  console.log(`  ✓ docker-compose.yml (${compose.split('\n').length} lines)`)

  console.log(`\n  ${pluginIds.length} plugins → ${featureList.length} features`)
  console.log('─── Done ───\n')
}

main().catch(err => { console.error('Fatal:', err); process.exit(1) })
