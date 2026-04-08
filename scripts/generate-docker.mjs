#!/usr/bin/env node
// =============================================================================
// generate-docker.mjs — Plugin-driven Dockerfile & docker-compose generator
// =============================================================================
//
// Reads plugin systemDeps declarations (from compiled dist/ or a static
// fallback map), resolves enabled Docker features from the selected plugin
// profile, and generates:
//   - Dockerfile              (from docker/Dockerfile.template)
//   - docker-compose.yml      (from docker-compose sections)
//
// Usage:
//   node scripts/generate-docker.mjs --profile=full
//   node scripts/generate-docker.mjs --profile=minimal
//   node scripts/generate-docker.mjs --plugins=ghidra,frida,malware
//   node scripts/generate-docker.mjs --profile=full --dry-run
//
// =============================================================================

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..')

// ─────────────────────────────────────────────────────────────────────────────
// 1. Dep name → Docker feature flag mapping
// ─────────────────────────────────────────────────────────────────────────────
// Maps systemDep.name → Docker "feature" that controls conditional blocks
// in Dockerfile.template.  Features correspond to `# @if <feature>` markers.

const DEP_NAME_TO_FEATURE = {
  'gdb':              'gdb',
  'frida':            'frida',
  'Ghidra':           'ghidra',
  'java':             'ghidra',        // Java JDK comes with the Ghidra stage
  'rizin':            'rizin',
  'dot (Graphviz)':   'graphviz',
  'upx':              'upx',
  'retdec':           'retdec',
  'angr':             'angr',
  'qiling':           'qiling',
  'wine':             'wine',
  'capa':             'capa',
  'vol3':             'vol3',
  'JADX':             'jadx',
  'pandare':          'pandare',
  'yara-x':           'yara-x',
  'yara-python':      'yara',
  'capa-rules':       'capa',
  'vol3-symbols':     null,            // optional dir, no separate feature
  // Python packages in base requirements — always available, no feature needed
  'python3':          null,
  'pefile':           null,
  'dnfile':           null,
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Static plugin → dep names fallback (used when dist/ is not available)
// ─────────────────────────────────────────────────────────────────────────────

const PLUGIN_DEP_NAMES_FALLBACK = {
  'android':          ['JADX'],
  'debug-session':    ['gdb'],
  'frida':            ['frida'],
  'ghidra':           ['Ghidra', 'java'],
  'docker-backends':  ['dot (Graphviz)', 'rizin', 'upx', 'retdec', 'angr', 'qiling', 'wine', 'pandare', 'yara-x'],
  'memory-forensics': ['vol3'],
  'dynamic':          ['frida'],
  'malware':          ['capa', 'yara-python', 'capa-rules'],
  'crackme':          ['angr'],
  'managed-sandbox':  ['python3'],
  'managed-il-xrefs': ['python3', 'dnfile'],
  'dotnet-reactor':   ['python3', 'dnfile'],
  'managed-fake-c2':  ['python3'],
  'host-correlation': ['python3', 'pefile'],
  // Pure TS plugins — no external deps
  'pe-analysis': [], 'strings': [], 'static-triage': [], 'code-analysis': [],
  'binary-diff': [], 'cross-module': [], 'elf-macho': [], 'kb-collaboration': [],
  'observability': [], 'reporting': [], 'sbom': [], 'threat-intel': [],
  'unpacking': [], 'visualization': [], 'vm-analysis': [], 'vuln-scanner': [],
  'batch': [],
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. Feature → runtime properties
// ─────────────────────────────────────────────────────────────────────────────

/** Extra apt packages to install per feature */
const FEATURE_APT = {
  gdb:        ['gdb', 'ltrace', 'strace'],
  graphviz:   ['graphviz'],
  wine:       ['wine', 'wine64'],
}

/** ENV vars to set per feature */
const FEATURE_ENV = {
  ghidra:   { JAVA_HOME: '/opt/java/openjdk', JAVA_TOOL_OPTIONS: '""', GHIDRA_INSTALL_DIR: '/opt/ghidra', GHIDRA_PROJECT_ROOT: '/ghidra-projects', GHIDRA_LOG_ROOT: '/ghidra-logs' },
  capa:     { CAPA_PATH: '/usr/local/bin/capa', CAPA_RULES_PATH: '/opt/capa-rules', DIE_PATH: '/usr/bin/diec' },
  graphviz: { GRAPHVIZ_DOT_PATH: '/usr/bin/dot' },
  rizin:    { RIZIN_PATH: '/opt/rizin/bin/rizin' },
  upx:      { UPX_PATH: '/usr/local/bin/upx' },
  wine:     { WINE_PATH: '/usr/bin/wine', WINEDBG_PATH: '/usr/bin/winedbg' },
  frida:    { FRIDA_PATH: '/usr/local/bin/frida' },
  qiling:   { QILING_PYTHON: '/opt/qiling-venv/bin/python', QILING_ROOTFS: '/opt/qiling-rootfs' },
  angr:     { ANGR_PYTHON: '/opt/angr-venv/bin/python' },
  retdec:   { RETDEC_PATH: '/opt/retdec/bin/retdec-decompiler', RETDEC_INSTALL_DIR: '/opt/retdec' },
  jadx:     { JADX_PATH: '/opt/jadx/bin/jadx' },
  pandare:  { PANDA_PYTHON: '/usr/local/bin/python3' },
  'yara-x': { YARAX_PYTHON: '/usr/local/bin/python3' },
  vol3:     { VOLATILITY3_PATH: '/usr/local/bin/vol' },
}

/** Validation commands per feature */
const FEATURE_VALIDATION = {
  capa:     ['/usr/local/bin/capa --version >/dev/null 2>&1', 'diec --version >/dev/null 2>&1'],
  graphviz: ['dot -V >/dev/null 2>&1'],
  rizin:    ['rizin -v >/dev/null 2>&1'],
  upx:      ['upx --version >/dev/null 2>&1'],
  wine:     ['wine --version >/dev/null 2>&1', 'command -v winedbg >/dev/null 2>&1'],
  frida:    ['frida-ps --help >/dev/null 2>&1'],
  retdec:   ['retdec-decompiler --help >/dev/null 2>&1', 'retdec-fileinfo --help >/dev/null 2>&1'],
  ghidra:   ['test -f /opt/ghidra/support/analyzeHeadless'],
  jadx:     ['jadx --version >/dev/null 2>&1'],
  qiling:   ['/opt/qiling-venv/bin/python -c "import qiling; print(\'✓ qiling\')"'],
  angr:     ['/opt/angr-venv/bin/python -c "import angr; print(\'✓ angr\')"'],
  vol3:     ['python3 -c "import volatility3; print(\'✓ volatility3\')"'],
  'dynamic-python': ['python3 -c "import frida, psutil; print(\'✓ dynamic imports\')"'],
}

/** Extra dirs to create per feature */
const FEATURE_DIRS = {
  ghidra: ['/ghidra-projects', '/ghidra-logs'],
  qiling: ['/opt/qiling-rootfs'],
}

/** Extra chown per feature */
const FEATURE_CHOWN = {
  ghidra: ['chown -R appuser:appuser /ghidra-projects', 'chown -R appuser:appuser /ghidra-logs'],
  qiling: ['chown -R appuser:appuser /opt/qiling-rootfs'],
}

// Implied features: if frida or pandare present, we need dynamic-python deps
const IMPLIED_FEATURES = {
  frida: ['dynamic-python'],
  pandare: ['dynamic-python'],
  'yara-x': ['dynamic-python'],
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Load plugin systemDeps (dynamic from dist/ or fallback)
// ─────────────────────────────────────────────────────────────────────────────

async function loadPluginDepNames(pluginIds) {
  const distDir = join(ROOT, 'dist', 'plugins')
  const result = new Map()

  // Try dynamic import from compiled plugins
  if (existsSync(distDir)) {
    let dynamicOk = 0
    for (const id of pluginIds) {
      const indexPath = join(distDir, id, 'index.js')
      if (!existsSync(indexPath)) {
        // Fallback for this plugin
        result.set(id, PLUGIN_DEP_NAMES_FALLBACK[id] || [])
        continue
      }
      try {
        const mod = await import(`file://${indexPath.replace(/\\/g, '/')}`)
        const plugin = mod.default
        if (plugin?.systemDeps?.length > 0) {
          result.set(id, plugin.systemDeps.map(d => d.name))
          dynamicOk++
        } else {
          result.set(id, [])
        }
      } catch {
        result.set(id, PLUGIN_DEP_NAMES_FALLBACK[id] || [])
      }
    }
    if (dynamicOk > 0) {
      console.log(`  Loaded systemDeps from ${dynamicOk} compiled plugins (dist/)`)
    }
  } else {
    console.log('  dist/ not found, using static fallback mapping')
    for (const id of pluginIds) {
      result.set(id, PLUGIN_DEP_NAMES_FALLBACK[id] || [])
    }
  }

  return result
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. Resolve features from plugins
// ─────────────────────────────────────────────────────────────────────────────

function resolveFeatures(pluginDepMap) {
  const features = new Set()

  for (const [, depNames] of pluginDepMap) {
    for (const depName of depNames) {
      const feature = DEP_NAME_TO_FEATURE[depName]
      if (feature) {
        features.add(feature)
        // Add implied features
        if (IMPLIED_FEATURES[feature]) {
          for (const implied of IMPLIED_FEATURES[feature]) features.add(implied)
        }
      } else if (feature === undefined) {
        console.warn(`  ⚠ Unknown dep name "${depName}" — no Docker feature mapped`)
      }
      // feature === null means deliberately no-op (always available)
    }
  }

  return features
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Process Dockerfile.template
// ─────────────────────────────────────────────────────────────────────────────

function processTemplate(template, features) {
  // 6a. Process conditional blocks: # @if feature ... # @endif feature
  const lines = template.replace(/\r\n/g, '\n').split('\n')
  const output = []
  const featureStack = []
  let enabled = true

  for (const line of lines) {
    const ifMatch = line.match(/^[ \t]*# @if (.+)$/)
    const endifMatch = line.match(/^[ \t]*# @endif (.+)$/)

    if (ifMatch) {
      featureStack.push(enabled)
      const requiredFeature = ifMatch[1].trim()
      enabled = enabled && features.has(requiredFeature)
      continue // don't emit the marker line
    } else if (endifMatch) {
      enabled = featureStack.pop() ?? true
      continue // don't emit the marker line
    }

    if (enabled) {
      output.push(line)
    }
  }

  let result = output.join('\n')

  // 6b. Replace {{RUNTIME_APT_PACKAGES}}
  const aptPkgs = []
  for (const [feature, pkgs] of Object.entries(FEATURE_APT)) {
    if (features.has(feature)) aptPkgs.push(...pkgs)
  }
  const aptLines = aptPkgs.length > 0
    ? aptPkgs.map(p => `    ${p} \\`).join('\n') + '\n'
    : ''
  result = result.replace('{{RUNTIME_APT_PACKAGES}}', aptLines)

  // 6c. Replace {{RUNTIME_ENV_VARS}}
  const envPairs = []
  for (const [feature, vars] of Object.entries(FEATURE_ENV)) {
    if (features.has(feature)) {
      for (const [k, v] of Object.entries(vars)) {
        envPairs.push([k, v])
      }
    }
  }
  const envLines = envPairs.length > 0
    ? envPairs.map(([k, v]) => `    ${k}=${v} \\`).join('\n') + '\n'
    : ''
  // Remove trailing backslash from last base ENV line if no feature envs
  if (envLines) {
    result = result.replace('{{RUNTIME_ENV_VARS}}', envLines)
  } else {
    // Remove the placeholder and fix the trailing backslash
    result = result.replace('\n{{RUNTIME_ENV_VARS}}', '')
  }

  // 6d. Replace {{VALIDATION_COMMANDS}}
  const validationCmds = ['echo "[validate] Rikune Docker build"']
  for (const [feature, cmds] of Object.entries(FEATURE_VALIDATION)) {
    if (features.has(feature)) validationCmds.push(...cmds)
  }
  validationCmds.push('echo "[validate] ✓ All checks passed"')
  const validationBlock = `RUN ${validationCmds.join(' && \\\n    ')}`
  result = result.replace('{{VALIDATION_COMMANDS}}', validationBlock)

  // 6e. Replace {{EXTRA_DIRS}}
  const extraDirs = []
  for (const [feature, dirs] of Object.entries(FEATURE_DIRS)) {
    if (features.has(feature)) extraDirs.push(...dirs)
  }
  result = result.replace('{{EXTRA_DIRS}}', extraDirs.join(' '))

  // 6f. Replace {{EXTRA_CHOWN}}
  const chownCmds = []
  for (const [feature, cmds] of Object.entries(FEATURE_CHOWN)) {
    if (features.has(feature)) chownCmds.push(...cmds)
  }
  const chownLines = chownCmds.length > 0
    ? chownCmds.map(c => `    ${c} && \\`).join('\n') + '\n'
    : ''
  result = result.replace('{{EXTRA_CHOWN}}', chownLines)

  // Clean up any double blank lines
  result = result.replace(/\n{3,}/g, '\n\n')

  return result
}

// ─────────────────────────────────────────────────────────────────────────────
// 7. Generate docker-compose.yml
// ─────────────────────────────────────────────────────────────────────────────

function generateDockerCompose(features, profileName) {
  const buildArgs = []
  if (features.has('capa'))   { buildArgs.push('CAPA_RULES_VERSION: v9.3.1', 'CAPA_VERSION: "9.3.1"', 'DIE_VERSION: "3.10"', 'DIE_RELEASE_CHANNEL: "3.10"') }
  if (features.has('upx'))    { buildArgs.push('UPX_VERSION: "5.1.1"') }
  if (features.has('rizin'))  { buildArgs.push('RIZIN_VERSION: "0.8.2"') }
  if (features.has('retdec')) { buildArgs.push('RETDEC_VERSION: "5.0"') }
  if (features.has('angr'))   { buildArgs.push('ANGR_VERSION: "9.2.205"') }
  if (features.has('jadx'))   { buildArgs.push('JADX_VERSION: "1.5.1"') }

  const envVars = [
    'NODE_ENV=production',
    'PYTHONUNBUFFERED=1',
    'WORKSPACE_ROOT=/app/workspaces',
    'DB_PATH=/app/data/database.db',
    'CACHE_ROOT=/app/cache',
    'AUDIT_LOG_PATH=/app/logs/audit.log',
    'XDG_CONFIG_HOME=/app/logs/.config',
    'XDG_CACHE_HOME=/app/cache/xdg',
    'LOG_LEVEL=info',
    'SANDBOX_PYTHON_PATH=/usr/local/bin/python3',
  ]

  for (const [feature, vars] of Object.entries(FEATURE_ENV)) {
    if (features.has(feature)) {
      for (const [k, v] of Object.entries(vars)) {
        // Skip JAVA_TOOL_OPTIONS empty string and JAVA_HOME (set in Dockerfile)
        if (k === 'JAVA_TOOL_OPTIONS' || k === 'JAVA_HOME') continue
        envVars.push(`${k}=${v}`)
      }
    }
  }

  // API config
  envVars.push(
    '', '# API File Server',
    'API_ENABLED=true',
    'API_PORT=18080',
    '# API_KEY=your-secret-key-here',
    'API_STORAGE_ROOT=/app/storage',
    'API_MAX_FILE_SIZE=524288000',
    'API_RETENTION_DAYS=30',
  )

  const volumes = [
    '# Sample files (read-only)',
    './samples:/samples:ro',
    '',
    '# Persistent data',
    '"${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/workspaces:/app/workspaces:rw"',
    '"${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/data:/app/data:rw"',
    '"${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/cache:/app/cache:rw"',
    '"${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/logs:/app/logs:rw"',
    '',
    '# API storage',
    '"${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/storage:/app/storage:rw"',
  ]

  const namedVolumes = ['root-config:', '  driver: local', 'storage:', '  driver: local']

  if (features.has('ghidra')) {
    volumes.push(
      '', '# Ghidra',
      '"${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/ghidra-projects:/ghidra-projects:rw"',
      '"${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/ghidra-logs:/ghidra-logs:rw"',
    )
    namedVolumes.push('ghidra-projects:', '  driver: local', 'ghidra-logs:', '  driver: local')
  }
  if (features.has('qiling')) {
    volumes.push(
      '', '# Qiling rootfs',
      '"${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/qiling-rootfs:/opt/qiling-rootfs:ro"',
    )
  }

  volumes.push(
    '',
    '# Root config',
    'type: volume',
    'source: root-config',
    'target: /root/.rikune',
  )

  // Assemble
  const buildArgsYaml = buildArgs.length > 0
    ? buildArgs.map(a => `        ${a}`).join('\n')
    : ''

  const envYaml = envVars
    .map(v => v === '' ? '' : v.startsWith('#') ? `      ${v}` : `      - ${v}`)
    .join('\n')

  let volumeYaml = ''
  for (const v of volumes) {
    if (v === '') { volumeYaml += '\n'; continue }
    if (v.startsWith('#')) { volumeYaml += `      ${v}\n`; continue }
    if (v.startsWith('type:')) {
      // Named volume mount (multi-line)
      volumeYaml += `      - ${v}\n`
      continue
    }
    if (v.startsWith('source:') || v.startsWith('target:')) {
      volumeYaml += `        ${v}\n`
      continue
    }
    volumeYaml += `      - ${v}\n`
  }

  const namedVolYaml = namedVolumes.map(v => `  ${v}`).join('\n')

  return `# =============================================================================
# Docker Compose - Rikune (profile: ${profileName})
# =============================================================================
# Generated by: npm run docker:generate -- --profile=${profileName}
# =============================================================================

name: rikune

services:
  mcp-server:
    image: rikune:latest
    build:
      context: .
      dockerfile: Dockerfile
      args:
${buildArgsYaml}
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
${envYaml}

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
      - "profile=${profileName}"

volumes:
${namedVolYaml}
`
}

// ─────────────────────────────────────────────────────────────────────────────
// 8. CLI
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
Rikune Docker Generator — builds Dockerfile + docker-compose.yml from plugin profiles

Usage:
  node scripts/generate-docker.mjs --profile=<name>
  node scripts/generate-docker.mjs --plugins=id1,id2,...
  node scripts/generate-docker.mjs --profile=full --dry-run

Options:
  --profile=<name>   Load profile from docker/profiles/<name>.json
  --plugins=<ids>    Comma-separated plugin IDs (overrides --profile)
  --output=<dir>     Output directory (default: project root)
  --dry-run          Print features without writing files
  --help             Show this help

Available profiles:
  full               All plugins, all tools (largest image)
  minimal            Core static analysis only (smallest)
  malware-analysis   Malware-focused stack
  dotnet-analysis    .NET reverse engineering

Profiles are defined in docker/profiles/*.json
`)
    process.exit(0)
  }

  console.log('─── Rikune Docker Generator ───')

  // Resolve plugin list
  let pluginIds = []
  let profileName = 'custom'

  if (flags.plugins) {
    pluginIds = flags.plugins.split(',').map(s => s.trim())
    profileName = 'custom'
    console.log(`  Plugin list: ${pluginIds.join(', ')}`)
  } else {
    profileName = flags.profile || 'full'
    const profilePath = join(ROOT, 'docker', 'profiles', `${profileName}.json`)
    if (!existsSync(profilePath)) {
      console.error(`  ✗ Profile not found: ${profilePath}`)
      console.error(`  Available: ${readdirSync(join(ROOT, 'docker', 'profiles')).filter(f => f.endsWith('.json')).map(f => f.replace('.json', '')).join(', ')}`)
      process.exit(1)
    }
    const profile = JSON.parse(readFileSync(profilePath, 'utf-8'))
    pluginIds = profile.plugins
    profileName = profile.name
    console.log(`  Profile: ${profileName} — ${profile.description}`)
    console.log(`  Plugins (${pluginIds.length}): ${pluginIds.join(', ')}`)
  }

  // Load dep names
  console.log('\n  Loading plugin dependencies...')
  const pluginDepMap = await loadPluginDepNames(pluginIds)

  // Resolve features
  const features = resolveFeatures(pluginDepMap)
  const featureList = [...features].sort()
  console.log(`\n  Enabled Docker features (${featureList.length}):`)
  for (const f of featureList) console.log(`    ✓ ${f}`)

  // Report what's NOT included
  const allFeatures = new Set(Object.values(DEP_NAME_TO_FEATURE).filter(Boolean))
  const disabled = [...allFeatures].filter(f => !features.has(f)).sort()
  if (disabled.length > 0) {
    console.log(`\n  Disabled features (${disabled.length}):`)
    for (const f of disabled) console.log(`    ○ ${f}`)
  }

  if (flags['dry-run']) {
    console.log('\n  [dry-run] No files written.')
    process.exit(0)
  }

  // Process template
  const templatePath = join(ROOT, 'docker', 'Dockerfile.template')
  if (!existsSync(templatePath)) {
    console.error(`  ✗ Template not found: ${templatePath}`)
    process.exit(1)
  }
  const template = readFileSync(templatePath, 'utf-8')
  const dockerfile = processTemplate(template, features)

  // Write outputs
  const outputDir = flags.output ? join(ROOT, flags.output) : ROOT
  const dockerfilePath = join(outputDir, 'Dockerfile')
  const composePath = join(outputDir, 'docker-compose.yml')

  writeFileSync(dockerfilePath, dockerfile, 'utf-8')
  console.log(`\n  ✓ Dockerfile written (${dockerfile.split('\n').length} lines)`)

  const compose = generateDockerCompose(features, profileName)
  writeFileSync(composePath, compose, 'utf-8')
  console.log(`  ✓ docker-compose.yml written (${compose.split('\n').length} lines)`)

  // Summary
  const fullLineCount = 465  // approximate original Dockerfile line count
  const ratio = Math.round((dockerfile.split('\n').length / fullLineCount) * 100)
  console.log(`\n  Profile "${profileName}": ${featureList.length} features, ~${ratio}% of full image`)
  console.log('─── Done ───\n')
}

main().catch(err => {
  console.error('Fatal:', err)
  process.exit(1)
})
