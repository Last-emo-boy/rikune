import { spawn } from 'node:child_process'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const scriptDir = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(scriptDir, '..', '..')

const TEST_REQUIREMENTS = {
  'analysis-coverage-boundaries.integration.mjs': {
    tier: 'safe',
    note: 'Uses mocked workflow handlers plus temp SQLite/workspace state.',
  },
  'analysis-runtime-convergence.integration.mjs': {
    tier: 'safe',
    note: 'Uses mocked backends and temp SQLite/workspace state.',
  },
  'code-function-cfg.integration.mjs': {
    tier: 'safe',
    note: 'Uses in-memory database mocks and mocked render availability.',
  },
  'crypto-routing.integration.mjs': {
    tier: 'safe',
    note: 'Uses mocked handlers and temp SQLite/workspace state.',
  },
  'docker-full-stack-health.integration.mjs': {
    tier: 'safe',
    note: 'Mocks Docker-backed health probes; does not start Docker.',
  },
  'intent-driven-backend-routing.integration.mjs': {
    tier: 'safe',
    note: 'Uses mocked backend handlers and temp SQLite/workspace state.',
  },
  'large-sample-memory-aware-analysis-runtime.integration.mjs': {
    tier: 'safe',
    note: 'Uses persisted temp SQLite/workspace state only.',
  },
  'npm-docker-launcher.integration.mjs': {
    tier: 'safe',
    note: 'Runs CLI print-command paths only; does not invoke Docker.',
  },
  'packer-aware-unpack-and-debug-runtime.integration.mjs': {
    tier: 'safe',
    note: 'Uses persisted temp SQLite/workspace state only.',
  },
  'summary-coverage-boundaries.integration.mjs': {
    tier: 'safe',
    note: 'Uses mocked summary handlers and temp SQLite/workspace state.',
  },
  'worker-pool-and-budget-scheduler.integration.mjs': {
    tier: 'safe',
    note: 'Mocks worker creation and uses temp SQLite state.',
  },
}

const VALID_MODES = new Set(['safe', 'all', 'external', 'list'])

function parseArgs(argv) {
  const options = {
    mode: 'safe',
    grep: [],
  }

  for (const arg of argv) {
    if (arg === '--safe') {
      options.mode = 'safe'
    } else if (arg === '--all') {
      options.mode = 'all'
    } else if (arg === '--external') {
      options.mode = 'external'
    } else if (arg === '--list') {
      options.mode = 'list'
    } else if (arg.startsWith('--mode=')) {
      options.mode = arg.slice('--mode='.length)
    } else if (arg.startsWith('--grep=')) {
      options.grep.push(arg.slice('--grep='.length))
    } else {
      throw new Error(`Unknown argument: ${arg}`)
    }
  }

  if (!VALID_MODES.has(options.mode)) {
    throw new Error(`Invalid --mode value "${options.mode}". Expected one of: ${[...VALID_MODES].join(', ')}`)
  }

  return options
}

async function discoverTests() {
  const entries = await fs.readdir(scriptDir, { withFileTypes: true })
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.integration.mjs'))
    .map((entry) => entry.name)
    .sort()
}

function verifyManifest(discoveredTests) {
  const discovered = new Set(discoveredTests)
  const manifest = new Set(Object.keys(TEST_REQUIREMENTS))

  const unclassified = discoveredTests.filter((test) => !manifest.has(test))
  if (unclassified.length > 0) {
    throw new Error(
      [
        'Unclassified Node integration tests were found.',
        'Add each file to TEST_REQUIREMENTS as safe or external before running through CI:',
        ...unclassified.map((test) => `  - ${test}`),
      ].join('\n')
    )
  }

  const missing = [...manifest].filter((test) => !discovered.has(test))
  if (missing.length > 0) {
    throw new Error(
      [
        'TEST_REQUIREMENTS includes files that no longer exist:',
        ...missing.map((test) => `  - ${test}`),
      ].join('\n')
    )
  }
}

function matchesGrep(testName, grepTerms) {
  return grepTerms.length === 0 || grepTerms.some((term) => testName.includes(term))
}

function missingEnvironment(meta) {
  return (meta.requiresEnv || []).filter((name) => !process.env[name])
}

function classifyTests(testNames, options) {
  const runnable = []
  const skipped = []

  for (const testName of testNames) {
    if (!matchesGrep(testName, options.grep)) {
      continue
    }

    const meta = TEST_REQUIREMENTS[testName]
    if (options.mode === 'safe' && meta.tier !== 'safe') {
      skipped.push({
        testName,
        reason: `requires external dependencies: ${meta.note}`,
      })
      continue
    }

    if (options.mode === 'external' && meta.tier !== 'external') {
      skipped.push({
        testName,
        reason: 'safe test omitted by --external',
      })
      continue
    }

    const missingEnv = missingEnvironment(meta)
    if (missingEnv.length > 0) {
      skipped.push({
        testName,
        reason: `missing environment: ${missingEnv.join(', ')}`,
      })
      continue
    }

    runnable.push(testName)
  }

  return { runnable, skipped }
}

function printList(testNames) {
  for (const testName of testNames) {
    const meta = TEST_REQUIREMENTS[testName]
    const requirements = meta.requiresEnv?.length ? ` env=${meta.requiresEnv.join(',')}` : ''
    console.log(`${meta.tier.padEnd(8)} ${testName}${requirements} - ${meta.note}`)
  }
}

function runOne(testName, mode) {
  return new Promise((resolve) => {
    const startedAt = Date.now()
    const child = spawn(process.execPath, [path.join(scriptDir, testName)], {
      cwd: repoRoot,
      env: {
        ...process.env,
        RIKUNE_NODE_INTEGRATION_MODE: mode,
      },
      stdio: 'inherit',
    })

    child.on('close', (code, signal) => {
      resolve({
        testName,
        code,
        signal,
        durationMs: Date.now() - startedAt,
      })
    })
  })
}

async function main() {
  const options = parseArgs(process.argv.slice(2))
  const discoveredTests = await discoverTests()
  verifyManifest(discoveredTests)

  if (options.mode === 'list') {
    printList(discoveredTests)
    return
  }

  const { runnable, skipped } = classifyTests(discoveredTests, options)

  if (options.grep.length > 0 && runnable.length === 0 && skipped.length === 0) {
    throw new Error(`No Node integration tests matched --grep=${options.grep.join(',')}`)
  }

  console.log(`[node-integration] mode=${options.mode} runnable=${runnable.length} skipped=${skipped.length}`)
  for (const skip of skipped) {
    console.log(`[node-integration] SKIP ${skip.testName} - ${skip.reason}`)
  }

  const failures = []
  for (const testName of runnable) {
    console.log(`\n[node-integration] RUN ${testName}`)
    const result = await runOne(testName, options.mode)
    const seconds = (result.durationMs / 1000).toFixed(2)
    if (result.code === 0) {
      console.log(`[node-integration] PASS ${testName} (${seconds}s)`)
    } else {
      const status = result.signal ? `signal ${result.signal}` : `exit ${result.code}`
      console.error(`[node-integration] FAIL ${testName} (${status}, ${seconds}s)`)
      failures.push(result)
    }
  }

  console.log(
    `\n[node-integration] summary: passed=${runnable.length - failures.length} failed=${failures.length} skipped=${skipped.length}`
  )

  if (failures.length > 0) {
    process.exitCode = 1
  }
}

main().catch((error) => {
  console.error(`[node-integration] ${error.message}`)
  process.exitCode = 1
})
