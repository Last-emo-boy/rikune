#!/usr/bin/env node
/**
 * Plugin template scaffolding.
 *
 * Usage:
 *   node scripts/create-plugin.js <plugin-id> [--name "Display Name"] [--template static|dynamic|format-adapter|manifest-only|runtime-gated]
 *
 * Example:
 *   node scripts/create-plugin.js memory-forensics --name "Memory Forensics"
 *   node scripts/create-plugin.js apk-static --template format-adapter
 *   node scripts/create-plugin.js sandbox-plan --template runtime-gated
 */

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(__dirname, '..')
const pluginsDir = process.env.RIKUNE_PLUGIN_OUTPUT_DIR
  ? path.resolve(process.env.RIKUNE_PLUGIN_OUTPUT_DIR)
  : path.join(projectRoot, 'plugins')

const SUPPORTED_TEMPLATES = new Set([
  'static',
  'dynamic',
  'format-adapter',
  'manifest-only',
  'runtime-gated',
])

function kebabToTitle(s) {
  return s
    .split('-')
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(' ')
}

function kebabToCamel(s) {
  return s.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
}

function optionValue(args, longName, shortName) {
  const longIndex = args.indexOf(longName)
  if (longIndex >= 0 && args[longIndex + 1]) return args[longIndex + 1]
  if (shortName) {
    const shortIndex = args.indexOf(shortName)
    if (shortIndex >= 0 && args[shortIndex + 1]) return args[shortIndex + 1]
  }
  return undefined
}

function usage() {
  console.log(
    'Usage: node scripts/create-plugin.js <plugin-id> [--name "Display Name"] [--template static|dynamic|format-adapter|manifest-only|runtime-gated]'
  )
}

const args = process.argv.slice(2)
if (args.length === 0 || args[0] === '--help') {
  usage()
  process.exit(0)
}

const pluginId = args[0]
const displayName = optionValue(args, '--name') ?? kebabToTitle(pluginId)
const template = optionValue(args, '--template', '-t') ?? 'static'
const camelId = kebabToCamel(pluginId)

if (!/^[a-z][a-z0-9-]*$/.test(pluginId)) {
  console.error('Error: plugin-id must be kebab-case, for example "my-plugin"')
  process.exit(1)
}

if (!SUPPORTED_TEMPLATES.has(template)) {
  console.error(`Error: unsupported template "${template}"`)
  usage()
  process.exit(1)
}

const pluginDir = path.join(pluginsDir, pluginId)
const srcDir = path.join(pluginDir, 'src')

if (fs.existsSync(pluginDir)) {
  console.error(`Error: plugin directory already exists: ${pluginDir}`)
  process.exit(1)
}

fs.mkdirSync(srcDir, { recursive: true })

const packageJson = {
  name: `rikune-plugin-${pluginId}`,
  version: '0.1.0',
  private: true,
  type: 'module',
  main: './index.js',
  types: './index.d.ts',
  scripts: {
    build: 'tsc -p tsconfig.json',
    typecheck: 'tsc --noEmit -p tsconfig.json',
  },
  dependencies: {
    '@rikune/plugin-sdk': '1.0.0-beta.3',
    zod: '^3.25.76',
  },
  devDependencies: {
    '@types/node': '^25.3.5',
    typescript: '^5.9.3',
  },
}

const tsconfig = {
  compilerOptions: {
    target: 'ES2022',
    module: 'Node16',
    moduleResolution: 'Node16',
    strict: true,
    esModuleInterop: true,
    skipLibCheck: true,
    declaration: true,
    rootDir: './src',
    outDir: '.',
  },
  include: ['src/**/*.ts'],
  exclude: ['node_modules', 'index.js', 'index.d.ts'],
}

function templateDefaults() {
  if (template === 'dynamic' || template === 'runtime-gated') {
    return {
      executionDomain: 'dynamic',
      toolName: `${pluginId}.plan`,
      category: 'dynamic-analysis',
      aspects: {
        formats: ['pe', 'dll', 'dotnet', 'elf', 'so', 'macho', 'ipa', 'apk', 'dex', 'wasm'],
        platforms: ['windows', 'linux', 'macos', 'ios', 'android', 'wasm'],
        execution: ['dynamic'],
        runtimes: [
          'windows-sandbox',
          'hyperv',
          'windows-host-agent',
          'wine',
          'speakeasy',
          'qiling',
          'unicorn',
          'gdb',
          'strace',
          'ltrace',
          'lldb',
          'dtrace',
          'fs-usage',
          'sandbox-exec',
          'adb',
          'android-emulator',
          'frida',
          'frida-server',
          'idevice-tools',
          'wasmtime',
          'docker',
        ],
        safety: [
          'passive',
          'opt_in_dynamic',
          'requires_isolation',
          'no_live_sample_by_default',
          'no_network_by_default',
        ],
        capabilities: ['readiness', 'behavior-plan', 'runtime-policy', 'trace-plan', 'hook-plan'],
        evidence: ['timeline', 'behavior', 'process', 'filesystem', 'network', 'memory', 'provenance'],
      },
      runtimePolicy: {
        passiveByDefault: true,
        requiresUserOptIn: true,
        requiresIsolation: true,
        allowedBackends: [
          'windows-sandbox',
          'hyperv',
          'windows-host-agent',
          'wine',
          'speakeasy',
          'qiling',
          'unicorn',
          'gdb',
          'strace',
          'ltrace',
          'lldb',
          'dtrace',
          'fs-usage',
          'sandbox-exec',
          'adb',
          'android-emulator',
          'frida',
          'frida-server',
          'idevice-tools',
          'wasmtime',
          'docker',
        ],
        maxRuntimeMs: 30000,
        networkPolicy: 'disabled',
        notes: [
          'Scaffolded dynamic tools return plans until an explicit runtime backend is wired.',
          'Windows examples: Windows Sandbox, Hyper-V, host-agent, Wine, Speakeasy.',
          'Linux examples: Qiling, Unicorn, gdb, strace, ltrace.',
          'macOS/iOS examples: LLDB, DTrace, fs_usage, sandbox-exec, Frida, idevice-tools.',
          'Android examples: ADB, emulator, Frida server.',
          'WASM example: wasmtime in plan-only or isolated runtime mode.',
        ],
      },
      runtime: {
        type: 'spawn',
        handler: `${pluginId}.runtime.plan`,
        modes: ['plan_only', 'safe_simulation', 'emulation', 'manual_runtime'],
        capabilities: ['readiness', 'behavior-plan', 'runtime-policy', 'trace-plan', 'hook-plan'],
        safety: [
          'passive',
          'opt_in_dynamic',
          'requires_isolation',
          'no_live_sample_by_default',
          'no_network_by_default',
        ],
        isolation: {
          required: true,
          backends: [
            'windows-sandbox',
            'hyperv',
            'windows-host-agent',
            'wine',
            'speakeasy',
            'qiling',
            'unicorn',
            'gdb',
            'strace',
            'ltrace',
            'lldb',
            'dtrace',
            'fs-usage',
            'sandbox-exec',
            'adb',
            'android-emulator',
            'frida',
            'frida-server',
            'idevice-tools',
            'wasmtime',
            'docker',
          ],
          reason: 'Dynamic scaffold must run in an explicitly selected isolated backend.',
        },
        policy: {
          passiveByDefault: true,
          requiresUserOptIn: true,
          requiresIsolation: true,
          allowedBackends: [
            'windows-sandbox',
            'hyperv',
            'windows-host-agent',
            'wine',
            'speakeasy',
            'qiling',
            'unicorn',
            'gdb',
            'strace',
            'ltrace',
            'lldb',
            'dtrace',
            'fs-usage',
            'sandbox-exec',
            'adb',
            'android-emulator',
            'frida',
            'frida-server',
            'idevice-tools',
            'wasmtime',
            'docker',
          ],
          maxRuntimeMs: 30000,
          networkPolicy: 'disabled',
        },
        fallback: [
          {
            mode: 'plan_only',
            reason: 'Default scaffold fallback never starts live runtime backends.',
          },
        ],
      },
    }
  }

  if (template === 'format-adapter') {
    return {
      executionDomain: 'static',
      toolName: `${pluginId}.profile`,
      category: 'static-analysis',
      aspects: {
        formats: ['archive'],
        platforms: ['cross-platform'],
        execution: ['static', 'triage'],
        safety: ['passive'],
        capabilities: ['structure', 'routing'],
        evidence: ['structure', 'artifact', 'nested-binaries'],
      },
    }
  }

  return {
    executionDomain: 'static',
    toolName: `${pluginId}.analyze`,
    category: 'static-analysis',
    aspects: {
      formats: ['archive'],
      platforms: ['cross-platform'],
      execution: ['static'],
      safety: ['passive'],
      capabilities: ['structure'],
      evidence: ['artifact', 'provenance'],
    },
  }
}

const defaults = templateDefaults()
const artifacts = [
  {
    type: `${pluginId}.json`,
    description: `${displayName} JSON analysis output.`,
    mime: 'application/json',
  },
]
const evidence = [
  {
    category: defaults.executionDomain === 'dynamic' ? 'timeline' : 'structure',
    description: `${displayName} scaffold evidence metadata.`,
    artifactTypes: [`${pluginId}.json`],
  },
]
const outputSchema = {
  type: 'object',
  properties: {
    plugin: { type: 'string' },
    sample_id: { type: 'string' },
    mode: { type: 'string' },
    message: { type: 'string' },
  },
  required: ['plugin', 'sample_id', 'message'],
  additionalProperties: true,
}

const manifestExample = {
  id: pluginId,
  name: displayName,
  description: `${displayName} plugin tools and integration.`,
  version: '0.1.0',
  executionDomain: defaults.executionDomain,
  aspects: defaults.aspects,
  runtimePolicy: defaults.runtimePolicy,
  surfaceRules: {
    tier: defaults.executionDomain === 'dynamic' ? 3 : template === 'format-adapter' ? 1 : 3,
    category: defaults.category,
    activateOn:
      template === 'format-adapter'
        ? { fileTypes: defaults.aspects.formats }
        : undefined,
  },
  tools: [
    {
      name: defaults.toolName,
      description: `${displayName} scaffold tool.`,
      inputSchema: {
        type: 'object',
        properties: {
          sample_id: { type: 'string', description: 'Sample ID to analyze.' },
        },
        required: ['sample_id'],
      },
      outputSchema,
      aspects: defaults.aspects,
      artifacts,
      evidence,
      runtimePolicy: defaults.runtimePolicy,
      runtime: defaults.runtime,
      handler: defaults.toolName,
    },
  ],
}

function renderManifestOnlyIndex() {
  return `import { defineManifestPlugin, ok } from '@rikune/plugin-sdk'
import type { PluginManifest } from '@rikune/plugin-sdk'

const manifest: PluginManifest = ${JSON.stringify(manifestExample, null, 2)}

const ${camelId}Plugin = defineManifestPlugin(manifest, {
  ${JSON.stringify(defaults.toolName)}: async (args: { sample_id: string }) =>
    ok({
      plugin: ${JSON.stringify(pluginId)},
      sample_id: args.sample_id,
      mode: 'manifest-only',
      message: 'Replace scaffold output with a real implementation.',
    }),
})

export default ${camelId}Plugin
`
}

function renderCodeIndex() {
  const sdkImports =
    defaults.runtimePolicy || defaults.runtime
      ? `import type { DynamicRuntimePolicy, ToolRuntimeContract } from '@rikune/plugin-sdk'\n`
      : ''
  const runtimePolicyBlock = defaults.runtimePolicy
    ? `\nconst runtimePolicy: DynamicRuntimePolicy = ${JSON.stringify(defaults.runtimePolicy, null, 2)}\n`
    : ''
  const runtimeContractBlock = defaults.runtime
    ? `\nconst runtimeContract: ToolRuntimeContract = {
  ...${JSON.stringify({ ...defaults.runtime, policy: undefined }, null, 2)},
  policy: runtimePolicy,
}\n`
    : ''
  const runtimeLine = defaults.runtime
    ? `
      runtime: runtimeContract,`
    : ''
  const dynamicOptions =
    defaults.executionDomain === 'dynamic'
      ? `,
          mode: 'plan_only',
          message: 'This dynamic scaffold is passive by default. Wire a runtime backend before live execution.',
        },
        {
          evidence: [
            createEvidenceRef({
              id: \`${pluginId}:plan:\${args.sample_id}\`,
              category: 'timeline',
              source: ${JSON.stringify(pluginId)},
              toolName: ${JSON.stringify(defaults.toolName)},
              sampleId: args.sample_id,
              confidence: 1,
            }),
          ],
          execution_semantics: {
            requested_mode: 'plan_only',
            actual_mode: 'plan_only',
            live_execution: false,
            reason: 'Scaffold template is passive by default.',
          },
        }`
      : `,
          mode: 'static',
          message: 'Replace scaffold output with a real implementation.',
        },
        {
          evidence: [
            createEvidenceRef({
              id: \`${pluginId}:evidence:\${args.sample_id}\`,
              category: 'structure',
              source: ${JSON.stringify(pluginId)},
              toolName: ${JSON.stringify(defaults.toolName)},
              sampleId: args.sample_id,
              confidence: 1,
            }),
          ],
        }`

  return `import { z } from 'zod'
import { createEvidenceRef, definePlugin, defineTool, ok } from '@rikune/plugin-sdk'
${sdkImports}
${runtimePolicyBlock}
${runtimeContractBlock}
const ${camelId}Plugin = definePlugin({
  id: ${JSON.stringify(pluginId)},
  name: ${JSON.stringify(displayName)},
  description: ${JSON.stringify(`${displayName} plugin tools and integration.`)},
  version: '0.1.0',
  executionDomain: ${JSON.stringify(defaults.executionDomain)},
  aspects: ${JSON.stringify(defaults.aspects, null, 2)},
  runtimePolicy: ${defaults.runtimePolicy ? 'runtimePolicy' : 'undefined'},
  surfaceRules: ${JSON.stringify(manifestExample.surfaceRules, null, 2)},
  tools: [
    defineTool({
      name: ${JSON.stringify(defaults.toolName)},
      description: ${JSON.stringify(`${displayName} scaffold tool.`)},
      inputSchema: z.object({
        sample_id: z.string().describe('Sample ID to analyze.'),
      }),
      outputSchema: z.object({
        plugin: z.string(),
        sample_id: z.string(),
        mode: z.string().optional(),
        message: z.string(),
      }).passthrough(),
      aspects: ${JSON.stringify(defaults.aspects, null, 2)},
      artifacts: ${JSON.stringify(artifacts, null, 2)},
      evidence: ${JSON.stringify(evidence, null, 2)},
      runtimePolicy: ${defaults.runtimePolicy ? 'runtimePolicy' : 'undefined'},${runtimeLine}
      handler: async (args: { sample_id: string }) =>
        ok({
          plugin: ${JSON.stringify(pluginId)},
          sample_id: args.sample_id${dynamicOptions}
      ),
    }),
  ],
})

export default ${camelId}Plugin
`
}

const indexContent = template === 'manifest-only' ? renderManifestOnlyIndex() : renderCodeIndex()

fs.writeFileSync(path.join(pluginDir, 'package.json'), `${JSON.stringify(packageJson, null, 2)}\n`)
fs.writeFileSync(path.join(pluginDir, 'tsconfig.json'), `${JSON.stringify(tsconfig, null, 2)}\n`)
fs.writeFileSync(path.join(srcDir, 'index.ts'), indexContent)
fs.writeFileSync(
  path.join(pluginDir, 'plugin.json.example'),
  `${JSON.stringify(manifestExample, null, 2)}\n`
)

console.log(`Created ${template} plugin scaffold at plugins/${pluginId}/`)
console.log(`  - plugins/${pluginId}/src/index.ts`)
console.log(`  - plugins/${pluginId}/package.json`)
console.log(`  - plugins/${pluginId}/tsconfig.json`)
console.log(`  - plugins/${pluginId}/plugin.json.example`)
console.log('\nNext steps:')
console.log(`  1. cd plugins/${pluginId}`)
console.log('  2. npm install')
console.log('  3. npm run typecheck')
console.log('  4. npm run build')
console.log('  5. Restart the server; compiled index.js is auto-discovered')
