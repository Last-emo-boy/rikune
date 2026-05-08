#!/usr/bin/env node
/**
 * Plugin template scaffolding.
 *
 * Usage:
 *   node scripts/create-plugin.js <plugin-id> [--name "Display Name"]
 *
 * Example:
 *   node scripts/create-plugin.js memory-forensics --name "Memory Forensics"
 */

import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(__dirname, '..')
const pluginsDir = process.env.RIKUNE_PLUGIN_OUTPUT_DIR
  ? path.resolve(process.env.RIKUNE_PLUGIN_OUTPUT_DIR)
  : path.join(projectRoot, 'plugins')

function kebabToTitle(s) {
  return s
    .split('-')
    .map((w) => w[0].toUpperCase() + w.slice(1))
    .join(' ')
}

function kebabToCamel(s) {
  return s.replace(/-([a-z])/g, (_, c) => c.toUpperCase())
}

const args = process.argv.slice(2)
if (args.length === 0 || args[0] === '--help') {
  console.log('Usage: node scripts/create-plugin.js <plugin-id> [--name "Display Name"]')
  process.exit(0)
}

const pluginId = args[0]
const nameIdx = args.indexOf('--name')
const displayName = nameIdx >= 0 && args[nameIdx + 1] ? args[nameIdx + 1] : kebabToTitle(pluginId)
const camelId = kebabToCamel(pluginId)

if (!/^[a-z][a-z0-9-]*$/.test(pluginId)) {
  console.error('Error: plugin-id must be kebab-case, for example "my-plugin"')
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

const indexContent = `import { z } from 'zod'
import { definePlugin, defineTool, ok } from '@rikune/plugin-sdk'

const ${camelId}Plugin = definePlugin({
  id: ${JSON.stringify(pluginId)},
  name: ${JSON.stringify(displayName)},
  description: ${JSON.stringify(`${displayName} plugin tools and integration.`)},
  version: '0.1.0',
  executionDomain: 'static',
  surfaceRules: { tier: 3, category: 'static-analysis' },
  tools: [
    defineTool({
      name: ${JSON.stringify(`${pluginId}.hello`)},
      description: ${JSON.stringify(`${displayName} baseline scaffold tool.`)},
      inputSchema: z.object({
        sample_id: z.string().describe('Sample ID to analyze.'),
      }),
      handler: async (args: { sample_id: string }, _deps, ctx) =>
        ok({
          plugin: ${JSON.stringify(pluginId)},
          sample_id: args.sample_id,
          plugin_context: ctx?.pluginId ?? ${JSON.stringify(pluginId)},
          message: 'Replace scaffold output with a real implementation.',
        }),
    }),
  ],
})

export default ${camelId}Plugin
`

const manifestExample = {
  id: pluginId,
  name: displayName,
  description: `${displayName} plugin tools and integration.`,
  version: '0.1.0',
  executionDomain: 'static',
  surfaceRules: { tier: 3, category: 'static-analysis' },
  tools: [
    {
      name: `${pluginId}.hello`,
      description: `${displayName} baseline scaffold tool.`,
      inputSchema: {
        type: 'object',
        properties: {
          sample_id: { type: 'string', description: 'Sample ID to analyze.' },
        },
        required: ['sample_id'],
      },
    },
  ],
}

fs.writeFileSync(path.join(pluginDir, 'package.json'), `${JSON.stringify(packageJson, null, 2)}\n`)
fs.writeFileSync(path.join(pluginDir, 'tsconfig.json'), `${JSON.stringify(tsconfig, null, 2)}\n`)
fs.writeFileSync(path.join(srcDir, 'index.ts'), indexContent)
fs.writeFileSync(
  path.join(pluginDir, 'plugin.json.example'),
  `${JSON.stringify(manifestExample, null, 2)}\n`
)

console.log(`Created plugin scaffold at plugins/${pluginId}/`)
console.log(`  - plugins/${pluginId}/src/index.ts`)
console.log(`  - plugins/${pluginId}/package.json`)
console.log(`  - plugins/${pluginId}/tsconfig.json`)
console.log(`  - plugins/${pluginId}/plugin.json.example`)
console.log('\nNext steps:')
console.log(`  1. cd plugins/${pluginId}`)
console.log('  2. npm install')
console.log('  3. npm run build')
console.log('  4. Restart the server; compiled index.js is auto-discovered')
