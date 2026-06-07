#!/usr/bin/env node
// Generate docs/tool-catalog.html from the current core and plugin tool registry.
// Run with: npm run docs:tool-catalog

import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dirname, '..')
const OUTPUT_PATH = resolve(ROOT, 'docs', 'tool-catalog.html')

function toFileUrl(...segments) {
  return pathToFileURL(resolve(ROOT, ...segments)).href
}

function unique(values) {
  return Array.from(
    new Set(values.filter((value) => typeof value === 'string' && value.length > 0))
  )
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function text(value, fallback = '') {
  return typeof value === 'string' && value.trim().length > 0 ? value.trim() : fallback
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function escapeScriptJson(value) {
  return value.replace(/&/g, '\\u0026').replace(/</g, '\\u003c').replace(/>/g, '\\u003e')
}

function normalizeDescription(value) {
  return text(value)
    .replace(/\s+/g, ' ')
    .replace(/\s+([,.])/g, '$1')
}

function inferCoreCategory(name) {
  if (name.startsWith('sample.')) return 'sample-intake'
  if (name.startsWith('artifact') || name.startsWith('artifacts.')) return 'artifact-management'
  if (name.startsWith('workflow.')) return 'workflow-orchestration'
  if (name.startsWith('task.')) return 'task-control'
  if (name.startsWith('system.') || name.startsWith('setup.')) return 'system-diagnostics'
  if (name.startsWith('tool.') || name.startsWith('tools.')) return 'tool-discovery'
  if (name.startsWith('plugin.')) return 'plugin-management'
  if (name.startsWith('llm.')) return 'llm-review'
  if (name.startsWith('analysis.')) return 'analysis-context'
  return 'core'
}

function inferPluginCategory(plugin, definition) {
  const surfaceCategory = plugin.surfaceRules?.category
  if (typeof surfaceCategory === 'string' && surfaceCategory.length > 0) return surfaceCategory
  const capabilities = [
    ...asArray(definition.aspects?.capabilities),
    ...asArray(plugin.aspects?.capabilities),
  ].join(' ')
  const execution = [
    ...asArray(definition.aspects?.execution),
    ...asArray(plugin.aspects?.execution),
  ].join(' ')
  const haystack = `${plugin.id} ${definition.name} ${capabilities} ${execution}`.toLowerCase()

  if (haystack.includes('android') || haystack.includes('apk') || haystack.includes('dex')) {
    return 'android-analysis'
  }
  if (haystack.includes('dotnet') || haystack.includes('clr') || haystack.includes('il')) {
    return 'dotnet-analysis'
  }
  if (haystack.includes('javascript') || haystack.includes('jsvmp') || haystack.includes('jsir')) {
    return 'javascript-deobfuscation'
  }
  if (
    haystack.includes('dynamic') ||
    haystack.includes('runtime') ||
    haystack.includes('sandbox')
  ) {
    return 'dynamic-analysis'
  }
  if (haystack.includes('memory') || haystack.includes('volatility')) return 'memory-forensics'
  if (haystack.includes('pcap') || haystack.includes('network')) return 'network-analysis'
  if (haystack.includes('malware') || haystack.includes('ioc') || haystack.includes('c2')) {
    return 'malware-analysis'
  }
  if (haystack.includes('vm') || haystack.includes('symbolic') || haystack.includes('smt')) {
    return 'symbolic-execution'
  }
  if (haystack.includes('firmware')) return 'firmware-analysis'
  if (haystack.includes('vuln') || haystack.includes('sbom')) return 'vulnerability-research'
  if (haystack.includes('unpack') || haystack.includes('packer')) return 'unpacking'
  return 'reverse-engineering'
}

function mergeAspects(pluginAspects, toolAspects) {
  const result = {}
  for (const source of [pluginAspects ?? {}, toolAspects ?? {}]) {
    for (const [key, value] of Object.entries(source)) {
      const values = asArray(value)
        .map((item) => String(item))
        .filter(Boolean)
      if (values.length > 0) result[key] = unique([...(result[key] ?? []), ...values])
    }
  }
  return result
}

function summarizeAspects(aspects) {
  const priority = [
    'formats',
    'platforms',
    'architectures',
    'execution',
    'capabilities',
    'evidence',
  ]
  const parts = []
  for (const key of priority) {
    const values = asArray(aspects[key]).slice(0, 5)
    if (values.length > 0) parts.push(`${key}: ${values.join(', ')}`)
  }
  return parts
}

function systemDepSummary(plugin) {
  return asArray(plugin.systemDeps).map((dep) => ({
    name: text(dep.name, text(dep.envVar, text(dep.target, 'dependency'))),
    type: text(dep.type, 'dependency'),
    required: Boolean(dep.required),
    envVar: text(dep.envVar),
    dockerFeature: text(dep.dockerFeature),
    dockerInstallProfile: text(dep.dockerInstallProfile),
    dockerInstallRoute: text(dep.dockerInstallRoute),
  }))
}

function toolMetadata(source, plugin, definition) {
  const aspects = mergeAspects(plugin?.aspects, definition.aspects)
  const runtime = definition.runtime ?? null
  const workerBackend = definition.workerBackend ?? null
  const runtimePolicy = definition.runtimePolicy ?? plugin?.runtimePolicy ?? null
  const category =
    source === 'core' ? inferCoreCategory(definition.name) : inferPluginCategory(plugin, definition)
  return {
    source,
    pluginId: plugin?.id ?? 'core',
    pluginName: plugin?.name ?? 'Core Tools',
    pluginDescription: normalizeDescription(plugin?.description ?? ''),
    pluginVersion: plugin?.version ?? '',
    executionDomain: plugin?.executionDomain ?? 'core',
    category,
    tier: typeof plugin?.surfaceRules?.tier === 'number' ? plugin.surfaceRules.tier : null,
    name: definition.name,
    canonicalName: definition.canonicalName ?? definition.name,
    description: normalizeDescription(definition.description),
    aspects,
    aspectSummary: summarizeAspects(aspects),
    artifactTypes: asArray(definition.artifacts)
      .map((artifact) => text(artifact.type))
      .filter(Boolean),
    evidenceCategories: asArray(definition.evidence)
      .map((item) => text(item.category))
      .filter(Boolean),
    workflowRecipes: asArray(definition.workflowRecipes)
      .map((recipe) => text(recipe.id, text(recipe.title)))
      .filter(Boolean),
    runtimeBacked: Boolean(runtime || runtimePolicy || plugin?.executionDomain === 'dynamic'),
    runtimeMode: text(runtime?.mode, text(runtime?.executionMode, '')),
    workerBacked: Boolean(workerBackend),
    backendName: text(workerBackend?.backendName),
    backendKind: text(workerBackend?.backendKind),
    backendAvailability: text(workerBackend?.availability),
    backendAdapter: text(workerBackend?.adapter),
    backendInstallRoute: text(workerBackend?.packaging?.installRoute),
    backendInstallProfile: text(workerBackend?.packaging?.installProfile),
    backendDockerFeature: text(workerBackend?.packaging?.dockerFeature),
    safety: unique([
      ...asArray(aspects.safety),
      ...(runtimePolicy?.networkPolicy === 'disabled' ? ['no-network'] : []),
      ...(workerBackend?.policy?.noLiveExecution ? ['no-live-execution'] : []),
      ...(workerBackend?.policy?.requiresUserOptIn ? ['requires-opt-in'] : []),
    ]),
  }
}

function createRegistryServer() {
  const definitions = []
  return {
    definitions,
    registerTool(definition) {
      definitions.push(definition)
    },
    unregisterTool(name) {
      const index = definitions.findIndex((definition) => definition.name === name)
      if (index >= 0) definitions.splice(index, 1)
    },
    getToolDefinitions() {
      return [...definitions]
    },
    registerPrompt() {},
    getPromptDefinitions() {
      return []
    },
    registerResource() {},
    getClientCapabilities() {
      return undefined
    },
    getClientVersion() {
      return undefined
    },
    async createMessage() {
      throw new Error('Sampling is unavailable during documentation generation.')
    },
    setPluginManager() {},
  }
}

function createMockPluginDeps(server = null) {
  return {
    workspaceManager: {},
    database: {},
    policyGuard: {},
    cacheManager: {},
    jobQueue: {},
    storageManager: {},
    config: {
      workers: {
        static: { pythonPath: undefined },
      },
      runtime: { mode: 'disabled' },
      node: { role: 'analyzer' },
    },
    server,
    runtimeClient: null,
    sandboxDir: null,
    resolvePackagePath: (...segments) => resolve(ROOT, ...segments),
    resolvePrimarySamplePath: async () => ({ samplePath: '' }),
    persistStaticAnalysisJsonArtifact: async () => null,
    services: {
      workspace: {
        manager: {},
        database: {},
        storage: {},
      },
      platform: {
        cacheManager: {},
        jobQueue: {},
        logger: {},
        policyGuard: {},
        server,
      },
      runtime: {
        client: null,
        mode: 'disabled',
        sandboxDir: null,
        config: { mode: 'disabled' },
      },
      ghidra: {},
    },
  }
}

function createCoreDeps(server) {
  return {
    workspaceManager: {},
    database: {},
    policyGuard: {},
    cacheManager: {},
    jobQueue: {},
    storageManager: {},
    config: {
      api: { port: 18080 },
      runtime: { mode: 'disabled' },
      node: { role: 'analyzer' },
    },
    server,
    runtimeClient: null,
    sandboxDir: null,
  }
}

async function collectCoreTools() {
  const server = createRegistryServer()
  const deps = createCoreDeps(server)
  const [
    sampleTools,
    artifactTools,
    llmTools,
    workflowTools,
    taskTools,
    systemTools,
    utilityTools,
    pluginTools,
    diagnosticsTools,
  ] = await Promise.all([
    import(toFileUrl('src/core/tool-registry/sample-tools.ts')),
    import(toFileUrl('src/core/tool-registry/artifact-tools.ts')),
    import(toFileUrl('src/core/tool-registry/llm-tools.ts')),
    import(toFileUrl('src/core/tool-registry/workflow-tools.ts')),
    import(toFileUrl('src/core/tool-registry/task-tools.ts')),
    import(toFileUrl('src/core/tool-registry/system-tools.ts')),
    import(toFileUrl('src/core/tool-registry/utility-tools.ts')),
    import(toFileUrl('src/core/tool-registry/plugin-tools.ts')),
    import(toFileUrl('src/core/tool-registry/diagnostics-tools.ts')),
  ])

  sampleTools.registerSampleTools(server, deps)
  artifactTools.registerArtifactTools(server, deps)
  llmTools.registerLlmTools(server)
  workflowTools.registerWorkflowTools(server, deps)
  taskTools.registerTaskTools(server, deps)
  systemTools.registerSystemTools(server, deps)
  utilityTools.registerUtilityTools(server, { runtimeClient: null, runtimeMode: 'disabled' })
  pluginTools.registerPluginTools(server)
  diagnosticsTools.registerDiagnosticsTools(server)

  const seen = new Set()
  return server.getToolDefinitions().filter((definition) => {
    if (seen.has(definition.name)) return false
    seen.add(definition.name)
    return true
  })
}

async function collectPluginCatalog() {
  const [{ discoverBuiltInPlugins }, { createPluginTestHarness }] = await Promise.all([
    import(toFileUrl('src/core/plugin-system/discovery.ts')),
    import('@rikune/plugin-sdk'),
  ])
  const plugins = (await discoverBuiltInPlugins()).sort((a, b) => a.id.localeCompare(b.id))
  const errors = []
  const entries = []

  for (const plugin of plugins) {
    const harness = createPluginTestHarness({
      ctx: { pluginId: plugin.id },
      deps: createMockPluginDeps(),
    })
    harness.deps.server = harness.server
    harness.deps.services.platform.server = harness.server
    try {
      harness.registerPlugin(plugin)
      const definitions = harness.registeredTools.map((tool) => tool.definition)
      entries.push({
        id: plugin.id,
        name: plugin.name,
        description: normalizeDescription(plugin.description ?? ''),
        version: plugin.version ?? '',
        executionDomain: plugin.executionDomain ?? 'both',
        tier: typeof plugin.surfaceRules?.tier === 'number' ? plugin.surfaceRules.tier : null,
        category: plugin.surfaceRules?.category ?? '',
        aspects: plugin.aspects ?? {},
        systemDeps: systemDepSummary(plugin),
        tools: definitions.map((definition) => toolMetadata('plugin', plugin, definition)),
      })
    } catch (err) {
      errors.push({
        pluginId: plugin.id,
        message: err instanceof Error ? err.message : String(err),
      })
      entries.push({
        id: plugin.id,
        name: plugin.name,
        description: normalizeDescription(plugin.description ?? ''),
        version: plugin.version ?? '',
        executionDomain: plugin.executionDomain ?? 'both',
        tier: typeof plugin.surfaceRules?.tier === 'number' ? plugin.surfaceRules.tier : null,
        category: plugin.surfaceRules?.category ?? '',
        aspects: plugin.aspects ?? {},
        systemDeps: systemDepSummary(plugin),
        tools: [],
      })
    }
  }

  return { plugins: entries, errors }
}

function groupCounts(items, selector) {
  const counts = new Map()
  for (const item of items) {
    const key = selector(item) || 'other'
    counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return Array.from(counts.entries())
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name))
}

function renderBadges(values, limit = 8) {
  const shown = unique(values).slice(0, limit)
  if (shown.length === 0) return '<span class="tool-muted">none</span>'
  return shown.map((value) => `<span class="tool-badge">${escapeHtml(value)}</span>`).join('')
}

function renderNav(active = false) {
  return `
        <ul class="nav__links" id="navLinks">
          <li><a href="index.html#features" data-lang-en>Features</a><a href="index.html#features" data-lang-zh>功能特性</a></li>
          <li><a href="api-reference.html">API</a></li>
          <li><a href="usage.html" data-lang-en>Usage</a><a href="usage.html" data-lang-zh>使用指南</a></li>
          <li><a href="local-setup.html"><span data-lang-en>Local</span><span data-lang-zh>本地</span></a></li>
          <li><a href="docker.html">Docker</a></li>
          <li><a href="examples.html" data-lang-en>Examples</a><a href="examples.html" data-lang-zh>示例</a></li>
          <li><a href="plugins.html" data-lang-en>Plugins</a><a href="plugins.html" data-lang-zh>插件</a></li>
          <li><a href="tool-catalog.html"${active ? ' class="active"' : ''} data-lang-en>Tools</a><a href="tool-catalog.html"${active ? ' class="active"' : ''} data-lang-zh>工具</a></li>
          <li><a href="anti-obfuscation.html" data-lang-en>Anti-Obf</a><a href="anti-obfuscation.html" data-lang-zh>反混淆</a></li>
          <li><a href="faq.html">FAQ</a></li>
        </ul>`
}

function renderToolRow(tool) {
  const search = [
    tool.name,
    tool.description,
    tool.pluginId,
    tool.pluginName,
    tool.category,
    tool.executionDomain,
    ...Object.values(tool.aspects).flat(),
    ...tool.artifactTypes,
    ...tool.evidenceCategories,
    tool.backendName,
    tool.backendAdapter,
  ]
    .join(' ')
    .toLowerCase()

  return `
                    <article class="tool-row" data-tool-row data-search="${escapeHtml(search)}" data-category="${escapeHtml(tool.category)}" data-domain="${escapeHtml(tool.executionDomain)}" data-runtime="${tool.runtimeBacked ? 'yes' : 'no'}" data-worker="${tool.workerBacked ? 'yes' : 'no'}">
                      <div class="tool-row__head">
                        <code>${escapeHtml(tool.name)}</code>
                        <div class="tool-row__badges">
                          <span class="badge badge--blue">${escapeHtml(tool.category)}</span>
                          <span class="badge badge--purple">${escapeHtml(tool.executionDomain)}</span>
                          ${tool.runtimeBacked ? '<span class="badge badge--amber">runtime-aware</span>' : ''}
                          ${tool.workerBacked ? '<span class="badge badge--green">worker-backed</span>' : ''}
                        </div>
                      </div>
                      <p>${escapeHtml(tool.description || 'No description provided.')}</p>
                      <div class="tool-row__meta">
                        ${tool.backendName ? `<span><strong>Backend</strong> ${escapeHtml(tool.backendName)}${tool.backendKind ? ` (${escapeHtml(tool.backendKind)})` : ''}</span>` : ''}
                        ${tool.backendAdapter ? `<span><strong>Adapter</strong> <code>${escapeHtml(tool.backendAdapter)}</code></span>` : ''}
                        ${tool.backendInstallRoute ? `<span><strong>Install</strong> ${escapeHtml(tool.backendInstallRoute)}${tool.backendInstallProfile ? ` / ${escapeHtml(tool.backendInstallProfile)}` : ''}</span>` : ''}
                        ${tool.artifactTypes.length > 0 ? `<span><strong>Artifacts</strong> ${escapeHtml(tool.artifactTypes.slice(0, 4).join(', '))}</span>` : ''}
                      </div>
                      <div class="tool-tags">${renderBadges([...asArray(tool.aspects.formats), ...asArray(tool.aspects.capabilities), ...tool.safety], 10)}</div>
                    </article>`
}

function renderPluginSection(plugin) {
  const tools = plugin.tools
  const categories = unique(tools.map((tool) => tool.category))
  const deps = plugin.systemDeps
  const search = [
    plugin.id,
    plugin.name,
    plugin.description,
    plugin.executionDomain,
    plugin.category,
    ...categories,
    ...tools.flatMap((tool) => [
      tool.name,
      tool.description,
      tool.backendName,
      tool.backendAdapter,
    ]),
    ...deps.flatMap((dep) => [dep.name, dep.type, dep.envVar, dep.dockerFeature]),
  ]
    .join(' ')
    .toLowerCase()

  return `
              <section class="plugin-card" data-plugin-card data-search="${escapeHtml(search)}" data-domain="${escapeHtml(plugin.executionDomain)}">
                <button class="plugin-card__summary" type="button" data-plugin-toggle>
                  <span>
                    <code>${escapeHtml(plugin.id)}</code>
                    <strong>${escapeHtml(plugin.name)}</strong>
                  </span>
                  <span>${tools.length} tools</span>
                </button>
                <div class="plugin-card__body">
                  <p>${escapeHtml(plugin.description || 'No plugin description provided.')}</p>
                  <div class="tool-tags">
                    <span class="badge badge--purple">${escapeHtml(plugin.executionDomain)}</span>
                    ${plugin.tier === null ? '' : `<span class="badge badge--blue">tier ${plugin.tier}</span>`}
                    ${renderBadges(categories, 8)}
                  </div>
                  ${
                    deps.length > 0
                      ? `<div class="dependency-list"><strong>Declared deps</strong> ${deps
                          .map(
                            (dep) =>
                              `<span class="tool-badge">${escapeHtml(dep.name)}${dep.envVar ? ` / ${escapeHtml(dep.envVar)}` : ''}${dep.required ? ' / required' : ' / optional'}</span>`
                          )
                          .join('')}</div>`
                      : ''
                  }
                  <div class="tool-row-list">
                    ${tools.map((tool) => renderToolRow(tool)).join('\n')}
                  </div>
                </div>
              </section>`
}

function renderCoreSection(coreTools) {
  const groups = groupCounts(coreTools, (tool) => tool.category)
  return `
            <div class="tool-section-header">
              <h3>Core MCP Surface</h3>
              <p>Always-on MCP gateway, sample intake, artifact, workflow, task, diagnostic, plugin, and LLM helper tools.</p>
            </div>
            <div class="category-strip">
              ${groups.map((group) => `<span>${escapeHtml(group.name)} <strong>${group.count}</strong></span>`).join('')}
            </div>
            <div class="tool-row-list">
              ${coreTools.map((tool) => renderToolRow(tool)).join('\n')}
            </div>`
}

function renderHtml({ coreTools, plugins, errors }) {
  const pluginTools = plugins.flatMap((plugin) => plugin.tools)
  const allTools = [...coreTools, ...pluginTools]
  const runtimeTools = allTools.filter((tool) => tool.runtimeBacked).length
  const workerTools = allTools.filter((tool) => tool.workerBacked).length
  const domains = groupCounts(pluginTools, (tool) => tool.executionDomain)
  const categories = groupCounts(allTools, (tool) => tool.category)
  const generatedAt = new Date().toISOString()
  const catalogData = {
    generatedAt,
    counts: {
      coreTools: coreTools.length,
      builtInPlugins: plugins.length,
      pluginTools: pluginTools.length,
      totalTools: allTools.length,
      runtimeTools,
      workerTools,
      registrationErrors: errors.length,
    },
    categories,
    domains,
  }

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Tool Catalog — Rikune</title>
    <meta
      name="description"
      content="Searchable catalog of Rikune MCP core tools and built-in plugin tools."
    />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link
      href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@300;400;500;600;700;800;900&display=swap"
      rel="stylesheet"
    />
    <link rel="stylesheet" href="assets/style.css" />
    <style>
      .catalog-stats {
        display: grid;
        grid-template-columns: repeat(6, minmax(0, 1fr));
        gap: 12px;
        margin: 28px 0 16px;
      }
      .catalog-stat {
        border: 1px solid var(--border);
        border-radius: var(--radius-sm);
        background: rgba(255,255,255,.025);
        padding: 16px;
      }
      .catalog-stat strong {
        display: block;
        font-family: var(--mono);
        font-size: 1.45rem;
        color: var(--text);
        line-height: 1.2;
      }
      .catalog-stat span {
        color: var(--text-dim);
        font-size: .78rem;
      }
      .catalog-controls {
        position: sticky;
        top: 76px;
        z-index: 20;
        display: grid;
        grid-template-columns: 1.8fr 1fr 1fr auto auto;
        gap: 10px;
        margin: 24px 0 28px;
        padding: 12px;
        border: 1px solid var(--border);
        border-radius: var(--radius-sm);
        background: rgba(9,9,11,.9);
        backdrop-filter: blur(16px);
      }
      .catalog-controls input,
      .catalog-controls select {
        width: 100%;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: rgba(255,255,255,.04);
        color: var(--text);
        font: inherit;
        font-size: .85rem;
        padding: 10px 12px;
      }
      .catalog-controls label {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        color: var(--text-muted);
        font-size: .8rem;
        white-space: nowrap;
      }
      .catalog-controls input[type="checkbox"] {
        width: 16px;
        height: 16px;
        accent-color: var(--accent);
      }
      .catalog-note {
        border: 1px solid rgba(56,189,248,.18);
        border-radius: var(--radius-sm);
        background: rgba(56,189,248,.055);
        padding: 16px 18px;
        color: var(--text-muted);
        font-size: .9rem;
      }
      .category-strip {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin: 16px 0 24px;
      }
      .category-strip span,
      .tool-badge {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        border: 1px solid var(--border);
        border-radius: 999px;
        background: rgba(255,255,255,.035);
        color: var(--text-muted);
        padding: 4px 10px;
        font-size: .75rem;
      }
      .category-strip strong { color: var(--text); }
      .tool-section-header {
        margin: 36px 0 12px;
      }
      .tool-section-header h3 {
        margin: 0 0 8px;
        font-size: 1.2rem;
      }
      .tool-section-header p {
        color: var(--text-muted);
        margin: 0;
      }
      .plugin-grid {
        display: grid;
        gap: 14px;
      }
      .plugin-card {
        border: 1px solid var(--border);
        border-radius: var(--radius-sm);
        background: rgba(255,255,255,.02);
        overflow: hidden;
      }
      .plugin-card[hidden],
      .tool-row[hidden] { display: none; }
      .plugin-card__summary {
        width: 100%;
        display: flex;
        justify-content: space-between;
        align-items: center;
        gap: 16px;
        border: 0;
        border-bottom: 1px solid var(--border);
        background: rgba(255,255,255,.025);
        color: var(--text);
        cursor: pointer;
        padding: 14px 16px;
        text-align: left;
      }
      .plugin-card__summary span:first-child {
        display: flex;
        align-items: center;
        gap: 12px;
        min-width: 0;
      }
      .plugin-card__summary code,
      .tool-row__head code {
        color: var(--accent);
        font-family: var(--mono);
      }
      .plugin-card__summary strong {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }
      .plugin-card__body {
        padding: 16px;
      }
      .plugin-card.is-collapsed .plugin-card__body {
        display: none;
      }
      .plugin-card__body > p {
        color: var(--text-muted);
        margin: 0 0 12px;
      }
      .dependency-list {
        margin: 12px 0 4px;
        color: var(--text-muted);
        font-size: .82rem;
      }
      .dependency-list strong {
        color: var(--text);
        margin-right: 8px;
      }
      .tool-row-list {
        display: grid;
        gap: 10px;
        margin-top: 14px;
      }
      .tool-row {
        border: 1px solid var(--border);
        border-radius: 8px;
        background: rgba(12,12,15,.78);
        padding: 14px;
      }
      .tool-row__head {
        display: flex;
        align-items: flex-start;
        justify-content: space-between;
        gap: 12px;
        margin-bottom: 8px;
      }
      .tool-row__badges,
      .tool-tags {
        display: flex;
        flex-wrap: wrap;
        gap: 6px;
      }
      .tool-row p {
        color: var(--text-muted);
        font-size: .88rem;
        margin: 0 0 10px;
      }
      .tool-row__meta {
        display: flex;
        flex-wrap: wrap;
        gap: 8px 14px;
        color: var(--text-dim);
        font-size: .78rem;
        margin-bottom: 10px;
      }
      .tool-row__meta strong {
        color: var(--text-muted);
        margin-right: 4px;
      }
      .tool-muted {
        color: var(--text-dim);
        font-size: .78rem;
      }
      .catalog-empty {
        display: none;
        border: 1px solid var(--border);
        border-radius: var(--radius-sm);
        padding: 24px;
        color: var(--text-muted);
        text-align: center;
      }
      .catalog-empty.is-visible { display: block; }
      @media (max-width: 980px) {
        .catalog-stats { grid-template-columns: repeat(3, minmax(0, 1fr)); }
        .catalog-controls { grid-template-columns: 1fr 1fr; }
      }
      @media (max-width: 640px) {
        .catalog-stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        .catalog-controls { position: static; grid-template-columns: 1fr; }
        .tool-row__head,
        .plugin-card__summary { align-items: flex-start; flex-direction: column; }
      }
    </style>
  </head>
  <body>
    <div class="bg-grid"></div>
    <div class="bg-glow bg-glow--1"></div>
    <div class="bg-glow bg-glow--2"></div>
    <canvas id="particles"></canvas>

    <nav class="nav" id="nav">
      <div class="nav__inner">
        <a href="index.html" class="nav__logo"><span class="nav__logo-icon">R</span> Rikune</a>
${renderNav(true)}
        <div class="nav__right">
          <button class="lang-toggle" id="lang-toggle">中文</button>
          <a href="https://github.com/Last-emo-boy/rikune" class="nav__cta" target="_blank" rel="noopener">GitHub →</a>
        </div>
        <button class="nav__hamburger" id="hamburger" aria-label="Toggle menu"><span></span><span></span><span></span></button>
      </div>
    </nav>

    <div class="page-hero">
      <div class="container">
        <div class="breadcrumb"><a href="index.html">Rikune</a> / Tool Catalog</div>
        <h1><span data-lang-en>Tool Catalog</span><span data-lang-zh>工具目录</span></h1>
        <p>
          <span data-lang-en>Search the current MCP core tools and built-in plugin tools, including runtime-aware and worker-backed backend integrations.</span>
          <span data-lang-zh>检索当前 MCP core tools 和内置 plugin tools，包括 runtime-aware 与 worker-backed 后端接入。</span>
        </p>
      </div>
    </div>

    <div class="doc-layout">
      <aside class="doc-sidebar">
        <div class="doc-sidebar__title"><span data-lang-en>On this page</span><span data-lang-zh>本页目录</span></div>
        <a href="#overview">Overview</a>
        <a href="#core">Core Tools</a>
        <a href="#plugins">Plugin Tools</a>
        <a href="#maintenance">Maintenance</a>
      </aside>

      <main class="doc-main">
        <section id="overview" class="reveal">
          <h2><span data-lang-en>Overview</span><span data-lang-zh>概览</span></h2>
          <div class="catalog-stats">
            <div class="catalog-stat"><strong>${coreTools.length}</strong><span>core tools</span></div>
            <div class="catalog-stat"><strong>${plugins.length}</strong><span>built-in plugins</span></div>
            <div class="catalog-stat"><strong>${pluginTools.length}</strong><span>plugin tools</span></div>
            <div class="catalog-stat"><strong>${allTools.length}</strong><span>cataloged tools</span></div>
            <div class="catalog-stat"><strong>${runtimeTools}</strong><span>runtime-aware</span></div>
            <div class="catalog-stat"><strong>${workerTools}</strong><span>worker-backed</span></div>
          </div>
          <p class="catalog-note">
            This catalog is generated from tool definitions and plugin metadata. Rikune uses a minimal AI-facing gateway at runtime: begin with <code>workflow.search</code>, execute staged actions through <code>workflow.run</code>, and read full persisted payloads with <code>artifact.read</code>.
          </p>
          <p class="catalog-note">
            <code>workflow.search</code> is the default passive profile-search portal for hidden capabilities. Use <code>action=search</code> or <code>action=recommend</code> to receive ranked toolchains with <code>score</code>, <code>match_reasons</code>, <code>readiness_state</code>, <code>activation_plan</code>, <code>activation_command</code>, <code>why_hidden</code>, and backend profile hints. Use <code>workflow.search action=activate</code> only to expose selected tools; activation responses include <code>activation_audit</code> and must preserve <code>backend_execution_started=false</code>. <code>tools.discover</code> remains a hidden low-level compatibility portal.
          </p>
          <table class="doc-table">
            <thead>
              <tr><th>Portal concept</th><th>Release guard</th></tr>
            </thead>
            <tbody>
              <tr><td>Small startup surface</td><td>Hidden registered tools remain blocked by <code>ToolExecutor</code> until <code>workflow.search action=activate</code> exposes selected tools.</td></tr>
              <tr><td>Recommendation fields</td><td><code>score</code>, <code>match_reasons</code>, readiness state, activation command, and hidden-surface explanation are machine-readable.</td></tr>
              <tr><td>Backend profiles</td><td>Routes such as <code>installed</code>, <code>profile-gated</code>, <code>byo</code>, <code>sidecar</code>, and <code>validation-only</code> are metadata until an explicit worker/runtime path is approved.</td></tr>
              <tr><td>Safety policy</td><td>Discovery, help, readiness, plugin listing, catalog generation, and Docker dry-runs do not start external backends, sidecars, runtimes, solvers, or samples.</td></tr>
            </tbody>
          </table>
          <div class="category-strip">
            ${categories.map((group) => `<span>${escapeHtml(group.name)} <strong>${group.count}</strong></span>`).join('')}
          </div>
          <div class="catalog-controls" aria-label="Tool catalog filters">
            <input id="catalogSearch" type="search" placeholder="Search tool, plugin, backend, format, capability..." />
            <select id="categoryFilter">
              <option value="">All categories</option>
              ${categories.map((group) => `<option value="${escapeHtml(group.name)}">${escapeHtml(group.name)} (${group.count})</option>`).join('')}
            </select>
            <select id="domainFilter">
              <option value="">All domains</option>
              <option value="core">core</option>
              ${domains.map((group) => `<option value="${escapeHtml(group.name)}">${escapeHtml(group.name)} (${group.count})</option>`).join('')}
            </select>
            <label><input id="runtimeOnly" type="checkbox" /> Runtime</label>
            <label><input id="workerOnly" type="checkbox" /> Worker</label>
          </div>
          <div class="catalog-empty" id="catalogEmpty">No tools match the current filters.</div>
        </section>

        <section id="core" class="reveal">
          <h2><span data-lang-en>Core Tools</span><span data-lang-zh>核心工具</span></h2>
          ${renderCoreSection(coreTools)}
        </section>

        <section id="plugins" class="reveal">
          <h2><span data-lang-en>Plugin Tools</span><span data-lang-zh>插件工具</span></h2>
          <div class="tool-section-header">
            <h3>Built-in Plugins</h3>
            <p>Grouped by plugin. Each row lists what the tool does, what domain it belongs to, and whether it has runtime or backend-worker metadata.</p>
          </div>
          <div class="plugin-grid">
            ${plugins.map((plugin) => renderPluginSection(plugin)).join('\n')}
          </div>
        </section>

        <section id="maintenance" class="reveal">
          <h2><span data-lang-en>Maintenance</span><span data-lang-zh>维护方式</span></h2>
          <p>
            Regenerate this page after adding, removing, or renaming plugins:
          </p>
          <div class="code-block">
            <div class="code-block__header"><span>Terminal</span><button class="code-block__copy">Copy</button></div>
            <pre>npm run docs:tool-catalog</pre>
          </div>
          <table class="doc-table">
            <thead>
              <tr><th>Field</th><th>Source</th></tr>
            </thead>
            <tbody>
              <tr><td><code>description</code></td><td>Tool <code>definition.description</code> and plugin <code>description</code></td></tr>
              <tr><td><code>category</code></td><td>Plugin <code>surfaceRules.category</code>, then catalog inference for uncategorized tools</td></tr>
              <tr><td><code>runtime-aware</code></td><td>Tool <code>runtime</code>, <code>runtimePolicy</code>, or dynamic plugin domain</td></tr>
              <tr><td><code>worker-backed</code></td><td>Tool <code>workerBackend</code> contract and packaging metadata</td></tr>
              <tr><td><code>dependencies</code></td><td>Plugin <code>systemDeps</code>, including Docker install profile where declared</td></tr>
            </tbody>
          </table>
          <script type="application/json" id="catalogMetadata">${escapeScriptJson(JSON.stringify(catalogData, null, 2))}</script>
        </section>
      </main>
    </div>

    <footer class="footer">
      <div class="container footer__inner">
        <div class="footer__brand"><span class="nav__logo-icon" style="width:24px;height:24px;font-size:.65rem;border-radius:6px;">R</span> Rikune</div>
        <ul class="footer__links">
          <li><a href="api-reference.html">API</a></li>
          <li><a href="local-setup.html"><span data-lang-en>Local</span><span data-lang-zh>本地</span></a></li>
          <li><a href="docker.html">Docker</a></li>
          <li><a href="faq.html">FAQ</a></li>
          <li><a href="examples.html"><span data-lang-en>Examples</span><span data-lang-zh>示例</span></a></li>
          <li><a href="plugins.html"><span data-lang-en>Plugins</span><span data-lang-zh>插件</span></a></li>
          <li><a href="tool-catalog.html"><span data-lang-en>Tools</span><span data-lang-zh>工具</span></a></li>
          <li><a href="anti-obfuscation.html"><span data-lang-en>Anti-Obf</span><span data-lang-zh>反混淆</span></a></li>
        </ul>
        <span class="footer__copy">MIT License · Built for the MCP ecosystem</span>
      </div>
    </footer>

    <script src="assets/main.js"></script>
    <script>
      (function () {
        const search = document.getElementById('catalogSearch');
        const category = document.getElementById('categoryFilter');
        const domain = document.getElementById('domainFilter');
        const runtimeOnly = document.getElementById('runtimeOnly');
        const workerOnly = document.getElementById('workerOnly');
        const empty = document.getElementById('catalogEmpty');
        const rows = Array.from(document.querySelectorAll('[data-tool-row]'));
        const plugins = Array.from(document.querySelectorAll('[data-plugin-card]'));

        function matches(row) {
          const query = search.value.trim().toLowerCase();
          if (query && !row.dataset.search.includes(query)) return false;
          if (category.value && row.dataset.category !== category.value) return false;
          if (domain.value && row.dataset.domain !== domain.value) return false;
          if (runtimeOnly.checked && row.dataset.runtime !== 'yes') return false;
          if (workerOnly.checked && row.dataset.worker !== 'yes') return false;
          return true;
        }

        function applyFilters() {
          let visibleRows = 0;
          rows.forEach((row) => {
            const visible = matches(row);
            row.hidden = !visible;
            if (visible) visibleRows += 1;
          });
          plugins.forEach((plugin) => {
            const visible = Array.from(plugin.querySelectorAll('[data-tool-row]')).some((row) => !row.hidden);
            plugin.hidden = !visible;
          });
          empty.classList.toggle('is-visible', visibleRows === 0);
        }

        [search, category, domain, runtimeOnly, workerOnly].forEach((control) => {
          control.addEventListener('input', applyFilters);
          control.addEventListener('change', applyFilters);
        });

        document.querySelectorAll('[data-plugin-toggle]').forEach((button) => {
          button.addEventListener('click', () => button.closest('[data-plugin-card]').classList.toggle('is-collapsed'));
        });

        applyFilters();
      })();
    </script>
  </body>
</html>
`
}

async function main() {
  const coreDefinitions = await collectCoreTools()
  const coreTools = coreDefinitions.map((definition) => toolMetadata('core', null, definition))
  const { plugins, errors } = await collectPluginCatalog()
  const html = renderHtml({ coreTools, plugins, errors })
  mkdirSync(dirname(OUTPUT_PATH), { recursive: true })
  writeFileSync(OUTPUT_PATH, html.replace(/[ \t]+(?=\r?\n)/g, ''), 'utf8')
  const pluginToolCount = plugins.reduce((sum, plugin) => sum + plugin.tools.length, 0)
  console.log(
    `Generated docs/tool-catalog.html (${coreTools.length} core tools, ${plugins.length} plugins, ${pluginToolCount} plugin tools, ${errors.length} registration errors).`
  )
  if (errors.length > 0) {
    for (const error of errors) {
      console.warn(`Plugin registration error: ${error.pluginId}: ${error.message}`)
    }
  }
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
