/**
 * Cross-Module Analysis Plugin
 *
 * Cross-binary comparison, cross-module call graphs, and DLL dependency trees.
 */

import type { Plugin } from '../sdk.js'
import {
  crossBinaryCompareToolDefinition,
  createCrossBinaryCompareHandler,
} from './tools/cross-binary-compare.js'
import {
  callGraphCrossModuleToolDefinition,
  createCallGraphCrossModuleHandler,
} from './tools/call-graph-cross-module.js'
import {
  dllDependencyTreeToolDefinition,
  createDllDependencyTreeHandler,
} from './tools/dll-dependency-tree.js'

const CROSS_MODULE_FORMATS = ['pe', 'dll', 'exe', 'elf', 'so', 'macho', 'dylib', 'native']
const CROSS_MODULE_PLATFORMS = ['windows', 'linux', 'macos', 'cross-platform']
const CROSS_MODULE_ARCHITECTURES = ['x86', 'x64', 'arm', 'arm64']
const CROSS_MODULE_SAFETY = [
  'passive',
  'no_network_by_default',
  'no_mutation',
  'no_live_sample_by_default',
  'no_sample_execution',
]
const CROSS_MODULE_CAPABILITIES = [
  'dependencies',
  'dependency-graph',
  'dependency-tree',
  'dll-dependency',
  'cross-module',
  'cross-module-call-graph',
  'call-graph',
  'diffing',
  'similarity',
  'lineage',
  'function-hashes',
  'imports',
  'exports',
  'symbols',
  'imports/exports/symbols/call-graph',
  'routing',
  'search-profile',
  'workflow-handoff',
  'metadata-only-handoff',
]
const CROSS_MODULE_EVIDENCE = [
  'imports',
  'exports',
  'symbols',
  'functions',
  'function-hashes',
  'strings',
  'dependency-graph',
  'call-graph',
  'dll-dependency',
  'similarity',
  'lineage',
  'sideload-risk',
  'nested-binaries',
  'workflow',
  'provenance',
]
const CROSS_MODULE_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  notes: [
    'Cross-module tools correlate existing static evidence and persisted sample metadata.',
    'The plugin must not load, link, execute, mutate, or fetch dependencies while building cross-module profiles.',
  ],
} as Plugin['runtimePolicy'] & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
}

const crossModulePlugin: Plugin = {
  id: 'cross-module',
  name: 'Cross-Module Analysis',
  executionDomain: 'static',
  aspects: {
    formats: CROSS_MODULE_FORMATS,
    platforms: CROSS_MODULE_PLATFORMS,
    architectures: CROSS_MODULE_ARCHITECTURES,
    execution: ['static', 'triage', 'correlation'],
    safety: CROSS_MODULE_SAFETY,
    capabilities: CROSS_MODULE_CAPABILITIES,
    evidence: CROSS_MODULE_EVIDENCE,
  },
  runtimePolicy: CROSS_MODULE_RUNTIME_POLICY,
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: ['pe', 'dll', 'exe', 'elf', 'so', 'macho', 'dylib', 'native'],
      findings: [
        'suspicious_imports',
        'dependency_graph',
        'dll_dependency',
        'cross_module',
        'call_graph',
      ],
    },
    signalMap: {
      suspicious_imports: 'suspicious_imports',
      imported_dlls: 'dll_dependency',
      dependency_graph: 'dependency_graph',
      cross_module: 'cross_module',
      call_graph: 'call_graph',
    },
    category: 'reverse-engineering',
  },
  description:
    'Cross-binary comparison, cross-module call graphs, dependency graph search, DLL dependency trees, and imports/exports/symbols/call graph handoff routing',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(crossBinaryCompareToolDefinition, createCrossBinaryCompareHandler(deps))
    server.registerTool(callGraphCrossModuleToolDefinition, createCallGraphCrossModuleHandler(deps))
    server.registerTool(dllDependencyTreeToolDefinition, createDllDependencyTreeHandler(deps))
    return ['cross.binary.compare', 'call.graph.cross.module', 'dll.dependency.tree']
  },
}

export default crossModulePlugin
