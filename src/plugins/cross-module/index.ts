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

const crossModulePlugin: Plugin = {
  id: 'cross-module',
  name: 'Cross-Module Analysis',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'elf', 'macho'],
    platforms: ['windows', 'linux', 'macos'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'correlation'],
    safety: ['passive'],
    capabilities: ['dependencies', 'call-graph', 'diffing', 'routing'],
    evidence: ['imports', 'exports', 'symbols', 'nested-binaries', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: { findings: ['suspicious_imports'] },
    category: 'reverse-engineering',
  },
  description: 'Cross-binary comparison, cross-module call graphs, and DLL dependency trees',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(crossBinaryCompareToolDefinition, createCrossBinaryCompareHandler(deps))
    server.registerTool(callGraphCrossModuleToolDefinition, createCallGraphCrossModuleHandler(deps))
    server.registerTool(dllDependencyTreeToolDefinition, createDllDependencyTreeHandler(deps))
    return ['cross.binary.compare', 'call.graph.cross.module', 'dll.dependency.tree']
  },
}

export default crossModulePlugin
