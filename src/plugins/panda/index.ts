/**
 * PANDA Plugin
 *
 * PANDA record/replay analysis for dynamic binary inspection.
 */

import type { Plugin } from '../sdk.js'
import { pandaInspectToolDefinition, createPandaInspectHandler } from './tools/panda-inspect.js'

const pandaPlugin: Plugin = {
  id: 'panda',
  name: 'PANDA',
  executionDomain: 'dynamic',
  aspects: {
    formats: ['pe', 'elf', 'macho', 'firmware', 'memory-image'],
    platforms: ['windows', 'linux', 'macos', 'embedded'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['dynamic', 'record-replay'],
    runtimes: ['panda', 'pandare', 'qemu'],
    safety: ['opt_in_dynamic', 'requires_isolation', 'no_live_sample_by_default'],
    capabilities: ['record-replay', 'taint-analysis', 'dynamic-tracing', 'runtime-inspection'],
    evidence: ['process', 'memory', 'trace', 'timeline', 'provenance'],
  },
  surfaceRules: { tier: 3, category: 'dynamic-analysis' },
  description: 'PANDA record/replay analysis for dynamic binary inspection',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'PANDA_PYTHON',
      description: 'Python binary with PANDA installed',
      required: false,
      defaultValue: '/usr/local/bin/python3',
    },
  ],
  systemDeps: [
    {
      type: 'python',
      name: 'pandare',
      importName: 'pandare',
      required: false,
      description: 'PANDA record/replay analysis',
      dockerInstall: 'pip install pandare',
      dockerFeature: 'dynamic-python',
      extraEnv: { PANDA_PYTHON: '/usr/local/bin/python3' },
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(pandaInspectToolDefinition, createPandaInspectHandler(wm, db))
    return ['panda.inspect']
  },
}

export default pandaPlugin
