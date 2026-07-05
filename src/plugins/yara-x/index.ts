/**
 * YARA-X Plugin
 *
 * YARA-X next-gen pattern matching for malware detection.
 */

import type { Plugin } from '../sdk.js'
import { yaraXScanToolDefinition, createYaraXScanHandler } from './tools/yara-x-scan.js'

const YARA_X_SAFETY = [
  'passive',
  'external_static_backend',
  'no_live_sample_by_default',
  'no_live_execution',
  'no_network_by_default',
  'no_mutation',
]

const YARA_X_CAPABILITIES = [
  'signatures',
  'pattern-matching',
  'rule-matching',
  'ruleset-provenance',
  'default-rules-semantics',
  'rule-validation',
  'engine-comparison',
  'legacy-yara-comparison',
  'yara-x-corroboration',
  'workflow-handoff',
  'evidence-correlation',
]

const YARA_X_EVIDENCE = [
  'signatures',
  'strings',
  'ruleset',
  'rule-validation',
  'engine-comparison',
  'corroboration',
  'workflow',
  'provenance',
]

const YARA_X_RUNTIME_POLICY = {
  passiveByDefault: true,
  requiresUserOptIn: false,
  requiresIsolation: false,
  allowedBackends: ['local'],
  networkPolicy: 'disabled',
  noNetwork: true,
  noMutation: true,
  noLiveExecution: true,
  notes: [
    'YARA-X scanning reads local sample bytes and analyst-provided rules only.',
    'The plugin does not download rules, mutate samples, or execute live sample code.',
    'Legacy yara.scan comparison is a passive corroboration follow-up, not an automatic second scan.',
  ],
} as NonNullable<Plugin['runtimePolicy']> & {
  noNetwork: true
  noMutation: true
  noLiveExecution: true
}

const yaraXPlugin: Plugin = {
  id: 'yara-x',
  name: 'YARA-X',
  executionDomain: 'static',
  aspects: {
    formats: [
      'pe',
      'elf',
      'macho',
      'apk',
      'dex',
      'jar',
      'dotnet',
      'wasm',
      'firmware',
      'archive',
      'container',
    ],
    platforms: ['windows', 'linux', 'macos', 'android', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'triage'],
    safety: YARA_X_SAFETY,
    capabilities: YARA_X_CAPABILITIES,
    evidence: YARA_X_EVIDENCE,
    rulesets: ['yara-x', 'yara', 'ruleset', 'default-rules', 'inline-rules', 'file-rules'],
    provenance: ['ruleset-provenance', 'rules-digest', 'artifact-provenance'],
    comparison: ['yara-x-corroboration', 'legacy-yara-comparison', 'engine-comparison'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: { findings: ['packed', 'obfuscated'] },
    category: 'malware-analysis',
  },
  description:
    'YARA-X next-gen pattern matching for passive malware detection, ruleset provenance, rule validation, and legacy YARA engine comparison.',
  version: '1.0.0',
  runtimePolicy: YARA_X_RUNTIME_POLICY,
  configSchema: [
    {
      envVar: 'YARAX_PYTHON',
      description: 'Python binary with YARA-X installed',
      required: false,
      defaultValue: '/usr/local/bin/python3',
    },
  ],
  systemDeps: [
    {
      type: 'python',
      name: 'yara-x',
      importName: 'yara_x',
      required: false,
      description:
        'Optional Python YARA-X backend used for passive rule validation, ruleset provenance, and legacy YARA comparison handoff',
      dockerInstall: 'pip install yara-x',
      dockerFeature: 'dynamic-python',
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'optional',
      dockerInstallNotes: [
        'No default rules are downloaded or bundled by this dependency; callers provide inline rules or a local rules file.',
      ],
      extraEnv: { YARAX_PYTHON: '/usr/local/bin/python3' },
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(yaraXScanToolDefinition, createYaraXScanHandler(wm, db))
    return ['yara_x.scan']
  },
}

export default yaraXPlugin
