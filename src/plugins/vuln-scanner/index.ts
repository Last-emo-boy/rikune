/**
 * Vulnerability Scanner Plugin
 *
 * CWE-based vulnerability pattern scanning on decompiled functions.
 * Uses curated pattern database (data/vuln-patterns.json).
 */

import type { Plugin } from '../sdk.js'
import {
  vulnPatternScanToolDefinition,
  createVulnPatternScanHandler,
} from './tools/vuln-pattern-scan.js'
import {
  vulnPatternSummaryToolDefinition,
  createVulnPatternSummaryHandler,
} from './tools/vuln-pattern-summary.js'

const VULN_SCANNER_SAFETY = [
  'passive',
  'static',
  'no_live_sample_by_default',
  'no_network_by_default',
  'no_mutation',
  'no_live_execution',
]

const vulnScannerPlugin: Plugin = {
  id: 'vuln-scanner',
  name: 'Vulnerability Scanner',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'elf', 'macho', 'dotnet', 'jar', 'wasm', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'jvm', 'dotnet', 'wasm', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'correlation'],
    safety: VULN_SCANNER_SAFETY,
    capabilities: [
      'cwe-patterns',
      'decompiled-code-scan',
      'function-risk-ranking',
      'audit-prioritization',
      'risk-summary',
      'workflow-handoff',
      'evidence-correlation',
    ],
    evidence: [
      'vulnerabilities',
      'functions',
      'decompiled-code',
      'cwe',
      'risk-ranking',
      'workflow',
      'provenance',
    ],
    search: [
      'vulnerability',
      'cwe',
      'buffer-overflow',
      'format-string',
      'command-injection',
      'dll-hijacking',
      'integer-overflow',
      'use-after-free',
      'function-risk',
      'audit-prioritization',
    ],
  },
  surfaceRules: {
    tier: 2,
    activateOn: {
      findings: [
        'suspicious_imports',
        'vulnerability',
        'cwe',
        'unsafe-api',
        'function-risk',
      ],
    },
    category: 'vulnerability-research',
  },
  description:
    'CWE-based passive vulnerability pattern scanning, function risk ranking, and audit handoff over recovered decompiled code.',
  version: '1.0.0',
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: false,
    requiresIsolation: false,
    allowedBackends: ['local'],
    networkPolicy: 'disabled',
    noNetwork: true,
    noMutation: true,
    noLiveExecution: true,
    notes: [
      'The vulnerability scanner consumes local decompiled function evidence and curated local pattern data.',
      'It does not execute samples, access the network, or mutate workspace content beyond requested artifacts.',
    ],
  } as Plugin['runtimePolicy'] & {
    noNetwork: true
    noMutation: true
    noLiveExecution: true
  },
  resources: { data: 'data' },
  register(server, deps) {
    server.registerTool(vulnPatternScanToolDefinition, createVulnPatternScanHandler(deps))
    server.registerTool(vulnPatternSummaryToolDefinition, createVulnPatternSummaryHandler(deps))
    return ['vuln.pattern.scan', 'vuln.pattern.summary']
  },
}

export default vulnScannerPlugin
