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

const vulnScannerPlugin: Plugin = {
  id: 'vuln-scanner',
  name: 'Vulnerability Scanner',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'elf', 'macho', 'dotnet', 'jar', 'wasm', 'firmware'],
    platforms: ['windows', 'linux', 'macos', 'jvm', 'dotnet', 'wasm', 'embedded', 'cross-platform'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv', 'wasm'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_network_by_default'],
    capabilities: ['cwe-patterns', 'decompiled-code-scan', 'risk-summary'],
    evidence: ['vulnerabilities', 'symbols', 'strings', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: { findings: ['suspicious_imports'] },
    category: 'vulnerability-research',
  },
  description: 'CWE-based vulnerability pattern scanning on decompiled code',
  version: '1.0.0',
  resources: { data: 'data' },
  register(server, deps) {
    server.registerTool(vulnPatternScanToolDefinition, createVulnPatternScanHandler(deps))
    server.registerTool(vulnPatternSummaryToolDefinition, createVulnPatternSummaryHandler(deps))
    return ['vuln.pattern.scan', 'vuln.pattern.summary']
  },
}

export default vulnScannerPlugin
