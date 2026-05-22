/**
 * ELF / Mach-O Plugin
 *
 * Structure analysis and import/export extraction for ELF and Mach-O binaries.
 */

import type { Plugin } from '../sdk.js'
import {
  elfStructureAnalyzeToolDefinition,
  createElfStructureAnalyzeHandler,
} from './tools/elf-structure-analyze.js'
import {
  machoStructureAnalyzeToolDefinition,
  createMachoStructureAnalyzeHandler,
} from './tools/macho-structure-analyze.js'
import {
  elfImportsExtractToolDefinition,
  createElfImportsExtractHandler,
} from './tools/elf-imports-extract.js'
import {
  elfExportsExtractToolDefinition,
  createElfExportsExtractHandler,
} from './tools/elf-exports-extract.js'

const elfMachoPlugin: Plugin = {
  id: 'elf-macho',
  name: 'ELF / Mach-O',
  executionDomain: 'static',
  aspects: {
    formats: [
      'elf',
      'so',
      'core',
      'elf-core',
      'elf-object',
      'linux-kernel-module',
      'dwarf',
      'macho',
      'fat',
      'universal',
      'macho-object',
      'dylib',
      'framework',
      'dsym',
    ],
    platforms: ['linux', 'macos', 'ios'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
    execution: ['static', 'triage'],
    safety: ['passive'],
    capabilities: ['structure', 'imports', 'exports', 'symbols', 'routing'],
    evidence: ['structure', 'imports', 'exports', 'symbols', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'elf',
        'so',
        'core',
        'elf-core',
        'elf-object',
        'linux-kernel-module',
        'dwarf',
        'macho',
        'mach-o',
        'mach-o-fat',
        'fat',
        'universal',
        'macho-object',
        'dylib',
        'framework',
        'dsym',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Structure analysis and import/export extraction for Linux ELF and macOS Mach-O binaries',
  version: '1.0.0',
  resources: { workers: 'workers' },
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(elfStructureAnalyzeToolDefinition, createElfStructureAnalyzeHandler(wm, db))
    server.registerTool(
      machoStructureAnalyzeToolDefinition,
      createMachoStructureAnalyzeHandler(wm, db)
    )
    server.registerTool(elfImportsExtractToolDefinition, createElfImportsExtractHandler(wm, db))
    server.registerTool(elfExportsExtractToolDefinition, createElfExportsExtractHandler(wm, db))

    return [
      'elf.structure.analyze',
      'macho.structure.analyze',
      'elf.imports.extract',
      'elf.exports.extract',
    ]
  },
}

export default elfMachoPlugin
