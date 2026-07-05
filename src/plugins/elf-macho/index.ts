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
import { ELF_MACHO_RUNTIME_POLICY } from './elf-macho-metadata.js'

const elfMachoPlugin: Plugin = {
  id: 'elf-macho',
  name: 'ELF / Mach-O',
  executionDomain: 'static',
  aspects: {
    formats: [
      'elf',
      'elf-executable',
      'so',
      'elf-so',
      'shared-library',
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
      'mach-o-object',
      'dylib',
      'framework',
      'dsym',
    ],
    platforms: ['linux', 'macos', 'ios'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel', 'ppc', 'riscv'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'no_sample_execution',
      'no_runtime_start',
      'no_native_load',
      'no_network_by_default',
      'no_mutation',
    ],
    capabilities: [
      'structure',
      'imports',
      'exports',
      'symbols',
      'loader-metadata',
      'search-profile',
      'workflow-handoff',
      'routing',
    ],
    evidence: ['structure', 'imports', 'exports', 'symbols', 'loader', 'workflow', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'elf',
        'elf-executable',
        'so',
        'elf-so',
        'shared-library',
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
        'mach-o-object',
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
  runtimePolicy: ELF_MACHO_RUNTIME_POLICY,
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
