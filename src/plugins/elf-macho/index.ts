/**
 * ELF / Mach-O Plugin
 *
 * Structure analysis and import/export extraction for ELF and Mach-O binaries.
 */

import type { Plugin } from '../sdk.js'
import { elfStructureAnalyzeToolDefinition, createElfStructureAnalyzeHandler } from '../../tools/elf-structure-analyze.js'
import { machoStructureAnalyzeToolDefinition, createMachoStructureAnalyzeHandler } from '../../tools/macho-structure-analyze.js'
import { elfImportsExtractToolDefinition, createElfImportsExtractHandler } from '../../tools/elf-imports-extract.js'
import { elfExportsExtractToolDefinition, createElfExportsExtractHandler } from '../../tools/elf-exports-extract.js'

const elfMachoPlugin: Plugin = {
  id: 'elf-macho',
  name: 'ELF / Mach-O',
  description: 'Structure analysis and import/export extraction for Linux ELF and macOS Mach-O binaries',
  version: '1.0.0',
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(elfStructureAnalyzeToolDefinition, createElfStructureAnalyzeHandler(wm, db))
    server.registerTool(machoStructureAnalyzeToolDefinition, createMachoStructureAnalyzeHandler(wm, db))
    server.registerTool(elfImportsExtractToolDefinition, createElfImportsExtractHandler(wm, db))
    server.registerTool(elfExportsExtractToolDefinition, createElfExportsExtractHandler(wm, db))

    return [
      'elf.structure.analyze', 'macho.structure.analyze',
      'elf.imports.extract', 'elf.exports.extract',
    ]
  },
}

export default elfMachoPlugin
