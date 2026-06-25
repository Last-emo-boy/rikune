/**
 * PE (Portable Executable) Analysis Plugin
 *
 * Structure parsing, import/export tables, fingerprinting, symbols recovery.
 * Core analysis tooling for Windows binaries.
 */

import type { Plugin } from '../sdk.js'
import {
  peStructureAnalyzeToolDefinition,
  createPEStructureAnalyzeHandler,
} from './tools/pe-structure-analyze.js'
import {
  peImportsExtractToolDefinition,
  createPEImportsExtractHandler,
} from './tools/pe-imports-extract.js'
import {
  peExportsExtractToolDefinition,
  createPEExportsExtractHandler,
} from './tools/pe-exports-extract.js'
import { peFingerprintToolDefinition, createPEFingerprintHandler } from './tools/pe-fingerprint.js'
import {
  pePdataExtractToolDefinition,
  createPEPdataExtractHandler,
} from './tools/pe-pdata-extract.js'
import {
  peSymbolsRecoverToolDefinition,
  createPESymbolsRecoverHandler,
} from './tools/pe-symbols-recover.js'

const peAnalysisPlugin: Plugin = {
  id: 'pe-analysis',
  name: 'PE Analysis',
  executionDomain: 'static',
  aspects: {
    formats: ['pe', 'pe-clr', 'sys', 'efi'],
    platforms: ['windows'],
    architectures: ['x86', 'x64', 'arm', 'arm64'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'external_static_backend',
      'no_live_sample_by_default',
      'no_network_by_default',
      'no_mutation',
    ],
    capabilities: ['structure', 'imports', 'exports', 'resources', 'symbols', 'routing'],
    evidence: ['structure', 'imports', 'exports', 'resources', 'symbols', 'provenance'],
  },
  surfaceRules: {
    tier: 0,
    category: 'static-analysis',
    signalMap: {
      is_signed: 'signed',
      has_certificate: 'signed',
      suspicious_imports: 'suspicious_imports',
    },
  },
  description:
    'Windows PE structure analysis, import/export extraction, fingerprinting, and symbol recovery',
  version: '1.0.0',
  systemDeps: [
    {
      type: 'python',
      name: 'pefile',
      importName: 'pefile',
      required: false,
      description: 'pefile PE parser used by static PE structure workers',
      dockerInstall: 'pip install pefile',
      dockerFeature: 'static-python',
      dockerValidation: [
        "python3 -c \"import pefile; print(getattr(pefile, '__version__', 'ok'))\"",
      ],
      dockerInstallRoute: 'installed',
      dockerInstallProfile: 'default',
    },
    {
      type: 'python',
      name: 'lief',
      importName: 'lief',
      required: false,
      description: 'LIEF executable parser used for PE structure corroboration',
      dockerInstall: 'pip install lief or provide a pinned wheel',
      dockerFeature: 'static-python',
      dockerValidation: ["python3 -c \"import lief; print(getattr(lief, '__version__', 'ok'))\""],
      dockerInstallRoute: 'installed',
      dockerInstallProfile: 'default',
    },
  ],
  register(server, deps) {
    server.registerTool(peStructureAnalyzeToolDefinition, createPEStructureAnalyzeHandler(deps))
    server.registerTool(peImportsExtractToolDefinition, createPEImportsExtractHandler(deps))
    server.registerTool(peExportsExtractToolDefinition, createPEExportsExtractHandler(deps))
    server.registerTool(peFingerprintToolDefinition, createPEFingerprintHandler(deps))
    server.registerTool(pePdataExtractToolDefinition, createPEPdataExtractHandler(deps))
    server.registerTool(peSymbolsRecoverToolDefinition, createPESymbolsRecoverHandler(deps))
    return [
      'pe.structure.analyze',
      'pe.imports.extract',
      'pe.exports.extract',
      'pe.fingerprint',
      'pe.pdata.extract',
      'pe.symbols.recover',
    ]
  },
}

export default peAnalysisPlugin
