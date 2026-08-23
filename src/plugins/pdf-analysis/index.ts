/**
 * pdf-analysis Plugin
 *
 * Performs bounded, passive PDF structure and action analysis using a bundled
 * Python standard-library worker. Embedded JavaScript is extracted as text and
 * is never evaluated.
 */

import type { Plugin } from '../sdk.js'
import { createPdfAnalyzeHandler, pdfAnalyzeToolDefinition } from './tools/pdf-analyze.js'

const pdfAnalysisPlugin: Plugin = {
  id: 'pdf-analysis',
  name: 'PDF Static Analysis',
  executionDomain: 'static',
  aspects: {
    formats: ['pdf'],
    platforms: ['cross-platform', 'document'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'read_only',
      'bounded_output',
      'no_live_sample_by_default',
      'no_network_by_default',
      'no_js_execution',
    ],
    capabilities: [
      'pdf-static-analysis',
      'javascript-extraction',
      'object-model-parsing',
      'action-inventory',
      'malware-triage',
    ],
    evidence: ['structure', 'javascript', 'uris', 'actions', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: { fileTypes: ['pdf'] },
    category: 'malware-analysis',
  },
  description:
    'Statically inspect PDF structure, embedded JavaScript, URIs, launch actions, ' +
    'and embedded-file markers without opening the document or executing content.',
  version: '0.1.0',
  dependencies: [],
  configSchema: [
    {
      envVar: 'PYTHON_PATH',
      description: 'Python 3 interpreter for the bundled standard-library PDF worker',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'python3',
      versionFlag: '--version',
      dockerDefault: '/usr/local/bin/python3',
      required: true,
      description: 'Python 3 for the bounded PDF static-analysis worker',
    },
  ],
  resources: { workers: 'workers' },
  check() {
    return true
  },
  register(server, deps) {
    server.registerTool(pdfAnalyzeToolDefinition, createPdfAnalyzeHandler(deps))
    return ['pdf.analyze']
  },
}

export default pdfAnalysisPlugin
