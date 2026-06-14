/**
 * Batch Analysis Plugin
 *
 * Submit, monitor, and retrieve results for multi-sample batch analysis.
 */

import { requirePlatformServer, type Plugin } from '../sdk.js'
import {
  batchSubmitToolDefinition,
  createBatchSubmitHandler,
  batchStatusToolDefinition,
  createBatchStatusHandler,
  batchResultsToolDefinition,
  createBatchResultsHandler,
} from './tools/batch-analysis.js'

const batchPlugin: Plugin = {
  id: 'batch',
  name: 'Batch Analysis',
  executionDomain: 'both',
  aspects: {
    formats: ['pe', 'elf', 'macho', 'apk', 'jar', 'office', 'pcap', 'wasm', 'js'],
    platforms: ['windows', 'linux', 'macos', 'android', 'cross-platform'],
    execution: ['static', 'dynamic', 'workflow-orchestration'],
    safety: ['passive'],
    capabilities: ['batch-analysis', 'workflow-orchestration', 'task-control', 'reporting'],
    evidence: ['workflow', 'provenance'],
  },
  surfaceRules: { tier: 0, category: 'static-analysis' },
  description: 'Multi-sample batch submission, monitoring, and result retrieval',
  version: '1.0.0',
  register(server, deps) {
    const platformServer = requirePlatformServer(deps, 'batch.submit')
    server.registerTool(batchSubmitToolDefinition, createBatchSubmitHandler(platformServer))
    server.registerTool(batchStatusToolDefinition, createBatchStatusHandler())
    server.registerTool(batchResultsToolDefinition, createBatchResultsHandler())
    return ['batch.submit', 'batch.status', 'batch.results']
  },
}

export default batchPlugin
