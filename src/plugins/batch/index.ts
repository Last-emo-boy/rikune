/**
 * Batch Analysis Plugin
 *
 * Submit, monitor, and retrieve results for multi-sample batch analysis.
 */

import type { Plugin } from '../sdk.js'
import {
  batchSubmitToolDefinition, createBatchSubmitHandler,
  batchStatusToolDefinition, createBatchStatusHandler,
  batchResultsToolDefinition, createBatchResultsHandler,
} from './tools/batch-analysis.js'

const batchPlugin: Plugin = {
  id: 'batch',
  name: 'Batch Analysis',
  executionDomain: 'both',
  surfaceRules: { tier: 0, category: 'static-analysis' },
  description: 'Multi-sample batch submission, monitoring, and result retrieval',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(batchSubmitToolDefinition, createBatchSubmitHandler(deps.server, deps.database))
    server.registerTool(batchStatusToolDefinition, createBatchStatusHandler())
    server.registerTool(batchResultsToolDefinition, createBatchResultsHandler())
    return ['batch.submit', 'batch.status', 'batch.results']
  },
}

export default batchPlugin
