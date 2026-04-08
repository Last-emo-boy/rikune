/**
 * Knowledge Base & Collaboration Plugin
 *
 * Function signature matching and analysis template management.
 */

import type { Plugin } from '../sdk.js'
import { kbFunctionMatchToolDefinition, createKbFunctionMatchHandler } from './tools/kb-function-match.js'
import { analysisTemplateToolDefinition, createAnalysisTemplateHandler } from './tools/analysis-template.js'
import { kbImportBulkToolDefinition, createKbImportBulkHandler } from '../../tools/kb-import-bulk.js'
import { kbExportToolDefinition, createKbExportHandler } from '../../tools/kb-export.js'
import { kbImportToolDefinition, createKbImportHandler } from '../../tools/kb-import.js'
import { kbStatsToolDefinition, createKbStatsHandler } from '../../tools/kb-stats.js'

const kbCollaborationPlugin: Plugin = {
  id: 'kb-collaboration',
  name: 'Knowledge Base & Collaboration',
  description: 'Function signature matching, analysis templates, and knowledge base import/export/management',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(kbFunctionMatchToolDefinition, createKbFunctionMatchHandler(deps))
    server.registerTool(analysisTemplateToolDefinition, createAnalysisTemplateHandler(deps))
    server.registerTool(kbImportBulkToolDefinition, createKbImportBulkHandler(deps.workspaceManager, deps.database))
    server.registerTool(kbExportToolDefinition, createKbExportHandler(deps.workspaceManager, deps.database))
    server.registerTool(kbImportToolDefinition, createKbImportHandler(deps.workspaceManager, deps.database))
    server.registerTool(kbStatsToolDefinition, createKbStatsHandler(deps.workspaceManager, deps.database))
    return [
      'kb.function_match', 'analysis.template',
      'kb.import.bulk', 'kb.export', 'kb.import', 'kb.stats',
    ]
  },
}

export default kbCollaborationPlugin
