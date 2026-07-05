/**
 * Knowledge Base & Collaboration Plugin
 *
 * Function signature matching and analysis template management.
 */

import { requireDatabase, requireWorkspaceManager, type Plugin } from '../sdk.js'
import {
  KB_COLLABORATION_PLATFORMS,
  KB_COLLABORATION_RUNTIME_POLICY,
  KB_COLLABORATION_SAFETY,
  KB_FUNCTION_MATCH_CAPABILITIES,
  KB_FUNCTION_MATCH_EVIDENCE,
  KB_FUNCTION_MATCH_FORMATS,
  kbFunctionMatchToolDefinition,
  createKbFunctionMatchHandler,
} from './tools/kb-function-match.js'
import {
  analysisTemplateToolDefinition,
  createAnalysisTemplateHandler,
} from './tools/analysis-template.js'
import { kbImportBulkToolDefinition, createKbImportBulkHandler } from './tools/kb-import-bulk.js'
import { kbExportToolDefinition, createKbExportHandler } from './tools/kb-export.js'
import { kbImportToolDefinition, createKbImportHandler } from './tools/kb-import.js'
import { kbStatsToolDefinition, createKbStatsHandler } from './tools/kb-stats.js'
import { analysisNotesToolDefinition, createAnalysisNotesHandler } from './tools/analysis-notes.js'
import { ruleLibraryToolDefinition, createRuleLibraryHandler } from './tools/rule-library.js'
import {
  kbContextSuggestToolDefinition,
  createKbContextSuggestHandler,
} from './tools/kb-context-suggest.js'

const kbCollaborationPlugin: Plugin = {
  id: 'kb-collaboration',
  name: 'Knowledge Base & Collaboration',
  executionDomain: 'static',
  aspects: {
    formats: KB_FUNCTION_MATCH_FORMATS,
    platforms: KB_COLLABORATION_PLATFORMS,
    execution: ['static', 'correlation'],
    safety: KB_COLLABORATION_SAFETY,
    capabilities: [...KB_FUNCTION_MATCH_CAPABILITIES, 'rule-library', 'workflow-recommendation'],
    evidence: KB_FUNCTION_MATCH_EVIDENCE,
  },
  runtimePolicy: KB_COLLABORATION_RUNTIME_POLICY,
  surfaceRules: { tier: 0, category: 'static-analysis' },
  description:
    'Function signature matching, analysis templates, and knowledge base import/export/management',
  version: '1.0.0',
  resources: { data: 'data' },
  register(server, deps) {
    const workspaceManager = requireWorkspaceManager(deps, 'kb-collaboration')
    const database = requireDatabase(deps, 'kb-collaboration')
    server.registerTool(kbFunctionMatchToolDefinition, createKbFunctionMatchHandler(deps))
    server.registerTool(analysisTemplateToolDefinition, createAnalysisTemplateHandler(deps))
    server.registerTool(
      kbImportBulkToolDefinition,
      createKbImportBulkHandler(workspaceManager, database)
    )
    server.registerTool(kbExportToolDefinition, createKbExportHandler(workspaceManager, database))
    server.registerTool(kbImportToolDefinition, createKbImportHandler(workspaceManager, database))
    server.registerTool(kbStatsToolDefinition, createKbStatsHandler(workspaceManager, database))
    server.registerTool(analysisNotesToolDefinition, createAnalysisNotesHandler(deps))
    server.registerTool(ruleLibraryToolDefinition, createRuleLibraryHandler(deps))
    server.registerTool(kbContextSuggestToolDefinition, createKbContextSuggestHandler(deps))
    return [
      'kb.function.match',
      'analysis.template',
      'kb.import.bulk',
      'kb.export',
      'kb.import',
      'kb.stats',
      'analysis.notes',
      'rule.library',
      'kb.context.suggest',
    ]
  },
}

export default kbCollaborationPlugin
