/**
 * Knowledge Base & Collaboration Plugin
 *
 * Function signature matching and analysis template management.
 */

import type { Plugin } from '../sdk.js'
import { kbFunctionMatchToolDefinition, createKbFunctionMatchHandler } from './tools/kb-function-match.js'
import { analysisTemplateToolDefinition, createAnalysisTemplateHandler } from './tools/analysis-template.js'
import { analysisNotesToolDefinition, createAnalysisNotesHandler } from './tools/analysis-notes.js'
import { ruleLibraryToolDefinition, createRuleLibraryHandler } from './tools/rule-library.js'

const kbCollaborationPlugin: Plugin = {
  id: 'kb-collaboration',
  name: 'Knowledge Base & Collaboration',
  description: 'Function signature matching and analysis template management',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(kbFunctionMatchToolDefinition, createKbFunctionMatchHandler(deps))
    server.registerTool(analysisTemplateToolDefinition, createAnalysisTemplateHandler(deps))
    server.registerTool(analysisNotesToolDefinition, createAnalysisNotesHandler(deps))
    server.registerTool(ruleLibraryToolDefinition, createRuleLibraryHandler(deps))
    return ['kb.function_match', 'analysis.template', 'analysis.notes', 'rule.library']
  },
}

export default kbCollaborationPlugin
