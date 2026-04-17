/**
 * Reporting Plugin
 *
 * Report summarization, generation, and workflow summaries.
 */

import type { Plugin } from '../sdk.js'
import { reportSummarizeToolDefinition, createReportSummarizeHandler } from './tools/report-summarize.js'
import { reportGenerateToolDefinition, createReportGenerateHandler } from './tools/report-generate.js'
import { workflowSummarizeToolDefinition, createWorkflowSummarizeHandler } from '../../workflows/summarize.js'

const reportingPlugin: Plugin = {
  id: 'reporting',
  name: 'Reporting',
  executionDomain: 'both',
  surfaceRules: { tier: 0, category: 'static-analysis' },
  description: 'Report summarization, generation, and workflow summaries',
  version: '1.0.0',
  register(server, deps) {
    const { workspaceManager: wm, database: db, cacheManager: cm } = deps

    server.registerTool(reportSummarizeToolDefinition, createReportSummarizeHandler(wm, db, cm))
    server.registerTool(reportGenerateToolDefinition, createReportGenerateHandler(wm, db, cm))
    server.registerTool(workflowSummarizeToolDefinition, createWorkflowSummarizeHandler(wm, db, cm, deps.server))

    return ['report.summarize', 'report.generate', 'workflow.summarize']
  },
}

export default reportingPlugin
