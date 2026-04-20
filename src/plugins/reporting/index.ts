/**
 * Reporting Plugin
 *
 * Report summarization, generation, and workflow summaries.
 */

import {
  getPlatformServices,
  requireDatabase,
  requirePlatformServer,
  requireWorkspaceManager,
  type Plugin,
} from '../sdk.js'
import {
  reportSummarizeToolDefinition,
  createReportSummarizeHandler,
} from './tools/report-summarize.js'
import {
  reportGenerateToolDefinition,
  createReportGenerateHandler,
} from './tools/report-generate.js'
import {
  workflowSummarizeToolDefinition,
  createWorkflowSummarizeHandler,
} from '../../workflows/summarize.js'

const reportingPlugin: Plugin = {
  id: 'reporting',
  name: 'Reporting',
  executionDomain: 'both',
  surfaceRules: { tier: 0, category: 'static-analysis' },
  description: 'Report summarization, generation, and workflow summaries',
  version: '1.0.0',
  register(server, deps) {
    const workspaceManager = requireWorkspaceManager(deps, 'reporting')
    const database = requireDatabase(deps, 'reporting')
    const platformServer = requirePlatformServer(deps, 'workflow.summarize')
    const platform = getPlatformServices(deps)
    const cacheManager = platform.cacheManager

    server.registerTool(
      reportSummarizeToolDefinition,
      createReportSummarizeHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      reportGenerateToolDefinition,
      createReportGenerateHandler(workspaceManager, database, cacheManager)
    )
    server.registerTool(
      workflowSummarizeToolDefinition,
      createWorkflowSummarizeHandler(workspaceManager, database, cacheManager, platformServer)
    )

    return ['report.summarize', 'report.generate', 'workflow.summarize']
  },
}

export default reportingPlugin
