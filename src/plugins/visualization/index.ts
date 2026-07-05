/**
 * Visualization & Reporting Plugin
 *
 * HTML report generation, behavior timelines, and data-flow maps.
 */

import type { Plugin } from '../sdk.js'
import {
  reportHtmlGenerateToolDefinition,
  createReportHtmlGenerateHandler,
} from './tools/report-html-generate.js'
import {
  behaviorTimelineToolDefinition,
  createBehaviorTimelineHandler,
} from './tools/behavior-timeline.js'
import { dataFlowMapToolDefinition, createDataFlowMapHandler } from './tools/data-flow-map.js'
import { evidenceGraphToolDefinition, createEvidenceGraphHandler } from './tools/evidence-graph.js'
import {
  cryptoLifecycleGraphToolDefinition,
  createCryptoLifecycleGraphHandler,
} from './tools/crypto-lifecycle-graph.js'

const visualizationPlugin: Plugin = {
  id: 'visualization',
  name: 'Visualization & Reporting',
  executionDomain: 'static',
  aspects: {
    formats: ['artifact', 'report', 'analysis-evidence'],
    platforms: ['all', 'cross-platform'],
    execution: ['static', 'correlation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: [
      'report-generation',
      'timeline',
      'data-flow',
      'evidence-correlation',
      'crypto-flow',
    ],
    evidence: [
      'timeline',
      'behavior',
      'network',
      'filesystem',
      'registry',
      'memory',
      'artifact',
      'provenance',
    ],
  },
  surfaceRules: { tier: 0, category: 'static-analysis' },
  description:
    'HTML report generation, behavior timelines, data-flow maps, evidence graphs, and crypto lifecycle graphs',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(reportHtmlGenerateToolDefinition, createReportHtmlGenerateHandler(deps))
    server.registerTool(behaviorTimelineToolDefinition, createBehaviorTimelineHandler(deps))
    server.registerTool(dataFlowMapToolDefinition, createDataFlowMapHandler(deps))
    server.registerTool(evidenceGraphToolDefinition, createEvidenceGraphHandler(deps))
    server.registerTool(cryptoLifecycleGraphToolDefinition, createCryptoLifecycleGraphHandler(deps))
    return [
      'report.html.generate',
      'behavior.timeline',
      'data.flow.map',
      'analysis.evidence.graph',
      'crypto.lifecycle.graph',
    ]
  },
}

export default visualizationPlugin
