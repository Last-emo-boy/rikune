/**
 * Binary Diff Plugin
 *
 * Binary comparison and diff summary generation.
 */

import type { Plugin } from '../sdk.js'
import { binaryDiffToolDefinition, createBinaryDiffHandler } from './tools/binary-diff.js'
import { binaryDiffSummaryToolDefinition, createBinaryDiffSummaryHandler } from './tools/binary-diff-summary.js'

const binaryDiffPlugin: Plugin = {
  id: 'binary-diff',
  name: 'Binary Diff',
  surfaceRules: { tier: 2, activateOn: { findings: ['packed'] }, category: 'reverse-engineering' },
  description: 'Binary comparison and structural diff summaries',
  version: '1.0.0',
  resources: { workers: 'workers' },
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(binaryDiffToolDefinition, createBinaryDiffHandler(wm, db))
    server.registerTool(binaryDiffSummaryToolDefinition, createBinaryDiffSummaryHandler(wm, db))

    return ['binary.diff', 'binary.diff.summary']
  },
}

export default binaryDiffPlugin
