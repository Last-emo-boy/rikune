/**
 * YARA Plugin
 *
 * YARA rule scanning, single-rule generation, and batch rule generation.
 */

import type { Plugin } from '../sdk.js'
import { yaraScanToolDefinition, createYaraScanHandler } from './tools/yara-scan.js'
import { yaraGenerateToolDefinition, createYaraGenerateHandler } from './tools/yara-generate.js'
import { yaraGenerateBatchToolDefinition, createYaraGenerateBatchHandler } from './tools/yara-generate-batch.js'

const yaraPlugin: Plugin = {
  id: 'yara',
  name: 'YARA',
  description: 'YARA rule scanning and generation (single and batch)',
  version: '1.0.0',
  register(server, deps) {
    const { workspaceManager: wm, database: db, cacheManager: cm } = deps

    server.registerTool(yaraScanToolDefinition, createYaraScanHandler(wm, db, cm))
    server.registerTool(yaraGenerateToolDefinition, createYaraGenerateHandler(wm, db))
    server.registerTool(yaraGenerateBatchToolDefinition, createYaraGenerateBatchHandler(wm, db))

    return ['yara.scan', 'yara.generate', 'yara.generate.batch']
  },
}

export default yaraPlugin
