/**
 * Unpacking Plugin
 *
 * Automated unpacking and unpacking strategy guidance.
 */

import type { Plugin } from '../sdk.js'
import { unpackAutoToolDefinition, createUnpackAutoHandler } from './tools/unpack-auto.js'
import { unpackGuideToolDefinition, createUnpackGuideHandler } from './tools/unpack-guide.js'

const unpackingPlugin: Plugin = {
  id: 'unpacking',
  name: 'Unpacking',
  description: 'Automated unpacking and packer-specific unpacking guidance',
  version: '1.0.0',
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(unpackAutoToolDefinition, createUnpackAutoHandler(wm, db))
    server.registerTool(unpackGuideToolDefinition, createUnpackGuideHandler(wm, db))

    return ['unpack.auto', 'unpack.guide']
  },
}

export default unpackingPlugin
