/**
 * Strings Extraction Plugin
 *
 * Unicode/ASCII string extraction and FLOSS-based obfuscated string decoding.
 */

import type { Plugin } from '../sdk.js'
import { stringsExtractToolDefinition, createStringsExtractHandler } from './tools/strings-extract.js'
import { stringsFlossDecodeToolDefinition, createStringsFlossDecodeHandler } from './tools/strings-floss-decode.js'

const stringsPlugin: Plugin = {
  id: 'strings',
  name: 'Strings Extraction',
  description: 'Extract printable strings and decode obfuscated strings via FLOSS',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(stringsExtractToolDefinition, createStringsExtractHandler(deps.workspaceManager, deps.database, deps.cacheManager, deps.jobQueue))
    server.registerTool(stringsFlossDecodeToolDefinition, createStringsFlossDecodeHandler(deps.workspaceManager, deps.database, deps.cacheManager, deps.jobQueue))
    return ['strings.extract', 'strings.floss.decode']
  },
}

export default stringsPlugin
