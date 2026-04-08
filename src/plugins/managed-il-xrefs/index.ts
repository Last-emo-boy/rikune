/**
 * Managed IL Cross-References Plugin
 *
 * IL-level cross-reference analysis: field/method/type token xrefs,
 * generic context resolution, and bidirectional reference graphs.
 */

import type { Plugin } from '../sdk.js'
import {
  ilXrefsToolDefinition, createIlXrefsHandler,
} from './tools/il-xrefs.js'
import {
  tokenXrefsToolDefinition, createTokenXrefsHandler,
} from './tools/token-xrefs.js'

const managedIlXrefsPlugin: Plugin = {
  id: 'managed-il-xrefs',
  name: 'Managed IL Cross-References',
  description:
    'IL-level cross-reference analysis — scan method bodies for stfld/ldfld/call sites, ' +
    'build bidirectional reference graphs, and resolve generic instantiation contexts',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(ilXrefsToolDefinition, createIlXrefsHandler(deps))
    server.registerTool(tokenXrefsToolDefinition, createTokenXrefsHandler(deps))
    return ['managed.il_xrefs', 'managed.token_xrefs']
  },
}

export default managedIlXrefsPlugin
