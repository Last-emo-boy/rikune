/**
 * Managed IL Cross-References Plugin
 *
 * IL-level cross-reference analysis: field/method/type token xrefs,
 * generic context resolution, and bidirectional reference graphs.
 */

import type { Plugin } from '../sdk.js'
import { ilXrefsToolDefinition, createIlXrefsHandler } from './tools/il-xrefs.js'
import { tokenXrefsToolDefinition, createTokenXrefsHandler } from './tools/token-xrefs.js'
import {
  MANAGED_IL_XREFS_ARCHITECTURES,
  MANAGED_IL_XREFS_CAPABILITIES,
  MANAGED_IL_XREFS_EVIDENCE,
  MANAGED_IL_XREFS_FORMATS,
  MANAGED_IL_XREFS_PLATFORMS,
  MANAGED_IL_XREFS_PROFILE_TERMS,
  MANAGED_IL_XREFS_ROUTE_TERMS,
  MANAGED_IL_XREFS_RUNTIME_POLICY,
  MANAGED_IL_XREFS_SAFETY,
  MANAGED_IL_XREFS_SEARCH_TERMS,
  MANAGED_IL_XREFS_TOOL_VERSION,
} from './managed-il-xrefs-metadata.js'

const managedIlXrefsPlugin: Plugin = {
  id: 'managed-il-xrefs',
  name: 'Managed IL Cross-References',
  executionDomain: 'static',
  aspects: {
    formats: MANAGED_IL_XREFS_FORMATS,
    platforms: MANAGED_IL_XREFS_PLATFORMS,
    architectures: MANAGED_IL_XREFS_ARCHITECTURES,
    execution: ['static', 'triage'],
    safety: MANAGED_IL_XREFS_SAFETY,
    capabilities: MANAGED_IL_XREFS_CAPABILITIES,
    evidence: MANAGED_IL_XREFS_EVIDENCE,
    search: MANAGED_IL_XREFS_SEARCH_TERMS,
    profile: MANAGED_IL_XREFS_PROFILE_TERMS,
    route_terms: MANAGED_IL_XREFS_ROUTE_TERMS,
  },
  runtimePolicy: MANAGED_IL_XREFS_RUNTIME_POLICY,
  surfaceRules: { tier: 2, activateOn: { findings: ['dotnet'] }, category: 'dotnet-analysis' },
  description:
    'IL-level cross-reference analysis — scan method bodies for stfld/ldfld/call sites, ' +
    'build bidirectional reference graphs, and resolve generic instantiation contexts',
  version: MANAGED_IL_XREFS_TOOL_VERSION,
  systemDeps: [
    {
      type: 'binary',
      name: 'python3',
      versionFlag: '--version',
      dockerDefault: '/usr/local/bin/python3',
      required: false,
      description: 'Python 3 for explicit IL cross-reference worker execution',
    },
    {
      type: 'python',
      name: 'dnfile',
      importName: 'dnfile',
      required: false,
      description: 'Python dnfile library for explicit .NET metadata xref parsing',
      dockerInstall: 'pip install dnfile',
    },
  ],
  resources: { workers: 'workers' },
  register(server, deps) {
    server.registerTool(ilXrefsToolDefinition, createIlXrefsHandler(deps))
    server.registerTool(tokenXrefsToolDefinition, createTokenXrefsHandler(deps))
    return ['managed.il_xrefs', 'managed.token_xrefs']
  },
}

export default managedIlXrefsPlugin
