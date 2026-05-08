/**
 * SBOM Plugin
 *
 * Software Bill of Materials generation.
 */

import { definePlugin, defineTool, requireDatabase, requireWorkspaceManager } from '../sdk.js'
import { sbomGenerateToolDefinition, createSbomGenerateHandler } from './tools/sbom-generate.js'

const sbomPlugin = definePlugin({
  id: 'sbom',
  name: 'SBOM',
  executionDomain: 'static',
  surfaceRules: {
    tier: 2,
    activateOn: { findings: ['dotnet', 'go'] },
    category: 'static-analysis',
  },
  description: 'Software Bill of Materials (SBOM) generation from binary analysis',
  version: '1.0.0',
  tools: [
    defineTool({
      ...sbomGenerateToolDefinition,
      handler: (args, deps) =>
        createSbomGenerateHandler(
          requireWorkspaceManager(deps, 'sbom.generate'),
          requireDatabase(deps, 'sbom.generate')
        )(args as never),
    }),
  ],
})

export default sbomPlugin
