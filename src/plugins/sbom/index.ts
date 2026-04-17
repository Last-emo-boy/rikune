/**
 * SBOM Plugin
 *
 * Software Bill of Materials generation.
 */

import type { Plugin } from '../sdk.js'
import { sbomGenerateToolDefinition, createSbomGenerateHandler } from './tools/sbom-generate.js'

const sbomPlugin: Plugin = {
  id: 'sbom',
  name: 'SBOM',
  executionDomain: 'static',
  surfaceRules: { tier: 2, activateOn: { findings: ['dotnet', 'go'] }, category: 'static-analysis' },
  description: 'Software Bill of Materials (SBOM) generation from binary analysis',
  version: '1.0.0',
  register(server, deps) {
    server.registerTool(sbomGenerateToolDefinition, createSbomGenerateHandler(deps.workspaceManager, deps.database))
    return ['sbom.generate']
  },
}

export default sbomPlugin
