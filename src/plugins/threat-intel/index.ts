/**
 * Threat Intelligence Plugin
 *
 * MITRE ATT&CK mapping and IOC export (JSON/CSV/STIX2).
 */

import { requireDatabase, requireWorkspaceManager, type Plugin } from '../sdk.js'
import { attackMapToolDefinition, createAttackMapHandler } from './tools/attack-map.js'
import { iocExportToolDefinition, createIOCExportHandler } from './tools/ioc-export.js'
import {
  sigmaRuleGenerateToolDefinition,
  createSigmaRuleGenerateHandler,
} from './tools/sigma-rule-generate.js'

const threatIntelPlugin: Plugin = {
  id: 'threat-intel',
  name: 'Threat Intelligence',
  executionDomain: 'static',
  surfaceRules: { tier: 0, category: 'malware-analysis' },
  description:
    'MITRE ATT&CK technique mapping, IOC export (JSON, CSV, STIX2), and Sigma rule generation',
  version: '1.0.0',
  register(server, deps) {
    const workspaceManager = requireWorkspaceManager(deps, 'sigma.rule.generate')
    const database = requireDatabase(deps, 'sigma.rule.generate')
    server.registerTool(attackMapToolDefinition, createAttackMapHandler(deps))
    server.registerTool(iocExportToolDefinition, createIOCExportHandler(deps))
    server.registerTool(
      sigmaRuleGenerateToolDefinition,
      createSigmaRuleGenerateHandler(workspaceManager, database)
    )
    return ['attack.map', 'ioc.export', 'sigma.rule.generate']
  },
}

export default threatIntelPlugin
