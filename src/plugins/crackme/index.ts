/**
 * CrackMe Automation Plugin
 *
 * Validation routine location, symbolic execution, patching, and keygen verification.
 */

import type { Plugin } from '../sdk.js'
import {
  crackmeLocateValidationToolDefinition, createCrackmeLocateValidationHandler,
} from './tools/crackme-locate-validation.js'
import {
  symbolicExploreToolDefinition, createSymbolicExploreHandler,
} from './tools/symbolic-explore.js'
import {
  patchGenerateToolDefinition, createPatchGenerateHandler,
} from './tools/patch-generate.js'
import {
  keygenVerifyToolDefinition, createKeygenVerifyHandler,
} from './tools/keygen-verify.js'

const crackmePlugin: Plugin = {
  id: 'crackme',
  name: 'CrackMe Automation',
  executionDomain: 'static',
  surfaceRules: { tier: 3, category: 'reverse-engineering' },
  description: 'Validation routine location, symbolic execution, patching, and keygen verification',
  version: '1.0.0',
  dependencies: [],
  configSchema: [
    { envVar: 'ANGR_AVAILABLE', description: 'Whether angr is installed for symbolic execution', required: false },
  ],
  systemDeps: [
    { type: 'python-venv', name: 'angr', target: '$ANGR_PYTHON', envVar: 'ANGR_PYTHON', dockerDefault: '/opt/angr-venv/bin/python', required: false, description: 'angr symbolic execution framework', dockerInstall: 'python3 -m venv /opt/angr-venv && pip install angr', dockerFeature: 'angr', dockerValidation: ['/opt/angr-venv/bin/python -c "import angr; print(\'✓ angr\')"'] },
  ],
  resources: { workers: 'workers' },
  check() {
    return true
  },
  register(server, deps) {
    server.registerTool(crackmeLocateValidationToolDefinition, createCrackmeLocateValidationHandler(deps))
    server.registerTool(symbolicExploreToolDefinition, createSymbolicExploreHandler(deps))
    server.registerTool(patchGenerateToolDefinition, createPatchGenerateHandler(deps))
    server.registerTool(keygenVerifyToolDefinition, createKeygenVerifyHandler(deps))
    return ['crackme.locate_validation', 'symbolic.explore', 'patch.generate', 'keygen.verify']
  },
}

export default crackmePlugin
