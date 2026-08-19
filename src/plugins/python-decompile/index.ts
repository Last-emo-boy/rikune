/**
 * python-decompile Plugin
 *
 * Decompile Python bytecode (.pyc) to source code or bounded disassembly.
 * Recovers source via decompyle3/uncompyle6 when version-compatible; falls
 * back to dis.dis which always works. Fills the Python bytecode decompilation
 * gap left by the metadata-only `bytecode` plugin.
 */

import type { Plugin } from '../sdk.js'
import {
  pythonDecompileToolDefinition,
  createPythonDecompileHandler,
} from './tools/python-decompile.js'

const pythonDecompilePlugin: Plugin = {
  id: 'python-decompile',
  name: 'Python Bytecode Decompiler',
  executionDomain: 'static',
  aspects: {
    formats: ['pyc', 'pyo', 'python', 'python-bytecode'],
    platforms: ['python', 'cross-platform'],
    execution: ['static', 'decompilation'],
    safety: ['passive', 'read_only', 'no_live_sample_by_default', 'no_network_by_default'],
    capabilities: [
      'python-decompilation',
      'bytecode-disassembly',
      'code-object-recovery',
      'source-recovery',
    ],
    evidence: ['source', 'disassembly', 'strings', 'provenance'],
  },
  surfaceRules: {
    tier: 2,
    activateOn: { fileTypes: ['pyc', 'pyo', 'python', 'python-bytecode'] },
    category: 'reverse-engineering',
  },
  description:
    'Decompile Python bytecode (.pyc) to source via decompyle3/uncompyle6, ' +
    'with a dis.dis disassembly fallback. Never executes the code object bytecode.',
  version: '0.1.0',
  dependencies: [],
  configSchema: [
    {
      envVar: 'PYTHON_PATH',
      description: 'Python interpreter for the decompiler worker (stdlib marshal/dis)',
      required: false,
    },
  ],
  systemDeps: [
    {
      type: 'python',
      name: 'decompyle3',
      importName: 'decompyle3',
      required: false,
      description: 'Python 3.7-3.8 bytecode decompiler (optional source recovery)',
      dockerInstall: 'pip install decompyle3',
      dockerFeature: 'python-decompile',
      dockerValidation: ['python3 -c "import decompyle3; print(\'decompyle3 ok\')" || true'],
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'optional',
    },
    {
      type: 'python',
      name: 'uncompyle6',
      importName: 'uncompyle6',
      required: false,
      description: 'Python 2.7/3.5-3.8 bytecode decompiler (optional source recovery)',
      dockerInstall: 'pip install uncompyle6',
      dockerFeature: 'python-decompile',
      dockerValidation: ['python3 -c "import uncompyle6; print(\'uncompyle6 ok\')" || true'],
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'optional',
    },
  ],
  resources: { workers: 'workers' },
  check() {
    return true
  },
  register(server, deps) {
    server.registerTool(pythonDecompileToolDefinition, createPythonDecompileHandler(deps))
    return ['python.decompile']
  },
}

export default pythonDecompilePlugin
