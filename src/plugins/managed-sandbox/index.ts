/**
 * Managed Sandbox Plugin
 *
 * Isolated .NET assembly execution with network sinkholing,
 * CLR hooking, and dynamic-load capture.
 */

import type { Plugin } from '../sdk.js'
import {
  safeRunToolDefinition, createSafeRunHandler,
} from './tools/safe-run.js'

const managedSandboxPlugin: Plugin = {
  id: 'managed-sandbox',
  name: 'Managed Sandbox',
  description:
    'Execute .NET assemblies in an isolated sandbox with network sinkholing, ' +
    'CLR hooks (Assembly.Load, CreateDecryptor, MethodInfo.Invoke), and dynamic-load capture',
  version: '1.0.0',
  configSchema: [
    { envVar: 'SANDBOX_PYTHON_PATH', description: 'Python interpreter for the sandbox worker', required: false },
    { envVar: 'SANDBOX_TIMEOUT', description: 'Default execution timeout in seconds (1–300)', required: false, defaultValue: '60' },
    { envVar: 'SANDBOX_MEMORY_MB', description: 'Default memory limit in MB (32–2048)', required: false, defaultValue: '512' },
    { envVar: 'SANDBOX_NETWORK_SINKHOLE', description: 'Enable network sinkhole by default (true/false)', required: false, defaultValue: 'true' },
  ],
  systemDeps: [
    { type: 'binary', name: 'python3', target: '$SANDBOX_PYTHON_PATH', envVar: 'SANDBOX_PYTHON_PATH', versionFlag: '--version', dockerDefault: '/usr/local/bin/python3', required: true, description: 'Python 3 interpreter for sandbox worker' },
  ],
  register(server, deps) {
    server.registerTool(safeRunToolDefinition, createSafeRunHandler(deps))
    return ['managed.safe_run']
  },
}

export default managedSandboxPlugin
