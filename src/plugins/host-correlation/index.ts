/**
 * Host Correlation Plugin
 *
 * Auto-scan directories and system artifacts to correlate DLLs/EXEs
 * with their host processes, loaders, scheduled tasks, services,
 * startup entries, and sideloading configurations.
 */

import type { Plugin } from '../sdk.js'
import {
  hostCorrelateToolDefinition, createHostCorrelateHandler,
} from './tools/host-correlate.js'

const hostCorrelationPlugin: Plugin = {
  id: 'host-correlation',
  name: 'Host Correlation',
  description:
    'Auto-scan directory and system artifacts to correlate DLLs with host EXEs, ' +
    'scheduled tasks, services, startup entries, sideloading configs, and COM registration',
  version: '1.0.0',
  systemDeps: [
    { type: 'binary', name: 'python3', versionFlag: '--version', dockerDefault: '/usr/local/bin/python3', required: true, description: 'Python 3 for host correlation worker' },
    { type: 'python', name: 'pefile', importName: 'pefile', required: true, description: 'Python pefile for PE header analysis', dockerInstall: 'pip install pefile' },
  ],
  register(server, deps) {
    server.registerTool(hostCorrelateToolDefinition, createHostCorrelateHandler(deps))
    return ['host.correlate']
  },
}

export default hostCorrelationPlugin
