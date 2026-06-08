/**
 * Host Correlation Plugin
 *
 * Auto-scan directories and system artifacts to correlate DLLs/EXEs
 * with their host processes, loaders, scheduled tasks, services,
 * startup entries, and sideloading configurations.
 */

import type { Plugin } from '../sdk.js'
import {
  HOST_CORRELATION_CAPABILITIES,
  HOST_CORRELATION_EVIDENCE,
  HOST_CORRELATION_FORMATS,
  HOST_CORRELATION_RUNTIME_POLICY,
  HOST_CORRELATION_SAFETY,
  createHostCorrelateHandler,
  hostCorrelateToolDefinition,
} from './tools/host-correlate.js'

const hostCorrelationPlugin: Plugin = {
  id: 'host-correlation',
  name: 'Host Correlation',
  executionDomain: 'static',
  aspects: {
    formats: HOST_CORRELATION_FORMATS,
    platforms: ['windows'],
    execution: ['static', 'triage', 'correlation'],
    safety: HOST_CORRELATION_SAFETY,
    capabilities: HOST_CORRELATION_CAPABILITIES,
    evidence: HOST_CORRELATION_EVIDENCE,
  },
  runtimePolicy: HOST_CORRELATION_RUNTIME_POLICY,
  surfaceRules: {
    tier: 2,
    activateOn: {
      findings: ['suspicious_imports', 'dll_sideloading', 'persistence', 'host-loader'],
      fileTypes: ['pe', 'dll', 'exe', 'windows-host-artifacts', 'manifest', 'registry'],
    },
    category: 'malware-analysis',
  },
  description:
    'Auto-scan directory and system artifacts to correlate DLLs with host EXEs, ' +
    'scheduled tasks, services, startup entries, sideloading configs, and COM registration',
  version: '1.0.0',
  systemDeps: [
    {
      type: 'binary',
      name: 'python3',
      versionFlag: '--version',
      dockerDefault: '/usr/local/bin/python3',
      required: true,
      description: 'Python 3 for host correlation worker',
    },
    {
      type: 'python',
      name: 'pefile',
      importName: 'pefile',
      required: false,
      description:
        'Optional Python pefile for future deep PE header analysis; the bundled worker uses a minimal parser by default',
      dockerInstall: 'pip install pefile',
    },
  ],
  resources: { workers: 'workers' },
  register(server, deps) {
    server.registerTool(hostCorrelateToolDefinition, createHostCorrelateHandler(deps))
    return ['host.correlate']
  },
}

export default hostCorrelationPlugin
