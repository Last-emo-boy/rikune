/**
 * Managed Fake C2 Plugin
 *
 * Configurable fake C2 server for driving deeper sample logic
 * during sandbox analysis — custom endpoint responses, TLS support,
 * DNS redirection, and request capture.
 */

import type { Plugin } from '../sdk.js'
import {
  fakeC2ToolDefinition, createFakeC2Handler,
} from './tools/fake-c2.js'

const managedFakeC2Plugin: Plugin = {
  id: 'managed-fake-c2',
  name: 'Managed Fake C2',
  description:
    'Configurable fake C2 server — set custom responses for endpoints like /plugin, ' +
    '/ping, /gate to drive malware samples into deeper operational logic during sandbox execution',
  version: '1.0.0',
  dependencies: ['managed-sandbox'],
  configSchema: [
    { envVar: 'FAKE_C2_DEFAULT_PORT', description: 'Default HTTPS listener port (1024–65535)', required: false, defaultValue: '8443' },
    { envVar: 'FAKE_C2_TLS_CERT', description: 'Path to custom TLS certificate (auto-generated if omitted)', required: false },
    { envVar: 'FAKE_C2_TLS_KEY', description: 'Path to custom TLS private key', required: false },
  ],
  systemDeps: [
    { type: 'binary', name: 'python3', versionFlag: '--version', dockerDefault: '/usr/local/bin/python3', required: true, description: 'Python 3 for fake C2 server worker' },
  ],
  register(server, deps) {
    server.registerTool(fakeC2ToolDefinition, createFakeC2Handler(deps))
    return ['managed.fake_c2']
  },
}

export default managedFakeC2Plugin
