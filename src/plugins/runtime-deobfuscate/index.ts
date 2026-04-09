/**
 * Runtime Deobfuscation Plugin
 *
 * Dynamic deobfuscation via Frida instrumentation and de4dot integration.
 * Captures decrypted strings, resolved APIs, and execution traces at runtime.
 * Docker-priority: requires Frida for runtime hooks, de4dot for .NET.
 */

import type { Plugin } from '../sdk.js'
import { deobfStringsToolDefinition, createDeobfStringsHandler } from './tools/deobf-strings.js'
import { deobfApiResolveToolDefinition, createDeobfApiResolveHandler } from './tools/deobf-api-resolve.js'
import { deobfCfgTraceToolDefinition, createDeobfCfgTraceHandler } from './tools/deobf-cfg-trace.js'
import { deobfDotnetToolDefinition, createDeobfDotnetHandler } from './tools/deobf-dotnet.js'

const runtimeDeobfuscatePlugin: Plugin = {
  id: 'runtime-deobfuscate',
  name: 'Runtime Deobfuscation',
  description:
    'Dynamic deobfuscation: runtime string decryption via Frida hooks, ' +
    'dynamic API resolution capture, CFG recovery from execution traces, ' +
    'and .NET deobfuscation via de4dot. Docker-priority.',
  version: '1.0.0',
  configSchema: [
    { envVar: 'FRIDA_PATH', description: 'Path to Frida CLI', required: false },
    { envVar: 'DE4DOT_PATH', description: 'Path to de4dot binary', required: false },
    { envVar: 'DEOBF_TIMEOUT', description: 'Default deobfuscation timeout in seconds', required: false, defaultValue: '60' },
  ],
  systemDeps: [
    {
      type: 'binary', name: 'frida', versionFlag: '--version',
      envVar: 'FRIDA_PATH', required: false,
      description: 'Frida dynamic instrumentation toolkit for runtime hooks',
      dockerInstall: 'pip install frida frida-tools',
      dockerFeature: 'frida',
      dockerValidation: ['frida-ps --help >/dev/null 2>&1'],
  
    },
    {
      type: 'binary', name: 'de4dot', required: false,
      envVar: 'DE4DOT_PATH',
      dockerDefault: '/opt/de4dot/de4dot',
      description: '.NET deobfuscator (de4dot) for ConfuserEx, .NET Reactor, etc.',
      dockerFeature: 'de4dot',
      aptPackages: ['libicu72'],
      dockerValidation: ['de4dot --help >/dev/null 2>&1 || true'],
    },
    {
      type: 'binary', name: 'wine', versionFlag: '--version', required: false,
      description: 'Wine for Windows binary execution on Linux',
      dockerFeature: 'wine',
    },
  ],
  resources: { workers: 'workers' },
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(deobfStringsToolDefinition, createDeobfStringsHandler(wm, db))
    server.registerTool(deobfApiResolveToolDefinition, createDeobfApiResolveHandler(wm, db))
    server.registerTool(deobfCfgTraceToolDefinition, createDeobfCfgTraceHandler(wm, db))
    server.registerTool(deobfDotnetToolDefinition, createDeobfDotnetHandler(wm, db))
    return ['deobf.strings', 'deobf.api_resolve', 'deobf.cfg_trace', 'deobf.dotnet']
  },
}

export default runtimeDeobfuscatePlugin
