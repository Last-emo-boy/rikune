/**
 * .NET Reactor Deobfuscation Plugin
 *
 * Anti-tamper detection, string/route decryption tracking,
 * dynamic method recovery, and resource assembly export for
 * .NET Reactor-protected binaries.
 */

import type { Plugin } from '../sdk.js'
import {
  antiTamperToolDefinition, createAntiTamperHandler,
} from './tools/anti-tamper.js'
import {
  stringDecryptToolDefinition, createStringDecryptHandler,
} from './tools/string-decrypt.js'
import {
  dynamicMethodsToolDefinition, createDynamicMethodsHandler,
} from './tools/dynamic-methods.js'
import {
  resourceExportToolDefinition, createResourceExportHandler,
} from './tools/resource-export.js'

const dotnetReactorPlugin: Plugin = {
  id: 'dotnet-reactor',
  name: '.NET Reactor Deobfuscation',
  description:
    'Analyze and deobfuscate .NET Reactor-protected assemblies — anti-tamper detection, ' +
    'string decryption, dynamic method recovery, and resource assembly export',
  version: '1.0.0',
  configSchema: [
    { envVar: 'REACTOR_SANDBOX_ENABLED', description: 'Allow sandbox execution for dynamic analysis (true/false)', required: false, defaultValue: 'false' },
  ],
  systemDeps: [
    { type: 'binary', name: 'python3', versionFlag: '--version', dockerDefault: '/usr/local/bin/python3', required: true, description: 'Python 3 for .NET Reactor analysis workers' },
    { type: 'python', name: 'dnfile', importName: 'dnfile', required: true, description: 'Python dnfile for .NET metadata analysis', dockerInstall: 'pip install dnfile' },
  ],
  register(server, deps) {
    server.registerTool(antiTamperToolDefinition, createAntiTamperHandler(deps))
    server.registerTool(stringDecryptToolDefinition, createStringDecryptHandler(deps))
    server.registerTool(dynamicMethodsToolDefinition, createDynamicMethodsHandler(deps))
    server.registerTool(resourceExportToolDefinition, createResourceExportHandler(deps))
    return [
      'reactor.anti_tamper',
      'reactor.string_decrypt',
      'reactor.dynamic_methods',
      'reactor.resource_export',
    ]
  },
}

export default dotnetReactorPlugin
