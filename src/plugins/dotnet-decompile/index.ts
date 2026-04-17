/**
 * .NET Decompile Plugin
 *
 * Full C# source code recovery from .NET assemblies using ILSpy CLI (ilspycmd).
 */

import type { Plugin } from '../sdk.js'
import { dotnetDecompileToolDefinition, createDotnetDecompileHandler } from './tools/dotnet-decompile.js'
import { dotnetDecompileTypeToolDefinition, createDotnetDecompileTypeHandler } from './tools/dotnet-decompile-type.js'

const dotnetDecompilePlugin: Plugin = {
  id: 'dotnet-decompile',
  name: '.NET Decompile',
  executionDomain: 'static',
  surfaceRules: { tier: 2, activateOn: { findings: ['dotnet'] }, category: 'dotnet-analysis' },
  description: 'Full C# source code recovery from .NET assemblies using ILSpy CLI',
  version: '1.0.0',
  configSchema: [
    { envVar: 'ILSPYCMD_PATH', description: 'Path to ilspycmd binary', required: false, defaultValue: 'ilspycmd' },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'ilspycmd',
      target: '$ILSPYCMD_PATH',
      envVar: 'ILSPYCMD_PATH',
      versionFlag: '--version',
      required: false,
      description: 'ILSpy command-line decompiler for .NET assemblies',
      dockerInstall: 'dotnet tool install ilspycmd -g',
      dockerFeature: 'dotnet-runtime',
      dockerValidation: ['ilspycmd --version >/dev/null 2>&1'],
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(dotnetDecompileToolDefinition, createDotnetDecompileHandler(wm, db))
    server.registerTool(dotnetDecompileTypeToolDefinition, createDotnetDecompileTypeHandler(wm, db))

    return ['dotnet.decompile', 'dotnet.decompile.type']
  },
}

export default dotnetDecompilePlugin
