/**
 * .NET Managed Inventory Plugin
 *
 * Passive inventory for PE-CLR, NuGet, WinMD, Mono, and managed assemblies.
 * It does not start the CLR, restore packages, or launch a decompiler.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createDotnetAssemblyInspectHandler,
  dotnetAssemblyInspectToolDefinition,
} from './tools/dotnet-assembly-inspect.js'
import {
  DOTNET_MANAGED_RUNTIME_POLICY,
  DOTNET_MANAGED_TOOL_VERSION,
  dotnetManagedAspects,
} from './dotnet-managed-metadata.js'

const dotnetManagedPlugin = definePlugin({
  id: 'dotnet-managed',
  name: '.NET Managed Inventory',
  executionDomain: 'static',
  aspects: dotnetManagedAspects(),
  runtimePolicy: DOTNET_MANAGED_RUNTIME_POLICY,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['dotnet', 'pe-clr', 'nupkg', 'mono', 'winmd'],
    },
    category: 'dotnet-analysis',
  },
  description:
    'Passive .NET, Mono, NuGet, and WinMD metadata inventory without CLR execution or package restore.',
  version: DOTNET_MANAGED_TOOL_VERSION,
  tools: [
    defineTool({
      ...dotnetAssemblyInspectToolDefinition,
      handler: (args, deps) => createDotnetAssemblyInspectHandler(deps)(args as never),
    }),
  ],
})

export default dotnetManagedPlugin
