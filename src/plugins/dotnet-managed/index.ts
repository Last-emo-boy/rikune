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

const dotnetManagedPlugin = definePlugin({
  id: 'dotnet-managed',
  name: '.NET Managed Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['dotnet', 'pe-clr', 'nupkg', 'mono', 'winmd'],
    platforms: ['dotnet', 'windows', 'linux', 'macos'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage', 'decompilation'],
    safety: ['passive', 'no_live_sample_by_default'],
    capabilities: ['assembly-metadata', 'resources', 'dependencies', 'decompile-plan', 'routing'],
    evidence: ['manifest', 'resources', 'package-metadata', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['dotnet', 'pe-clr', 'nupkg', 'mono', 'winmd'],
    },
    category: 'dotnet-analysis',
  },
  description:
    'Passive .NET, Mono, NuGet, and WinMD metadata inventory without CLR execution or package restore.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...dotnetAssemblyInspectToolDefinition,
      handler: (args, deps) => createDotnetAssemblyInspectHandler(deps)(args as never),
    }),
  ],
})

export default dotnetManagedPlugin
