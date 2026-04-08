/**
 * Dynamic Analysis Automation Plugin
 *
 * Automated Frida hooking, trace attribution, and memory dumping.
 */

import type { Plugin } from '../sdk.js'
import {
  dynamicAutoHookToolDefinition, createDynamicAutoHookHandler,
} from './tools/dynamic-auto-hook.js'
import {
  dynamicTraceAttributeToolDefinition, createDynamicTraceAttributeHandler,
} from './tools/dynamic-trace-attribute.js'
import {
  dynamicMemoryDumpToolDefinition, createDynamicMemoryDumpHandler,
} from './tools/dynamic-memory-dump.js'
import { dynamicDependenciesToolDefinition, createDynamicDependenciesHandler } from '../../tools/dynamic-dependencies.js'
import { dynamicTraceImportToolDefinition, createDynamicTraceImportHandler } from '../../tools/dynamic-trace-import.js'
import { dynamicMemoryImportToolDefinition, createDynamicMemoryImportHandler } from '../../tools/dynamic-memory-import.js'
import { sandboxExecuteToolDefinition, createSandboxExecuteHandler } from '../../tools/sandbox-execute.js'

const dynamicPlugin: Plugin = {
  id: 'dynamic',
  name: 'Dynamic Analysis Automation',
  description: 'Automated Frida hooking, trace attribution, memory dumping, dependency analysis, trace/memory import, and sandbox execution',
  version: '1.0.0',
  configSchema: [
    { envVar: 'FRIDA_PATH', description: 'Path to frida CLI', required: false },
  ],
  systemDeps: [
    { type: 'binary', name: 'frida', versionFlag: '--version', envVar: 'FRIDA_PATH', required: false, description: 'Frida dynamic instrumentation toolkit', dockerInstall: 'pip install frida-tools', dockerFeature: 'frida', dockerValidation: ['frida-ps --help >/dev/null 2>&1'] },
  ],
  register(server, deps) {
    server.registerTool(dynamicAutoHookToolDefinition, createDynamicAutoHookHandler(deps))
    server.registerTool(dynamicTraceAttributeToolDefinition, createDynamicTraceAttributeHandler(deps))
    server.registerTool(dynamicMemoryDumpToolDefinition, createDynamicMemoryDumpHandler(deps))
    server.registerTool(dynamicDependenciesToolDefinition, createDynamicDependenciesHandler(deps.workspaceManager, deps.database))
    server.registerTool(dynamicTraceImportToolDefinition, createDynamicTraceImportHandler(deps.workspaceManager, deps.database))
    server.registerTool(dynamicMemoryImportToolDefinition, createDynamicMemoryImportHandler(deps.workspaceManager, deps.database))
    server.registerTool(sandboxExecuteToolDefinition, createSandboxExecuteHandler(deps.workspaceManager, deps.database, deps.policyGuard))
    return [
      'dynamic.auto_hook', 'dynamic.trace_attribute', 'dynamic.memory_dump',
      'dynamic.dependencies', 'dynamic.trace.import', 'dynamic.memory.import',
      'sandbox.execute',
    ]
  },
}

export default dynamicPlugin
