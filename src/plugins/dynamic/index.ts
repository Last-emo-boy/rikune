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
import { dynamicDependenciesToolDefinition, createDynamicDependenciesHandler } from './tools/dynamic-dependencies.js'
import { dynamicTraceImportToolDefinition, createDynamicTraceImportHandler } from './tools/dynamic-trace-import.js'
import { dynamicMemoryImportToolDefinition, createDynamicMemoryImportHandler } from './tools/dynamic-memory-import.js'
import { sandboxExecuteToolDefinition, createSandboxExecuteHandler } from './tools/sandbox-execute.js'
import {
  runtimeDebugSessionStartToolDefinition, createRuntimeDebugSessionStartHandler,
  runtimeDebugSessionStatusToolDefinition, createRuntimeDebugSessionStatusHandler,
  runtimeDebugSessionStopToolDefinition, createRuntimeDebugSessionStopHandler,
  runtimeDebugCommandToolDefinition, createRuntimeDebugCommandHandler,
} from './tools/runtime-debug-session.js'
import { dynamicRuntimeStatusToolDefinition, createDynamicRuntimeStatusHandler } from './tools/dynamic-runtime-status.js'
import { dynamicBehaviorCaptureToolDefinition, createDynamicBehaviorCaptureHandler } from './tools/dynamic-behavior-capture.js'
import { runtimeHyperVControlToolDefinition, createRuntimeHyperVControlHandler } from './tools/runtime-hyperv-control.js'
import { dynamicToolkitStatusToolDefinition, createDynamicToolkitStatusHandler } from './tools/dynamic-toolkit-status.js'
import { dynamicDeepPlanToolDefinition, createDynamicDeepPlanHandler } from './tools/dynamic-deep-plan.js'
import { debugCdbPlanToolDefinition, createDebugCdbPlanHandler } from './tools/debug-cdb-plan.js'
import { debugProcDumpPlanToolDefinition, createDebugProcDumpPlanHandler } from './tools/debug-procdump-plan.js'
import { debugTelemetryPlanToolDefinition, createDebugTelemetryPlanHandler } from './tools/debug-telemetry-plan.js'
import { debugNetworkPlanToolDefinition, createDebugNetworkPlanHandler } from './tools/debug-network-plan.js'
import { debugManagedPlanToolDefinition, createDebugManagedPlanHandler } from './tools/debug-managed-plan.js'
import { debugGuiHandoffToolDefinition, createDebugGuiHandoffHandler } from './tools/debug-gui-handoff.js'
import { dynamicPersonaPlanToolDefinition, createDynamicPersonaPlanHandler } from './tools/dynamic-persona-plan.js'
import { dynamicBehaviorDiffToolDefinition, createDynamicBehaviorDiffHandler } from './tools/dynamic-behavior-diff.js'

const dynamicPlugin: Plugin = {
  id: 'dynamic',
  name: 'Dynamic Analysis Automation',
  executionDomain: 'dynamic',
  surfaceRules: { tier: 3, category: 'dynamic-analysis' },
  description: 'Automated Frida hooking, trace attribution, memory dumping, behavior capture, behavior diffing, dependency analysis, trace/memory import, sandbox execution, explicit runtime debug sessions, Hyper-V control, runtime toolkit inventory, runtime persona planning, CDB, ProcDump, telemetry, network lab, managed runtime, GUI handoff planning, deep dynamic planning, and dynamic runtime status aggregation',
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
    server.registerTool(runtimeDebugSessionStartToolDefinition, createRuntimeDebugSessionStartHandler(deps))
    server.registerTool(runtimeDebugSessionStatusToolDefinition, createRuntimeDebugSessionStatusHandler(deps))
    server.registerTool(runtimeDebugSessionStopToolDefinition, createRuntimeDebugSessionStopHandler(deps))
    server.registerTool(runtimeDebugCommandToolDefinition, createRuntimeDebugCommandHandler(deps))
    server.registerTool(dynamicRuntimeStatusToolDefinition, createDynamicRuntimeStatusHandler(deps))
    server.registerTool(dynamicBehaviorCaptureToolDefinition, createDynamicBehaviorCaptureHandler(deps))
    server.registerTool(runtimeHyperVControlToolDefinition, createRuntimeHyperVControlHandler(deps))
    server.registerTool(dynamicToolkitStatusToolDefinition, createDynamicToolkitStatusHandler(deps))
    server.registerTool(dynamicDeepPlanToolDefinition, createDynamicDeepPlanHandler(deps))
    server.registerTool(debugCdbPlanToolDefinition, createDebugCdbPlanHandler(deps))
    server.registerTool(debugProcDumpPlanToolDefinition, createDebugProcDumpPlanHandler(deps))
    server.registerTool(debugTelemetryPlanToolDefinition, createDebugTelemetryPlanHandler(deps))
    server.registerTool(debugNetworkPlanToolDefinition, createDebugNetworkPlanHandler(deps))
    server.registerTool(debugManagedPlanToolDefinition, createDebugManagedPlanHandler(deps))
    server.registerTool(debugGuiHandoffToolDefinition, createDebugGuiHandoffHandler(deps))
    server.registerTool(dynamicPersonaPlanToolDefinition, createDynamicPersonaPlanHandler(deps))
    server.registerTool(dynamicBehaviorDiffToolDefinition, createDynamicBehaviorDiffHandler(deps))
    return [
      'dynamic.auto_hook', 'dynamic.trace_attribute', 'dynamic.memory_dump',
      'dynamic.dependencies', 'dynamic.trace.import', 'dynamic.memory.import',
      'sandbox.execute', 'runtime.debug.session.start', 'runtime.debug.session.status',
      'runtime.debug.session.stop', 'runtime.debug.command', 'dynamic.runtime.status',
      'dynamic.behavior.capture', 'runtime.hyperv.control', 'dynamic.toolkit.status',
      'dynamic.deep_plan', 'debug.cdb.plan', 'debug.procdump.plan', 'debug.telemetry.plan',
      'debug.network.plan', 'debug.managed.plan', 'debug.gui.handoff',
      'dynamic.persona.plan', 'dynamic.behavior.diff',
    ]
  },
}

export default dynamicPlugin
