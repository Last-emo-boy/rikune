/**
 * Debug Session Plugin
 *
 * GDB/LLDB-backed interactive debugging: start, breakpoint, step,
 * continue, inspect (registers/memory/stack/disasm), and end sessions.
 */

import type { Plugin } from '../sdk.js'
import {
  debugSessionStartToolDefinition, createDebugSessionStartHandler,
} from './tools/debug-session-start.js'
import {
  debugSessionBreakpointToolDefinition, createDebugSessionBreakpointHandler,
} from './tools/debug-session-breakpoint.js'
import {
  debugSessionContinueToolDefinition, createDebugSessionContinueHandler,
} from './tools/debug-session-continue.js'
import {
  debugSessionStepToolDefinition, createDebugSessionStepHandler,
} from './tools/debug-session-step.js'
import {
  debugSessionInspectToolDefinition, createDebugSessionInspectHandler,
} from './tools/debug-session-inspect.js'
import {
  debugSessionEndToolDefinition, createDebugSessionEndHandler,
} from './tools/debug-session-end.js'
import {
  debugSessionSmartBreakpointToolDefinition, createDebugSessionSmartBreakpointHandler,
} from './tools/debug-session-smart-breakpoint.js'
import {
  debugSessionSnapshotToolDefinition, createDebugSessionSnapshotHandler,
} from './tools/debug-session-snapshot.js'
import {
  debugSessionWatchToolDefinition, createDebugSessionWatchHandler,
} from './tools/debug-session-watch.js'

const debugSessionPlugin: Plugin = {
  id: 'debug-session',
  name: 'Debug Session',
  surfaceRules: { tier: 3, category: 'dynamic-analysis' },
  description: 'Interactive debugging via GDB/LLDB — breakpoints, stepping, memory inspection',
  version: '1.0.0',
  systemDeps: [
    { type: 'binary', name: 'gdb', versionFlag: '--version', required: true, description: 'GNU Debugger', dockerDefault: '/usr/bin/gdb', dockerInstall: 'apt-get install -y gdb', dockerFeature: 'gdb', aptPackages: ['gdb', 'ltrace', 'strace'] },
  ],
  check() {
    try {
      const { execSync } = require('child_process')
      execSync('gdb --version', { stdio: 'ignore' })
      return true
    } catch {
      throw new Error('GDB not found in PATH. Install GDB (e.g. via MSYS2: pacman -S mingw-w64-x86_64-gdb) or add it to PATH.')
    }
  },
  register(server, deps) {
    server.registerTool(debugSessionStartToolDefinition, createDebugSessionStartHandler(deps))
    server.registerTool(debugSessionBreakpointToolDefinition, createDebugSessionBreakpointHandler(deps))
    server.registerTool(debugSessionContinueToolDefinition, createDebugSessionContinueHandler(deps))
    server.registerTool(debugSessionStepToolDefinition, createDebugSessionStepHandler(deps))
    server.registerTool(debugSessionInspectToolDefinition, createDebugSessionInspectHandler(deps))
    server.registerTool(debugSessionEndToolDefinition, createDebugSessionEndHandler(deps))
    server.registerTool(debugSessionSmartBreakpointToolDefinition, createDebugSessionSmartBreakpointHandler(deps))
    server.registerTool(debugSessionSnapshotToolDefinition, createDebugSessionSnapshotHandler(deps))
    server.registerTool(debugSessionWatchToolDefinition, createDebugSessionWatchHandler(deps))
    return [
      'debug.session.start', 'debug.session.breakpoint', 'debug.session.continue',
      'debug.session.step', 'debug.session.inspect', 'debug.session.end',
      'debug.session.smart_breakpoint', 'debug.session.snapshot', 'debug.session.watch',
    ]
  },
}

export default debugSessionPlugin
