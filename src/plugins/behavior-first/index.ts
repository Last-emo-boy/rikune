/**
 * Behavior-First Analysis Plugin
 *
 * Comprehensive behavioral capture and analysis for binaries that resist
 * all static analysis and unpacking attempts.
 * Monitors file I/O, registry, network, process creation via Frida instrumentation.
 * Docker-priority: requires Frida + Wine for Windows binaries.
 */

import type { Plugin } from '../sdk.js'
import { behaviorCaptureToolDefinition, createBehaviorCaptureHandler } from './tools/behavior-capture.js'
import { behaviorIocToolDefinition, createBehaviorIocHandler } from './tools/behavior-ioc.js'
import { behaviorNetworkToolDefinition, createBehaviorNetworkHandler } from './tools/behavior-network.js'

const behaviorFirstPlugin: Plugin = {
  id: 'behavior-first',
  name: 'Behavior-First Analysis',
  executionDomain: 'dynamic',
  surfaceRules: { tier: 2, activateOn: { findings: ['c2', 'suspicious_imports', 'anti_debug'] }, category: 'dynamic-analysis' },
  description:
    'Behavioral-first analysis for opaque binaries: full behavioral capture ' +
    '(file/registry/network/process monitoring), IOC extraction, and network ' +
    'traffic analysis with C2 detection. Use when all other analysis approaches fail.',
  version: '1.0.0',
  configSchema: [
    { envVar: 'BEHAVIOR_TIMEOUT', description: 'Default behavioral capture timeout in seconds', required: false, defaultValue: '60' },
  ],
  systemDeps: [
    {
      type: 'binary', name: 'frida', versionFlag: '--version',
      envVar: 'FRIDA_PATH', required: true,
      description: 'Frida dynamic instrumentation for behavioral monitoring',
      dockerInstall: 'pip install frida frida-tools',
      dockerFeature: 'frida',
      dockerValidation: ['frida-ps --help >/dev/null 2>&1'],
    },
    {
      type: 'binary', name: 'wine', versionFlag: '--version', required: false,
      description: 'Wine for Windows binary execution on Linux',
      dockerFeature: 'wine',
      dockerValidation: ['wine --version'],
    },
  ],
  resources: { workers: 'workers' },
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(behaviorCaptureToolDefinition, createBehaviorCaptureHandler(wm, db))
    server.registerTool(behaviorIocToolDefinition, createBehaviorIocHandler(wm, db))
    server.registerTool(behaviorNetworkToolDefinition, createBehaviorNetworkHandler(wm, db))
    return ['behavior.capture', 'behavior.ioc', 'behavior.network']
  },
}

export default behaviorFirstPlugin
