/**
 * Qiling Plugin
 *
 * Qiling emulation framework for cross-platform binary emulation.
 */

import type { Plugin } from '../sdk.js'
import { qilingInspectToolDefinition, createQilingInspectHandler } from './tools/qiling-inspect.js'

const qilingPlugin: Plugin = {
  id: 'qiling',
  name: 'Qiling',
  executionDomain: 'dynamic',
  aspects: {
    formats: ['elf', 'elf-executable', 'so', 'pe', 'macho', 'shellcode', 'firmware'],
    platforms: ['linux', 'windows', 'macos', 'embedded'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'mipsel'],
    execution: ['dynamic', 'emulation'],
    runtimes: ['qiling', 'unicorn'],
    safety: ['passive', 'opt_in_dynamic', 'requires_isolation', 'no_live_sample_by_default'],
    capabilities: [
      'syscall-trace',
      'memory-map',
      'filesystem-hints',
      'network-hints',
      'unsupported-summary',
    ],
    evidence: ['syscalls', 'memory', 'filesystem', 'network', 'modules', 'timeline'],
  },
  runtimePolicy: {
    passiveByDefault: true,
    requiresUserOptIn: true,
    requiresIsolation: true,
    allowedBackends: ['qiling', 'unicorn'],
    maxRuntimeMs: 120000,
    networkPolicy: 'disabled',
    notes: [
      'Qiling inspection is emulation-backed and requires an explicit rootfs/backend selection before execution.',
      'Readiness checks must not run or emulate sample code by default.',
    ],
  },
  surfaceRules: { tier: 3, category: 'dynamic-analysis' },
  description: 'Qiling emulation framework for cross-platform binary emulation',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'QILING_PYTHON',
      description: 'Python binary with Qiling installed',
      required: false,
      defaultValue: '/opt/qiling-venv/bin/python',
    },
  ],
  systemDeps: [
    {
      type: 'python-venv',
      name: 'qiling',
      target: '$QILING_PYTHON',
      envVar: 'QILING_PYTHON',
      dockerDefault: '/opt/qiling-venv/bin/python',
      required: false,
      description: 'Qiling emulation framework (venv)',
      dockerInstall: 'python3 -m venv /opt/qiling-venv && pip install qiling',
      dockerFeature: 'qiling',
      dockerValidation: ['/opt/qiling-venv/bin/python -c "import qiling; print(\'✓ qiling\')"'],
      extraEnv: { QILING_ROOTFS: '/opt/qiling-rootfs' },
      directories: [{ path: '/opt/qiling-rootfs', chown: 'appuser:appuser' }],
      volumes: [
        {
          source: '${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/qiling-rootfs',
          target: '/opt/qiling-rootfs',
          mode: 'ro' as const,
        },
      ],
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(qilingInspectToolDefinition, createQilingInspectHandler(wm, db))
    return ['qiling.inspect']
  },
}

export default qilingPlugin
