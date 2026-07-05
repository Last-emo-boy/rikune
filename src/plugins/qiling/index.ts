/**
 * Qiling Plugin
 *
 * Qiling emulation framework for cross-platform binary emulation.
 */

import type { Plugin } from '../sdk.js'
import {
  QILING_INSPECT_ARCHITECTURES,
  QILING_INSPECT_CAPABILITIES,
  QILING_INSPECT_EVIDENCE,
  QILING_INSPECT_FORMATS,
  QILING_INSPECT_PLATFORMS,
  QILING_INSPECT_RUNTIME_POLICY,
  QILING_INSPECT_SAFETY,
} from './qiling-metadata.js'
import { qilingInspectToolDefinition, createQilingInspectHandler } from './tools/qiling-inspect.js'

const qilingPlugin: Plugin = {
  id: 'qiling',
  name: 'Qiling',
  executionDomain: 'dynamic',
  aspects: {
    formats: QILING_INSPECT_FORMATS,
    platforms: QILING_INSPECT_PLATFORMS,
    architectures: QILING_INSPECT_ARCHITECTURES,
    execution: ['dynamic', 'emulation', 'triage'],
    runtimes: ['qiling', 'unicorn'],
    safety: QILING_INSPECT_SAFETY,
    capabilities: QILING_INSPECT_CAPABILITIES,
    evidence: QILING_INSPECT_EVIDENCE,
  },
  runtimePolicy: QILING_INSPECT_RUNTIME_POLICY,
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
