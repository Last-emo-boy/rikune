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
  description: 'Qiling emulation framework for cross-platform binary emulation',
  version: '1.0.0',
  configSchema: [
    { envVar: 'QILING_PYTHON', description: 'Python binary with Qiling installed', required: false, defaultValue: '/opt/qiling-venv/bin/python' },
  ],
  systemDeps: [
    {
      type: 'python-venv', name: 'qiling', target: '$QILING_PYTHON', envVar: 'QILING_PYTHON',
      dockerDefault: '/opt/qiling-venv/bin/python', required: false,
      description: 'Qiling emulation framework (venv)',
      dockerInstall: 'python3 -m venv /opt/qiling-venv && pip install qiling',
      dockerFeature: 'qiling',
      dockerValidation: ['/opt/qiling-venv/bin/python -c "import qiling; print(\'✓ qiling\')"'],
      extraEnv: { QILING_ROOTFS: '/opt/qiling-rootfs' },
      directories: [{ path: '/opt/qiling-rootfs', chown: 'appuser:appuser' }],
      volumes: [{ source: '${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/qiling-rootfs', target: '/opt/qiling-rootfs', mode: 'ro' as const }],
    },
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(qilingInspectToolDefinition, createQilingInspectHandler(wm, db))
    return ['qiling.inspect']
  },
}

export default qilingPlugin
