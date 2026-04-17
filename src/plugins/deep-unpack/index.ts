/**
 * Deep Unpack Plugin
 *
 * Multi-strategy deep unpacking pipeline for heavily packed/obfuscated binaries.
 * Supports unlimited multi-layer unpacking, PE reconstruction, and memory dump scanning.
 * Docker-priority: best results with all backends (UPX, Speakeasy, Qiling, Wine) available.
 */

import type { Plugin } from '../sdk.js'
import { deepUnpackPipelineToolDefinition, createDeepUnpackPipelineHandler } from './tools/deep-unpack-pipeline.js'
import { peReconstructToolDefinition, createPeReconstructHandler } from './tools/deep-unpack-pe-reconstruct.js'
import { dumpScanToolDefinition, createDumpScanHandler } from './tools/deep-unpack-dump-scan.js'

const deepUnpackPlugin: Plugin = {
  id: 'deep-unpack',
  name: 'Deep Unpack',
  executionDomain: 'static',
  surfaceRules: { tier: 2, activateOn: { findings: ['packed'] }, category: 'unpacking' },
  description:
    'Multi-strategy deep unpacking for heavily packed/obfuscated binaries. ' +
    'Tries UPX → Speakeasy → Qiling → memory carve in sequence, supports up to 10 layers, ' +
    'with PE reconstruction and IAT fixing. Docker-priority.',
  version: '1.0.0',
  dependencies: ['unpacking'],
  configSchema: [
    { envVar: 'DEEP_UNPACK_MAX_LAYERS', description: 'Default max unpacking layers (1-10)', required: false, defaultValue: '5' },
    { envVar: 'DEEP_UNPACK_TIMEOUT', description: 'Default per-strategy timeout in seconds', required: false, defaultValue: '120' },
  ],
  systemDeps: [
    {
      type: 'binary', name: 'upx', versionFlag: '--version', required: false,
      description: 'UPX packer/unpacker for UPX-compressed binaries',
      dockerFeature: 'upx',
      dockerValidation: ['upx --version | head -1'],
  
    },
    {
      type: 'python', name: 'speakeasy-emulator', importName: 'speakeasy', required: false,
      description: 'Speakeasy x86 Windows emulator for emulation-based unpacking',
      dockerInstall: 'pip install speakeasy-emulator',
    },
    {
      type: 'python-venv', name: 'qiling', target: '$QILING_PYTHON',
      envVar: 'QILING_PYTHON', dockerDefault: '/opt/qiling-venv/bin/python', required: false,
      description: 'Qiling full-system emulator for advanced unpacking',
      dockerFeature: 'qiling',
      dockerValidation: ['/opt/qiling-venv/bin/python -c "import qiling; print(qiling.__version__)"'],
    },
    {
      type: 'binary', name: 'wine', versionFlag: '--version', required: false,
      description: 'Wine for Windows binary execution on Linux (memory carve strategy)',
      dockerFeature: 'wine',
      dockerValidation: ['wine --version'],
    },
    {
      type: 'python', name: 'pefile', importName: 'pefile', required: true,
      description: 'PE file parser for PE reconstruction',
    },
  ],
  resources: { workers: 'workers' },
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps
    server.registerTool(deepUnpackPipelineToolDefinition, createDeepUnpackPipelineHandler(wm, db))
    server.registerTool(peReconstructToolDefinition, createPeReconstructHandler(wm, db))
    server.registerTool(dumpScanToolDefinition, createDumpScanHandler(wm, db))
    return ['deep.unpack.pipeline', 'deep.unpack.pe_reconstruct', 'deep.unpack.dump_scan']
  },
}

export default deepUnpackPlugin
