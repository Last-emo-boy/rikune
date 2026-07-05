/**
 * Binary Diff Plugin
 *
 * Binary comparison and diff summary generation.
 */

import { defineTool, type Plugin } from '../sdk.js'
import { BINARY_DIFF_ASPECTS } from './binary-diff-metadata.js'
import { binaryDiffToolDefinition, createBinaryDiffHandler } from './tools/binary-diff.js'
import {
  binaryDiffSummaryToolDefinition,
  createBinaryDiffSummaryHandler,
} from './tools/binary-diff-summary.js'

const binaryDiffPlugin: Plugin = {
  id: 'binary-diff',
  name: 'Binary Diff',
  executionDomain: 'static',
  aspects: BINARY_DIFF_ASPECTS,
  surfaceRules: {
    tier: 2,
    activateOn: {
      fileTypes: ['pe', 'exe', 'dll', 'elf', 'macho', 'dotnet', 'native-binary'],
      findings: [
        'packed',
        'variant-comparison',
        'binary-diff',
        'function-comparison',
        'structural-delta',
        'radiff2-readiness',
      ],
    },
    category: 'reverse-engineering',
  },
  description:
    'Binary diff, variant comparison, function comparison, structural delta, similarity profile, radiff2 readiness, and evidence graph/report handoff.',
  version: '1.0.0',
  resources: { workers: 'workers' },
  configSchema: [
    {
      envVar: 'RADIFF2_PATH',
      description: 'Optional path to radiff2 for binary.diff function comparison.',
      required: false,
      defaultValue: 'radiff2',
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'radiff2',
      target: '$RADIFF2_PATH',
      envVar: 'RADIFF2_PATH',
      dockerDefault: '/opt/rizin/bin/radiff2',
      versionFlag: '-v',
      required: false,
      description: 'Optional radiff2 binary used by binary.diff for function-level comparison.',
      dockerInstall: 'Install Rizin/radiff2 from a pinned release or distro package.',
      dockerFeature: 'rizin',
      dockerValidation: ['radiff2 -v >/dev/null 2>&1'],
      dockerInstallRoute: 'profile-gated',
      dockerInstallProfile: 'optional',
    },
  ],
  tools: [
    defineTool({
      ...binaryDiffToolDefinition,
      handler: (args, deps) => createBinaryDiffHandler(deps.workspaceManager, deps.database)(args),
    }),
    defineTool({
      ...binaryDiffSummaryToolDefinition,
      handler: (args, deps) =>
        createBinaryDiffSummaryHandler(deps.workspaceManager, deps.database)(args),
    }),
  ],
  register(server, deps) {
    const { workspaceManager: wm, database: db } = deps

    server.registerTool(binaryDiffToolDefinition, createBinaryDiffHandler(wm, db))
    server.registerTool(binaryDiffSummaryToolDefinition, createBinaryDiffSummaryHandler(wm, db))

    return ['binary.diff', 'binary.diff.summary']
  },
}

export default binaryDiffPlugin
