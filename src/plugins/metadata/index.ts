/**
 * Metadata Plugin
 *
 * Universal file metadata extraction using exiftool.
 */

import { definePlugin, defineTool, requireDatabase, requireWorkspaceManager } from '../sdk.js'
import {
  metadataExtractToolDefinition,
  createMetadataExtractHandler,
} from './tools/metadata-extract.js'

const metadataPlugin = definePlugin({
  id: 'metadata',
  name: 'File Metadata',
  executionDomain: 'static',
  aspects: {
    formats: [
      'pe',
      'coff',
      'pdb',
      'elf',
      'elf-object',
      'linux-kernel-module',
      'macho',
      'macho-object',
      'dsym',
      'apk',
      'ipa',
      'dmg',
      'pkg',
      'deb',
      'rpm',
      'appimage',
      'jar',
      'wasm',
      'firmware',
      'archive',
      'container',
      'office',
      'pdf',
    ],
    platforms: ['windows', 'linux', 'macos', 'ios', 'android', 'cross-platform'],
    execution: ['static', 'triage'],
    safety: ['passive'],
    capabilities: ['metadata', 'package-metadata', 'manifest', 'routing'],
    evidence: ['package-metadata', 'manifest', 'provenance'],
  },
  surfaceRules: { tier: 0, category: 'static-analysis' },
  description:
    'Universal file metadata extraction using exiftool (works on PE, Office, PDF, images, and more)',
  version: '1.0.0',
  configSchema: [
    {
      envVar: 'EXIFTOOL_PATH',
      description: 'Path to exiftool binary',
      required: false,
      defaultValue: 'exiftool',
    },
  ],
  systemDeps: [
    {
      type: 'binary',
      name: 'exiftool',
      target: '$EXIFTOOL_PATH',
      envVar: 'EXIFTOOL_PATH',
      dockerDefault: '/usr/bin/exiftool',
      versionFlag: '-ver',
      required: false,
      description: 'ExifTool — universal file metadata reader',
      dockerInstall: 'apt-get install -y libimage-exiftool-perl',
      aptPackages: ['libimage-exiftool-perl'],
      dockerValidation: ['exiftool -ver >/dev/null 2>&1'],
    },
  ],
  tools: [
    defineTool({
      ...metadataExtractToolDefinition,
      handler: (args, deps) =>
        createMetadataExtractHandler(
          requireWorkspaceManager(deps, 'metadata.extract'),
          requireDatabase(deps, 'metadata.extract')
        )(args),
    }),
  ],
})

export default metadataPlugin
