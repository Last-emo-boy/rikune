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
