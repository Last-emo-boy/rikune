/**
 * Windows Installer Plugin
 *
 * Passive inventory for MSI/MSIX/APPX/CAB/NSIS/Inno containers. It never
 * installs packages, executes custom actions, or runs extracted payloads.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createWindowsInstallerInventoryHandler,
  windowsInstallerInventoryToolDefinition,
} from './tools/windows-installer-inventory.js'

const windowsInstallerPlugin = definePlugin({
  id: 'windows-installer',
  name: 'Windows Installer Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['msi', 'msix', 'appx', 'cab', 'nsis', 'inno', 'installer'],
    platforms: ['windows'],
    architectures: ['x86', 'x64', 'arm64', 'arm'],
    execution: ['static', 'triage'],
    safety: ['passive', 'no_installer_execution', 'no_live_sample_by_default'],
    capabilities: ['inventory', 'custom-actions', 'scripts', 'nested-binaries', 'routing'],
    evidence: ['filesystem', 'registry', 'nested-binaries', 'package-metadata', 'provenance'],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['msi', 'msix', 'appx', 'cab', 'nsis', 'inno', 'installer', 'windows'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive Windows installer inventory for MSI, MSIX, APPX, CAB, NSIS, and Inno without installer execution.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...windowsInstallerInventoryToolDefinition,
      handler: (args, deps) => createWindowsInstallerInventoryHandler(deps)(args as never),
    }),
  ],
})

export default windowsInstallerPlugin
