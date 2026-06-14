/**
 * Linux Package Plugin
 *
 * Passive inventory for Linux package containers. It never installs packages,
 * executes maintainer scripts, mounts filesystems, or runs package payloads.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createLinuxPackageInventoryHandler,
  linuxPackageInventoryToolDefinition,
} from './tools/linux-package-inventory.js'

const linuxPackagePlugin = definePlugin({
  id: 'linux-package',
  name: 'Linux Package Inventory',
  executionDomain: 'static',
  aspects: {
    formats: ['deb', 'rpm', 'apk-alpine', 'snap', 'flatpak', 'appimage'],
    platforms: ['linux'],
    architectures: ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv'],
    execution: ['static', 'triage'],
    safety: [
      'passive',
      'no_install',
      'no_script_execution',
      'no_installer_execution',
      'no_auto_mount',
      'no_live_sample_by_default',
    ],
    capabilities: [
      'inventory',
      'package-metadata',
      'scripts',
      'nested-binaries',
      'routing',
      'workflow-plan',
      'metadata-only-handoff',
      'supply-chain-handoff',
      'firmware-handoff',
    ],
    evidence: [
      'workflow',
      'provenance',
      'package-metadata',
      'nested-binaries',
      'filesystem',
      'sbom',
    ],
  },
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: ['deb', 'rpm', 'apk-alpine', 'snap', 'flatpak', 'appimage', 'package'],
    },
    category: 'static-analysis',
  },
  description:
    'Passive Linux package inventory for deb, rpm, Alpine apk, snap, flatpak, and AppImage without executing installers or payloads.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...linuxPackageInventoryToolDefinition,
      handler: (args, deps) => createLinuxPackageInventoryHandler(deps)(args as never),
    }),
  ],
})

export default linuxPackagePlugin
