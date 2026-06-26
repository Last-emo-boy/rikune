/**
 * UEFI/SMM Surface Plugin
 *
 * Passive UEFI firmware and SMM trust-boundary inventory. It reads bounded
 * bytes only and never boots firmware, triggers SMI, executes SMM code, writes
 * EFI variables, applies capsules, touches SPI flash/MMIO/MSR, invokes external
 * firmware tools, or mutates samples.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createUefiSmmSurfaceInventoryHandler,
  uefiSmmSurfaceInventoryAspects,
  uefiSmmSurfaceInventoryToolDefinition,
} from './tools/uefi-smm-surface-inventory.js'

const uefiSmmSurfacePlugin = definePlugin({
  id: 'uefi-smm-surface',
  name: 'UEFI/SMM Surface Inventory',
  executionDomain: 'static',
  aspects: uefiSmmSurfaceInventoryAspects,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'uefi',
        'efi',
        'uefi-firmware',
        'uefi-module',
        'uefi-smm',
        'smm',
        'smi',
        'te',
        'firmware-volume',
        'uefi-capsule',
        'dxe',
        'pei',
        'nvram',
        'fd',
        'rom',
        'cap',
      ],
      findings: [
        '_FVH',
        'SmiHandlerRegister',
        'EFI_SMM_SW_DISPATCH2_PROTOCOL',
        'EFI_MM_SW_DISPATCH_PROTOCOL',
        'EFI_SMM_COMMUNICATION_PROTOCOL',
        'EFI_MM_COMMUNICATION_PROTOCOL',
        'CommBuffer',
        'SMRAM',
        'SmmIsBufferOutsideSmmValid',
        'SmmCopyMemToSmram',
        'BootServices',
        'RuntimeServices',
        'SetVariable',
        'SecureBoot',
        'UpdateCapsule',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive UEFI/SMM firmware trust-boundary inventory for SMI handlers, communication buffers, protocol/service references, NVRAM variable surface, flash/capsule/MMIO/MSR primitives, and static follow-up routing.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...uefiSmmSurfaceInventoryToolDefinition,
      handler: (args, deps) => createUefiSmmSurfaceInventoryHandler(deps)(args as never),
    }),
  ],
})

export default uefiSmmSurfacePlugin
