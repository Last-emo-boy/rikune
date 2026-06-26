/**
 * Kernel Driver Surface Plugin
 *
 * Passive Windows/Linux kernel driver attack-surface inventory. It reads
 * bounded bytes only and never loads a driver, inserts a kernel module, opens a
 * device object, sends IOCTLs, calls syscalls, or starts runtime telemetry.
 */

import { definePlugin, defineTool } from '../sdk.js'
import {
  createKernelDriverSurfaceInventoryHandler,
  kernelDriverSurfaceInventoryAspects,
  kernelDriverSurfaceInventoryToolDefinition,
} from './tools/kernel-driver-surface-inventory.js'

const kernelDriverSurfacePlugin = definePlugin({
  id: 'kernel-driver-surface',
  name: 'Kernel Driver Surface Inventory',
  executionDomain: 'static',
  aspects: kernelDriverSurfaceInventoryAspects,
  surfaceRules: {
    tier: 1,
    activateOn: {
      fileTypes: [
        'kernel-driver',
        'windows-driver',
        'windows-kernel-driver',
        'linux-kernel-module',
        'linux-driver',
        'driver',
        'ioctl',
        'wdm',
        'kmdf',
        'sys',
        'pe',
        'pe32',
        'pe64',
        'elf',
        'elf-object',
      ],
      findings: [
        'IRP_MJ_DEVICE_CONTROL',
        'DeviceIoControl',
        'CTL_CODE',
        'METHOD_NEITHER',
        'IoCreateDevice',
        'IoCreateSymbolicLink',
        'WdfDriverCreate',
        'unlocked_ioctl',
        'compat_ioctl',
        'copy_from_user',
        'vermagic=',
        'linux-kernel-module',
      ],
    },
    category: 'static-analysis',
  },
  description:
    'Passive kernel driver surface inventory for Windows .sys and Linux .ko artifacts, including IOCTL constants, device interfaces, dispatch hints, module metadata, and risky primitive handoff.',
  version: '1.0.0',
  tools: [
    defineTool({
      ...kernelDriverSurfaceInventoryToolDefinition,
      handler: (args, deps) => createKernelDriverSurfaceInventoryHandler(deps)(args as never),
    }),
  ],
})

export default kernelDriverSurfacePlugin
