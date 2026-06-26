import { describe, expect, test } from '@jest/globals'
import kernelDriverSurfacePlugin from '../../src/plugins/kernel-driver-surface/index.js'
import {
  KERNEL_DRIVER_SURFACE_ARTIFACT_TYPE,
  buildKernelDriverSurfaceInventoryFromBuffer,
  createKernelDriverSurfaceInventoryHandler,
  kernelDriverSurfaceInventoryToolDefinition,
} from '../../src/plugins/kernel-driver-surface/tools/kernel-driver-surface-inventory.js'

function ctlCode(deviceType: number, functionCode: number, method: number, access: number): number {
  return (deviceType << 16) | (access << 14) | (functionCode << 2) | method
}

describe('kernel.driver.surface.inventory', () => {
  test('declares passive kernel driver surface metadata', () => {
    expect(kernelDriverSurfacePlugin.id).toBe('kernel-driver-surface')
    expect(kernelDriverSurfacePlugin.executionDomain).toBe('static')
    expect(kernelDriverSurfacePlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining(['kernel-driver', 'windows-driver', 'linux-kernel-module', 'ioctl'])
    )
    expect(kernelDriverSurfaceInventoryToolDefinition.name).toBe('kernel.driver.surface.inventory')
    expect(
      kernelDriverSurfaceInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)
    ).toEqual(expect.arrayContaining([KERNEL_DRIVER_SURFACE_ARTIFACT_TYPE]))
    const recipe = kernelDriverSurfaceInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'kernel.driver-surface-static-inventory'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['kernel.driver.surface.inventory'],
        producesArtifacts: [KERNEL_DRIVER_SURFACE_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_driver_load',
          'no_kernel_module_load',
          'no_device_open',
          'no_ioctl_send',
        ]),
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining([
        'pe.structure.analyze',
        'linux.binary.inventory',
        'code.xrefs.analyze',
        'analysis.evidence.graph',
      ])
    )
  })

  test('summarizes Windows driver IOCTL candidates, device paths, and risky primitives', () => {
    const ioctl = Buffer.alloc(4)
    ioctl.writeUInt32LE(ctlCode(0x22, 0x801, 3, 0), 0)
    const inventory = buildKernelDriverSurfaceInventoryFromBuffer(
      Buffer.concat([
        Buffer.from('MZ\0DriverEntry\0IRP_MJ_DEVICE_CONTROL\0IoCreateDevice\0', 'ascii'),
        Buffer.from('IoCreateSymbolicLink\0\\\\.\\VulnDrv\0\\Device\\VulnDrv\0', 'ascii'),
        Buffer.from('METHOD_NEITHER\0FILE_ANY_ACCESS\0MmMapIoSpace\0ProbeForRead\0', 'ascii'),
        ioctl,
      ]),
      { filename: 'vulndrv.sys', sampleId: 'sha256:driver' }
    )

    expect(inventory.format).toBe('windows-kernel-driver-surface')
    expect(inventory.platform).toBe('windows-driver')
    expect((inventory.windows_surface as any).present).toBe(true)
    expect((inventory.windows_surface as any).ioctl_candidate_count).toBeGreaterThan(0)
    expect(inventory.ioctl_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: '0x00222007',
          method: 'METHOD_NEITHER',
          access: 'FILE_ANY_ACCESS',
          risk_flags: expect.arrayContaining(['method_neither', 'file_any_access']),
        }),
      ])
    )
    expect(inventory.device_interfaces).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ platform: 'windows', value: '\\\\.\\VulnDrv' }),
      ])
    )
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'windows.ioctl.method_neither', severity: 'high' }),
        expect.objectContaining({ id: 'windows.ioctl.file_any_access', severity: 'medium' }),
      ])
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        driver_loaded_by_tool: false,
        device_opened_by_tool: false,
        ioctl_sent_by_tool: false,
        external_tool_invoked_by_tool: false,
      })
    )
  })

  test('summarizes Linux module metadata, ioctl handlers, and user-copy risks', () => {
    const inventory = buildKernelDriverSurfaceInventoryFromBuffer(
      Buffer.from(
        [
          '\x7fELF',
          'vermagic=6.8.0 SMP preempt mod_unload',
          'license=Proprietary',
          'depends=usbcore',
          'name=vulnko',
          'parm=debug:int',
          'file_operations',
          'unlocked_ioctl',
          'compat_ioctl',
          'copy_from_user',
          'ioremap',
          '/dev/vulnko',
        ].join('\0'),
        'latin1'
      ),
      { filename: 'vulnko.ko', sampleId: 'sha256:ko' }
    )

    expect(inventory.format).toBe('linux-kernel-module-surface')
    expect(inventory.platform).toBe('linux-kernel-module')
    expect((inventory.linux_surface as any).present).toBe(true)
    expect((inventory.linux_surface as any).vermagic).toContain('6.8.0')
    expect((inventory.linux_surface as any).license).toBe('Proprietary')
    expect(inventory.module_metadata).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ key: 'vermagic' }),
        expect.objectContaining({ key: 'license', value: 'Proprietary' }),
      ])
    )
    expect(inventory.dispatch_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ platform: 'linux', kind: 'unlocked_ioctl' }),
      ])
    )
    expect(inventory.risky_primitives).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ platform: 'linux', id: 'linux.copy-from-user' }),
        expect.objectContaining({ platform: 'linux', id: 'linux.mmio-mapping' }),
      ])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_kernel_module_load: true,
        no_ioctl_send: true,
        no_syscall: true,
        no_kernel_probe: true,
      })
    )
  })

  test('handler degrades clearly when sample resolution is unavailable', async () => {
    const handler = createKernelDriverSurfaceInventoryHandler()
    const result = await handler({ sample_id: 'sha256:test' })

    expect(result.ok).toBe(false)
    expect(result.errors?.join(' ')).toContain('resolvePrimarySamplePath dependency is unavailable')
  })
})
