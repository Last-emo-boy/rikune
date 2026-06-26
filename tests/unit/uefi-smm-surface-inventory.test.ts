import { describe, expect, test } from '@jest/globals'
import uefiSmmSurfacePlugin from '../../src/plugins/uefi-smm-surface/index.js'
import {
  UEFI_SMM_SURFACE_ARTIFACT_TYPE,
  buildUefiSmmSurfaceInventoryFromBuffer,
  createUefiSmmSurfaceInventoryHandler,
  uefiSmmSurfaceInventoryToolDefinition,
} from '../../src/plugins/uefi-smm-surface/tools/uefi-smm-surface-inventory.js'

describe('uefi.smm.surface.inventory', () => {
  test('declares passive UEFI/SMM surface metadata', () => {
    expect(uefiSmmSurfacePlugin.id).toBe('uefi-smm-surface')
    expect(uefiSmmSurfacePlugin.executionDomain).toBe('static')
    expect(uefiSmmSurfacePlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining(['uefi', 'efi', 'uefi-smm', 'firmware-volume', 'uefi-capsule'])
    )
    expect(uefiSmmSurfaceInventoryToolDefinition.name).toBe('uefi.smm.surface.inventory')
    expect(
      uefiSmmSurfaceInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)
    ).toEqual(expect.arrayContaining([UEFI_SMM_SURFACE_ARTIFACT_TYPE]))
    const recipe = uefiSmmSurfaceInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'uefi.smm-surface-static-inventory'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['uefi.smm.surface.inventory'],
        producesArtifacts: [UEFI_SMM_SURFACE_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_smi_trigger',
          'no_smm_execution',
          'no_efi_variable_write',
          'no_capsule_apply',
          'no_mmio_or_msr_access',
        ]),
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining([
        'firmware.scan',
        'pe.structure.analyze',
        'code.xrefs.analyze',
        'analysis.evidence.graph',
      ])
    )
  })

  test('summarizes SMM handlers, communication buffers, services, variables, and primitives', () => {
    const inventory = buildUefiSmmSurfaceInventoryFromBuffer(
      Buffer.from(
        [
          'MZ',
          '_FVH',
          'SmiHandlerRegister',
          'EFI_SMM_SW_DISPATCH2_PROTOCOL',
          'EFI_SMM_COMMUNICATION_PROTOCOL',
          'CommBuffer',
          'SMRAM',
          'gBS',
          'BootServices',
          'LocateProtocol',
          'gRT',
          'RuntimeServices',
          'SetVariable',
          'SecureBoot',
          'MmioWrite32',
          'AsmWriteMsr64',
          'UpdateCapsule',
          '12345678-1234-1234-1234-123456789abc',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'SmmDriver.efi', sampleId: 'sha256:uefi' }
    )

    expect(inventory.format).toBe('uefi-firmware-volume-smm-surface')
    expect(inventory.platform).toBe('uefi-firmware')
    expect(inventory.confidence).toBe('high')
    expect((inventory.smm_surface as any).present).toBe(true)
    expect((inventory.smm_surface as any).communication_buffer_hint).toBe(true)
    expect((inventory.service_references as any).boot_services.present).toBe(true)
    expect((inventory.variable_surface as any).write_hint).toBe(true)
    expect((inventory.variable_surface as any).secure_boot_variable_hint).toBe(true)
    expect(inventory.guid_references).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ guid: '12345678-1234-1234-1234-123456789abc' }),
      ])
    )
    expect(inventory.low_level_primitives).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'uefi.mmio-or-io-primitive' }),
        expect.objectContaining({ id: 'uefi.msr-primitive' }),
        expect.objectContaining({ id: 'uefi.capsule-update-primitive' }),
      ])
    )
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'smm.callout.boot-services', severity: 'high' }),
        expect.objectContaining({
          id: 'smm.comm-buffer.validation-missing-hint',
          severity: 'high',
        }),
        expect.objectContaining({ id: 'uefi.variable-write', severity: 'medium' }),
      ])
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        smi_triggered_by_tool: false,
        efi_variable_written_by_tool: false,
        capsule_applied_by_tool: false,
        external_tool_invoked_by_tool: false,
      })
    )
  })

  test('does not flag missing validation when SMM copy helpers are present', () => {
    const inventory = buildUefiSmmSurfaceInventoryFromBuffer(
      Buffer.from(
        [
          'VZ',
          'SmiHandlerRegister',
          'EFI_MM_COMMUNICATION_PROTOCOL',
          'CommBuffer',
          'SmmIsBufferOutsideSmmValid',
          'SmmCopyMemToSmram',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'SafeSmm.te' }
    )

    expect(inventory.format).toBe('uefi-smm-module-surface')
    expect((inventory.smm_surface as any).buffer_validation_hint).toBe(true)
    expect(inventory.risk_flags).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'smm.comm-buffer.validation-missing-hint' }),
      ])
    )
  })

  test('handler degrades clearly when sample resolution is unavailable', async () => {
    const handler = createUefiSmmSurfaceInventoryHandler()
    const result = await handler({ sample_id: 'sha256:test' })

    expect(result.ok).toBe(false)
    expect(result.errors?.join(' ')).toContain('resolvePrimarySamplePath dependency is unavailable')
  })
})
