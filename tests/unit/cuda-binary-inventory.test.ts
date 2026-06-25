import { describe, expect, test } from '@jest/globals'

import cudaBinaryPlugin from '../../src/plugins/cuda-binary/index.js'
import {
  CUDA_BINARY_INVENTORY_ARTIFACT_TYPE,
  CUDA_KERNEL_SUMMARY_ARTIFACT_TYPE,
  buildCudaBinaryInventoryFromBuffer,
  cudaBinaryInventoryToolDefinition,
} from '../../src/plugins/cuda-binary/tools/cuda-binary-inventory.js'

function elfFixture(type: number, machine = 190): Buffer {
  const data = Buffer.alloc(128)
  data[0] = 0x7f
  data[1] = 0x45
  data[2] = 0x4c
  data[3] = 0x46
  data[4] = 2
  data[5] = 1
  data[6] = 1
  data.writeUInt16LE(type, 16)
  data.writeUInt16LE(machine, 18)
  return data
}

describe('cuda.binary.inventory', () => {
  test('extracts PTX directives and kernel hints without CUDA tooling', () => {
    const ptx = Buffer.from(
      [
        '.version 8.1',
        '.target sm_90, texmode_independent',
        '.address_size 64',
        '.visible .entry _Z10vector_addPi(',
        '  .param .u64 _Z10vector_addPi_param_0',
        ') {',
        '  ret;',
        '}',
      ].join('\n'),
      'utf8'
    )

    const inventory = buildCudaBinaryInventoryFromBuffer(ptx, {
      filename: 'vector_add.ptx',
      sampleId: 'sha256:cuda-ptx',
    })

    expect(inventory.format).toBe('ptx')
    expect(inventory.is_cuda_candidate).toBe(true)
    expect(inventory.ptx_versions).toEqual(['8.1'])
    expect(inventory.address_sizes).toEqual([64])
    expect(inventory.target_arches).toEqual(
      expect.arrayContaining([expect.objectContaining({ kind: 'sm', value: 'sm_90' })])
    )
    expect(inventory.kernels).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: '_Z10vector_addPi', sources: ['ptx-entry'] }),
      ])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_cuda_driver: true,
        no_gpu_access: true,
        no_external_tool: true,
        no_network: true,
      })
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['culifter.gpu.plan', 'culifter.gpu.artifact.inventory'])
    )
    expect(inventory.recommended_next_tools).not.toContain('dynamic.runtime.status')
    expect(inventory.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.cuda_binary_inventory.evidence_summary.v1',
        source_tool: 'cuda.binary.inventory',
        sample_id: 'sha256:cuda-ptx',
        artifact_type: CUDA_BINARY_INVENTORY_ARTIFACT_TYPE,
        format: 'ptx',
        static_only: true,
      })
    )
    expect(inventory.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.cuda_binary_inventory.workflow_handoff.v1',
        handoff_mode: 'cuda_binary_inventory_to_gpu_lift_and_host_correlation',
        recommended_next_tools: expect.arrayContaining(['culifter.gpu.plan']),
      })
    )
    expect(inventory.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_execution_allowed: false,
        cuda_driver_allowed: false,
        gpu_access_allowed: false,
        external_tool_allowed: false,
        sample_executed_by_tool: false,
        cuda_driver_used_by_tool: false,
        gpu_accessed_by_tool: false,
        external_tool_started_by_tool: false,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.cuda_binary_inventory.quality_gates.v1',
        passive_static_inventory: true,
        bounded_preview_only: true,
        cuda_candidate_detected: true,
        kernel_hints_present: true,
        target_arches_present: true,
        sample_executed_by_tool: false,
        cuda_driver_used_by_tool: false,
        external_tool_started_by_tool: false,
      })
    )
  })

  test('detects CUBIN ELF, CUDA sections, and SASS hints statically', () => {
    const cubin = Buffer.concat([
      elfFixture(1, 190),
      Buffer.from(
        '\0.text._Z6kernelPi\0.nv.info._Z6kernelPi\0.nv.constant0._Z6kernelPi\0sm_80\0S2R IMAD LDG.E EXIT\0',
        'latin1'
      ),
    ])

    const inventory = buildCudaBinaryInventoryFromBuffer(cubin, { filename: 'kernel.cubin' })

    expect(inventory.format).toBe('cubin-elf')
    expect(inventory.elf).toEqual(
      expect.objectContaining({ is_elf: true, machine: 'cuda', machine_id: 190 })
    )
    expect(inventory.sections).toEqual(
      expect.arrayContaining([
        '.text._Z6kernelPi',
        '.nv.info._Z6kernelPi',
        '.nv.constant0._Z6kernelPi',
      ])
    )
    expect(inventory.kernels).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: '_Z6kernelPi',
          sources: expect.arrayContaining(['elf-section', 'nv-section']),
        }),
      ])
    )
    expect(inventory.sass_hints).toEqual(expect.arrayContaining(['S2R', 'IMAD', 'LDG.E', 'EXIT']))
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['native.object.inventory', 'linux.binary.inventory'])
    )
  })

  test('routes host-embedded CUDA registration markers without reclassifying host bytes as runtime work', () => {
    const host = Buffer.from(
      'MZ host executable preview __cudaRegisterFatBinary __cudaRegisterFunction sm_86 .text._Z9gpu_entryv',
      'latin1'
    )

    const inventory = buildCudaBinaryInventoryFromBuffer(host, { filename: 'host.exe' })

    expect(inventory.format).toBe('host-binary-cuda')
    expect(inventory.detected_by).toEqual(
      expect.arrayContaining(['CUDA host registration markers', 'GPU kernel/function hints'])
    )
    expect(inventory.host_registration_markers).toEqual(
      expect.arrayContaining(['__cudaRegisterFatBinary', '__cudaRegisterFunction'])
    )
    expect(inventory.kernels).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: '_Z9gpu_entryv' })])
    )
    expect(inventory.risk_notes.join('\n')).toContain('embedded fatbins')
    expect(inventory.workflow_handoff.routing).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          goal: 'host-device-correlation',
          next_tools: expect.arrayContaining(['native.object.inventory']),
        }),
      ])
    )
  })

  test('declares passive metadata, workflow, and discovery surface contract', () => {
    expect(cudaBinaryPlugin.executionDomain).toBe('static')
    expect(cudaBinaryPlugin.runtimePolicy).toBeUndefined()
    expect(cudaBinaryPlugin.surfaceRules?.tier).toBe(2)
    expect(cudaBinaryPlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining(['ptx', 'cubin', 'fatbin', 'cuda-fatbin'])
    )
    expect(cudaBinaryPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'cuda-artifact-inventory',
        'ptx-directive-extraction',
        'cubin-elf-detection',
        'culifter-handoff',
      ])
    )
    expect(cudaBinaryInventoryToolDefinition.artifacts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: CUDA_BINARY_INVENTORY_ARTIFACT_TYPE }),
        expect.objectContaining({ type: CUDA_KERNEL_SUMMARY_ARTIFACT_TYPE }),
      ])
    )
    expect(cudaBinaryInventoryToolDefinition.evidence?.map((entry) => entry.category)).toEqual(
      expect.arrayContaining(['structure', 'symbols', 'strings', 'workflow', 'provenance'])
    )
    expect(cudaBinaryInventoryToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'cuda.binary.static-inventory-handoff',
        startsWith: ['cuda.binary.inventory'],
        nextTools: expect.arrayContaining([
          'culifter.gpu.plan',
          'culifter.gpu.artifact.inventory',
          'native.object.inventory',
          'linux.binary.inventory',
        ]),
        producesArtifacts: [CUDA_BINARY_INVENTORY_ARTIFACT_TYPE, CUDA_KERNEL_SUMMARY_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_cuda_driver',
          'no_gpu_access',
          'no_external_tool',
        ]),
      })
    )
  })
})
