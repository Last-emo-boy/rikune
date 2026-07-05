import { describe, expect, test } from '@jest/globals'
import cppAbiLayoutPlugin from '../../src/plugins/cpp-abi-layout/index.js'
import {
  CPP_ABI_LAYOUT_ARTIFACT_TYPE,
  buildCppAbiLayoutInventoryFromBuffer,
  cppAbiLayoutInventoryToolDefinition,
  createCppAbiLayoutInventoryHandler,
} from '../../src/plugins/cpp-abi-layout/tools/cpp-abi-layout-inventory.js'

describe('cpp.abi.layout.inventory', () => {
  test('declares passive C++ ABI layout inventory metadata', () => {
    expect(cppAbiLayoutPlugin.id).toBe('cpp-abi-layout')
    expect(cppAbiLayoutPlugin.executionDomain).toBe('static')
    expect(cppAbiLayoutPlugin.surfaceRules?.activateOn?.fileTypes).toEqual(
      expect.arrayContaining(['cpp-abi', 'itanium-abi', 'msvc-abi', 'pe', 'elf', 'macho'])
    )
    expect(cppAbiLayoutInventoryToolDefinition.name).toBe('cpp.abi.layout.inventory')
    expect(cppAbiLayoutInventoryToolDefinition.artifacts?.map((artifact) => artifact.type)).toEqual(
      expect.arrayContaining([CPP_ABI_LAYOUT_ARTIFACT_TYPE])
    )
    const recipe = cppAbiLayoutInventoryToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'cpp.abi-layout-static-inventory'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['cpp.abi.layout.inventory'],
        producesArtifacts: [CPP_ABI_LAYOUT_ARTIFACT_TYPE],
        safety: expect.arrayContaining([
          'passive',
          'no_external_demangler',
          'no_native_load',
          'no_symbol_server_download',
          'no_source_fetch',
        ]),
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining([
        'native.object.inventory',
        'native.debug.types.inventory',
        'code.xrefs.analyze',
        'analysis.evidence.graph',
      ])
    )
  })

  test('summarizes Itanium vtables, typeinfo, thunks, and EH personality', () => {
    const inventory = buildCppAbiLayoutInventoryFromBuffer(
      Buffer.from(
        [
          '_ZTVN3foo3BarE',
          '_ZTIN3foo3BarE',
          '_ZTSN3foo3BarE',
          '_ZThn16_N3foo3Bar3bazEv',
          '__cxxabiv1::__class_type_info',
          '__cxa_pure_virtual',
          '__gxx_personality_v0',
          '.gcc_except_table',
        ].join('\0'),
        'utf8'
      ),
      { filename: 'libbar.so', sampleId: 'sha256:itanium' }
    )

    expect(inventory.format).toBe('itanium-cpp-abi')
    expect((inventory.abi_families as any).itanium).toEqual(
      expect.objectContaining({ present: true, confidence: 'high' })
    )
    expect(inventory.class_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          abi: 'itanium',
          class_name: 'foo::Bar',
          confidence: 'high',
        }),
      ])
    )
    expect(inventory.vtable_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          abi: 'itanium',
          kind: 'vtable',
          class_name: 'foo::Bar',
        }),
      ])
    )
    expect(inventory.rtti_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          abi: 'itanium',
          kind: 'typeinfo',
          class_name: 'foo::Bar',
        }),
      ])
    )
    expect((inventory.exception_profile as any).itanium).toEqual(
      expect.objectContaining({
        personality_present: true,
        throw_helper_present: false,
      })
    )
    expect((inventory.layout_seeds as any).multiple_inheritance_indicators).toEqual(
      expect.objectContaining({ present: true, itanium_adjustor_thunk_count: 1 })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        passive_static_inventory: true,
        sample_executed_by_tool: false,
        external_demangler_invoked_by_tool: false,
        external_tool_invoked_by_tool: false,
        network_used_by_tool: false,
      })
    )
  })

  test('summarizes MSVC vftables, RTTI descriptors, and C++ EH handlers', () => {
    const inventory = buildCppAbiLayoutInventoryFromBuffer(
      Buffer.from(
        [
          '??_7Widget@@6B@',
          '??_R0?AVWidget@@@8',
          '??_R4Widget@@6B@',
          '__RTTIClassHierarchyDescriptor',
          '__CxxFrameHandler3',
          'CxxThrowException',
          '__purecall',
          '.pdata',
          '.xdata',
        ].join('\0'),
        'utf8'
      ),
      { filename: 'widget.dll', sampleId: 'sha256:msvc' }
    )

    expect(inventory.format).toBe('msvc-cpp-abi')
    expect((inventory.abi_families as any).msvc).toEqual(
      expect.objectContaining({ present: true, confidence: 'high' })
    )
    expect(inventory.class_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          abi: 'msvc',
          class_name: 'Widget',
          confidence: 'high',
        }),
      ])
    )
    expect(inventory.vtable_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          abi: 'msvc',
          kind: 'vftable',
          class_name: 'Widget',
        }),
      ])
    )
    expect(inventory.rtti_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          abi: 'msvc',
          kind: 'type_descriptor',
          class_name: 'Widget',
        }),
        expect.objectContaining({
          abi: 'msvc',
          kind: 'complete_object_locator',
          class_name: 'Widget',
        }),
      ])
    )
    expect((inventory.exception_profile as any).msvc).toEqual(
      expect.objectContaining({
        frame_handler_present: true,
        throw_helper_present: true,
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_external_demangler: true,
        no_native_load: true,
        no_network: true,
      })
    )
  })

  test('handler degrades clearly when sample resolution is unavailable', async () => {
    const handler = createCppAbiLayoutInventoryHandler()
    const result = await handler({ sample_id: 'sha256:test' })

    expect(result.ok).toBe(false)
    expect(result.errors?.join(' ')).toContain('resolvePrimarySamplePath dependency is unavailable')
  })
})
