import { describe, expect, test } from '@jest/globals'

import elfMachoPlugin from '../../src/plugins/elf-macho/index.js'
import {
  enrichElfExportsResult,
  enrichElfImportsResult,
  enrichElfStructureResult,
  enrichMachoStructureResult,
} from '../../src/plugins/elf-macho/elf-macho-metadata.js'
import { elfExportsExtractToolDefinition } from '../../src/plugins/elf-macho/tools/elf-exports-extract.js'
import { elfImportsExtractToolDefinition } from '../../src/plugins/elf-macho/tools/elf-imports-extract.js'
import { elfStructureAnalyzeToolDefinition } from '../../src/plugins/elf-macho/tools/elf-structure-analyze.js'
import { machoStructureAnalyzeToolDefinition } from '../../src/plugins/elf-macho/tools/macho-structure-analyze.js'

describe('elf-macho metadata deepening', () => {
  test('declares passive ELF/Mach-O plugin profile and runtime policy', () => {
    expect(elfMachoPlugin.aspects?.formats).toEqual(
      expect.arrayContaining([
        'elf',
        'elf-executable',
        'elf-so',
        'shared-library',
        'macho',
        'mach-o',
        'mach-o-fat',
        'mach-o-object',
      ])
    )
    expect(elfMachoPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'structure',
        'imports',
        'exports',
        'loader-metadata',
        'search-profile',
        'workflow-handoff',
      ])
    )
    expect(elfMachoPlugin.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_sample_execution',
        'no_runtime_start',
        'no_native_load',
      ])
    )
    expect(elfMachoPlugin.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        allowedBackends: ['local'],
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noSampleExecution: true,
        noRuntimeStart: true,
        noNativeLoad: true,
      })
    )
  })

  test('declares scoped recipes, JSON artifacts, evidence, and bundled worker policy', () => {
    const cases = [
      {
        definition: elfStructureAnalyzeToolDefinition,
        recipeId: 'elf.passive-structure-handoff',
        startsWith: ['elf.structure.analyze'],
        artifactType: 'elf_structure',
        evidence: ['structure', 'symbols', 'imports', 'exports', 'workflow', 'provenance'],
      },
      {
        definition: machoStructureAnalyzeToolDefinition,
        recipeId: 'macho.passive-structure-handoff',
        startsWith: ['macho.structure.analyze'],
        artifactType: 'macho_structure',
        evidence: ['structure', 'symbols', 'imports', 'exports', 'workflow', 'provenance'],
      },
      {
        definition: elfImportsExtractToolDefinition,
        recipeId: 'elf.imports.passive-handoff',
        startsWith: ['elf.imports.extract'],
        artifactType: 'elf_imports',
        evidence: ['imports', 'symbols', 'workflow', 'provenance'],
      },
      {
        definition: elfExportsExtractToolDefinition,
        recipeId: 'elf.exports.passive-handoff',
        startsWith: ['elf.exports.extract'],
        artifactType: 'elf_exports',
        evidence: ['exports', 'symbols', 'workflow', 'provenance'],
      },
    ]

    for (const item of cases) {
      const recipe = item.definition.workflowRecipes?.find(
        (candidate) => candidate.id === item.recipeId
      )

      expect(item.definition.artifacts).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            type: item.artifactType,
            mime: 'application/json',
            mimeTypes: expect.arrayContaining(['application/json']),
          }),
        ])
      )
      expect(item.definition.evidence?.map((entry) => entry.category)).toEqual(
        expect.arrayContaining(item.evidence)
      )
      expect(recipe).toEqual(
        expect.objectContaining({
          startsWith: item.startsWith,
          requiredArtifacts: expect.arrayContaining(['sample']),
          producesArtifacts: expect.arrayContaining([item.artifactType]),
          safety: expect.arrayContaining([
            'passive',
            'no_sample_execution',
            'no_runtime_start',
            'no_native_load',
          ]),
          runtimeBackends: expect.arrayContaining(['local']),
        })
      )
      expect(item.definition.runtimePolicy).toEqual(
        expect.objectContaining({
          passiveByDefault: true,
          networkPolicy: 'disabled',
          noSampleExecution: true,
          noRuntimeStart: true,
          noNativeLoad: true,
        })
      )
      expect(item.definition.workerBackend).toEqual(
        expect.objectContaining({
          backendKind: 'external',
          adapter: 'builtin.elf_macho.parser',
          availability: 'required',
          supportedModes: ['local'],
          defaultMode: 'local',
          inputArtifactTypes: ['sample'],
          outputArtifactTypes: [item.artifactType],
          policy: expect.objectContaining({
            passiveByDefault: true,
            noNetwork: true,
            noMutation: true,
            noLiveExecution: true,
          }),
          readiness: expect.objectContaining({
            doesNotStartBackend: true,
          }),
        })
      )
    }
  })

  test('enriches ELF and Mach-O structure results without execution or native loading', () => {
    const elf = enrichElfStructureResult(
      {
        ok: true,
        format: 'ELF',
        class: 64,
        endian: 'little',
        machine: 'EM_X86_64',
        sections: [{ name: '.text' }],
        segments: [{ type: 'PT_LOAD' }],
        symbols: [{ name: 'main', value: 4096 }],
        dynamic: [{ tag: 'DT_NEEDED', value: 'libc.so.6' }],
      },
      { sampleId: 'sha256:elf-demo' }
    )
    const macho = enrichMachoStructureResult(
      {
        ok: true,
        format: 'MachO',
        cputype: 'ARM64',
        filetype: 'MH_DYLIB',
        load_commands: [{ cmd: 'LC_LOAD_DYLIB' }],
        sections: [{ sectname: '__text' }],
        symbols: [{ name: '_main' }],
        is_fat: true,
        fat_architectures: [{ cputype: 'ARM64' }],
      },
      { sampleId: 'sha256:macho-demo' }
    )

    expect(elf.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.elf_structure.evidence_summary.v1',
        source_tool: 'elf.structure.analyze',
        artifact_type: 'elf_structure',
        sample_id: 'sha256:elf-demo',
        static_only: true,
        sample_executed_by_tool: false,
        native_library_loaded_by_tool: false,
      })
    )
    expect((elf.evidence_summary as any).counts).toEqual(
      expect.objectContaining({
        sections: 1,
        segments: 1,
        symbols: 1,
        dynamic_entries: 1,
      })
    )
    expect(elf.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.elf_structure.workflow_handoff.v1',
        recommended_next_tools: expect.arrayContaining([
          'elf.imports.extract',
          'elf.exports.extract',
          'linux.binary.inventory',
          'analysis.evidence.graph',
        ]),
      })
    )
    expect((elf.workflow_handoff as any).dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        runtime_started_by_tool: false,
        native_library_loaded_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(elf.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.elf_structure.quality_gates.v1',
        passive_static_analysis: true,
        dynamic_entries_present: true,
      })
    )

    expect(macho.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.macho_structure.evidence_summary.v1',
        source_tool: 'macho.structure.analyze',
        artifact_type: 'macho_structure',
        sample_id: 'sha256:macho-demo',
        is_fat: true,
        static_only: true,
      })
    )
    expect((macho.evidence_summary as any).counts).toEqual(
      expect.objectContaining({
        load_commands: 1,
        sections: 1,
        symbols: 1,
        fat_architectures: 1,
      })
    )
    expect(macho.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.macho_structure.workflow_handoff.v1',
        recommended_next_tools: expect.arrayContaining([
          'apple.container.inventory',
          'apple.signing.inspect',
          'analysis.evidence.graph',
        ]),
      })
    )
    expect(macho.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.macho_structure.quality_gates.v1',
        passive_static_analysis: true,
        universal_slices_present: true,
      })
    )
  })

  test('enriches ELF import/export handoffs for dependency and symbol routing', () => {
    const imports = enrichElfImportsResult(
      {
        needed_libraries: ['libc.so.6'],
        imported_symbols: [{ name: 'printf', type: 'STT_FUNC', bind: 'STB_GLOBAL' }],
        total_needed: 1,
        total_imported_symbols: 1,
      },
      { sampleId: 'sha256:elf-demo' }
    )
    const exports = enrichElfExportsResult(
      {
        exported_symbols: [{ name: 'plugin_entry', address: 4096, type: 'STT_FUNC' }],
        total_exports: 1,
      },
      { sampleId: 'sha256:elf-demo' }
    )

    expect(imports.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.elf_imports.evidence_summary.v1',
        source_tool: 'elf.imports.extract',
        artifact_type: 'elf_imports',
        sample_id: 'sha256:elf-demo',
        static_only: true,
      })
    )
    expect((imports.evidence_summary as any).counts).toEqual(
      expect.objectContaining({
        needed_libraries: 1,
        imported_symbols: 1,
      })
    )
    expect(imports.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.elf_imports.workflow_handoff.v1',
        recommended_next_tools: expect.arrayContaining([
          'linux.binary.inventory',
          'sbom.generate',
          'analysis.evidence.graph',
        ]),
      })
    )
    expect(imports.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.elf_imports.quality_gates.v1',
        needed_libraries_present: true,
        imported_symbols_present: true,
        native_library_loaded_by_tool: false,
      })
    )

    expect(exports.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.elf_exports.evidence_summary.v1',
        source_tool: 'elf.exports.extract',
        artifact_type: 'elf_exports',
        sample_id: 'sha256:elf-demo',
        static_only: true,
      })
    )
    expect((exports.evidence_summary as any).counts).toEqual(
      expect.objectContaining({
        exported_symbols: 1,
      })
    )
    expect(exports.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.elf_exports.workflow_handoff.v1',
        recommended_next_tools: expect.arrayContaining([
          'linux.binary.inventory',
          'analysis.evidence.graph',
          'artifact.read',
        ]),
      })
    )
    expect(exports.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.elf_exports.quality_gates.v1',
        exported_symbols_present: true,
        sample_executed_by_tool: false,
      })
    )
  })
})
