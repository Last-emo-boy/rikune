import { describe, expect, test } from '@jest/globals'
import jvmPlugin from '../../src/plugins/jvm/index.js'
import {
  buildJvmStructureFromBuffer,
  jvmStructureAnalyzeToolDefinition,
} from '../../src/plugins/jvm/tools/jvm-structure-analyze.js'

function localZip(entries: Array<{ name: string; content?: Buffer }>): Buffer {
  const chunks: Buffer[] = []
  for (const entry of entries) {
    const name = Buffer.from(entry.name)
    const content = entry.content ?? Buffer.alloc(0)
    const header = Buffer.alloc(30)
    header.writeUInt32LE(0x04034b50, 0)
    header.writeUInt16LE(0, 8)
    header.writeUInt32LE(content.length, 18)
    header.writeUInt32LE(content.length, 22)
    header.writeUInt16LE(name.length, 26)
    chunks.push(header, name, content)
  }
  return Buffer.concat(chunks)
}

describe('jvm.structure.analyze', () => {
  test('declares passive JVM route profile and workflow handoff metadata', () => {
    expect(jvmPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'dependency-hints',
        'nested-archive-routing',
        'metadata-only-handoff',
        'workflow-plan',
        'workflow-handoff',
      ])
    )
    expect(jvmPlugin.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'no_runtime_start', 'no_decompiler_launch'])
    )
    expect(jvmStructureAnalyzeToolDefinition.aspects?.evidence).toEqual(
      expect.arrayContaining(['classes', 'dependency-hints', 'workflow', 'provenance'])
    )
    expect(jvmStructureAnalyzeToolDefinition.evidence?.map((entry) => entry.category)).toEqual(
      expect.arrayContaining([
        'manifest',
        'package-metadata',
        'structure',
        'classes',
        'dependency-hints',
        'nested-binaries',
        'workflow',
        'provenance',
      ])
    )
    expect(jvmStructureAnalyzeToolDefinition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'jvm.passive-structure-handoff',
        startsWith: ['jvm.structure.analyze'],
        nextTools: expect.arrayContaining([
          'metadata.extract',
          'strings.extract',
          'sbom.generate',
          'analysis.evidence.graph',
          'report.generate',
        ]),
        producesArtifacts: ['jvm_structure'],
        safety: expect.arrayContaining(['passive', 'no_runtime_start', 'no_decompiler_launch']),
      })
    )
    expect(jvmStructureAnalyzeToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        requiresUserOptIn: false,
        networkPolicy: 'disabled',
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
        noRuntimeStart: true,
        noDecompilerLaunch: true,
      })
    )
  })

  test('extracts JAR manifest, class inventory, dependencies, and nested archives passively', () => {
    const inventory = buildJvmStructureFromBuffer(
      localZip([
        {
          name: 'META-INF/MANIFEST.MF',
          content: Buffer.from(
            'Manifest-Version: 1.0\nMain-Class: demo.Main\nClass-Path: lib/a.jar\n'
          ),
        },
        { name: 'demo/Main.class', content: Buffer.from([0xca, 0xfe, 0xba, 0xbe]) },
        { name: 'demo/internal/Helper.class', content: Buffer.from([0xca, 0xfe, 0xba, 0xbe]) },
        { name: 'META-INF/demo.kotlin_module' },
        { name: 'lib/nested.jar' },
      ]),
      { filename: 'demo.jar' }
    )

    expect(inventory.format).toBe('jar')
    expect(inventory.manifest).toEqual(
      expect.objectContaining({ 'Main-Class': 'demo.Main', 'Class-Path': 'lib/a.jar' })
    )
    expect(inventory.class_files).toEqual(
      expect.arrayContaining(['demo/Main.class', 'demo/internal/Helper.class'])
    )
    expect(inventory.packages).toEqual(expect.arrayContaining(['demo', 'demo.internal']))
    expect(inventory.dependency_hints).toEqual(
      expect.arrayContaining(['lib/a.jar', 'META-INF/demo.kotlin_module'])
    )
    expect(inventory.nested_archive_candidates).toContain('lib/nested.jar')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_runtime_start: true,
        no_decompiler_launch: true,
      })
    )
    expect(inventory.decompile_plan.status).toBe('plan_only')
    expect(inventory.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.jvm_structure.evidence_summary.v1',
        artifact_type: 'jvm_structure',
        format: 'jar',
        manifest_present: true,
        class_file_count: 2,
        dependency_hint_count: 3,
        nested_archive_count: 1,
        passive_inventory_only: true,
      })
    )
    expect(inventory.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.jvm_structure.workflow_handoff.v1',
        artifact_contract: expect.objectContaining({
          produced_artifact_type: 'jvm_structure',
          producer_tool: 'jvm.structure.analyze',
        }),
        dynamic_boundary: expect.objectContaining({
          sample_executed_by_tool: false,
          jvm_started_by_tool: false,
          decompiler_launched_by_tool: false,
          network_accessed_by_tool: false,
          mutation_performed: false,
        }),
      })
    )
    expect(inventory.workflow_handoff.routing.recommended_next_tools).toEqual(
      expect.arrayContaining(['analysis.evidence.graph', 'artifact.read', 'report.generate'])
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.jvm_structure.quality_gates.v1',
        passive_inventory_only: true,
        jvm_started_by_tool: false,
        decompiler_launched_by_tool: false,
        manifest_present: true,
        class_inventory_present: true,
        dependency_hints_present: true,
        nested_archive_candidates_present: true,
      })
    )
  })

  test('covers standalone CLASS and JVM archive family naming without executing bytecode', () => {
    const classInventory = buildJvmStructureFromBuffer(Buffer.from([0xca, 0xfe, 0xba, 0xbe]), {
      filename: 'Main.class',
    })
    const aarInventory = buildJvmStructureFromBuffer(localZip([{ name: 'classes.jar' }]), {
      filename: 'lib.aar',
    })
    const jmodInventory = buildJvmStructureFromBuffer(
      localZip([{ name: 'classes/module-info.class' }]),
      {
        filename: 'demo.jmod',
      }
    )

    expect(classInventory.format).toBe('class')
    expect(classInventory.class_files).toContain('Main.class')
    expect(aarInventory.format).toBe('aar')
    expect(jmodInventory.format).toBe('jmod')
    expect(
      [classInventory, aarInventory, jmodInventory].every((item) => item.policy.no_execute)
    ).toBe(true)
    expect(
      [classInventory, aarInventory, jmodInventory].every((item) => item.policy.no_runtime_start)
    ).toBe(true)
    expect(classInventory.quality_gates).toEqual(
      expect.objectContaining({
        standalone_class_limited_parse: true,
        jvm_started_by_tool: false,
        decompiler_launched_by_tool: false,
      })
    )
  })
})
