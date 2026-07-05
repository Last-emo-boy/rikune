import { describe, expect, test } from '@jest/globals'
import {
  buildContainerStructureFromBuffer,
  ContainerStructureAnalyzeOutputSchema,
  containerStructureAnalyzeToolDefinition,
} from '../../src/plugins/container-analysis/tools/container-structure-analyze.js'

function localZip(
  entries: Array<{ name: string; compressedSize?: number; uncompressedSize?: number }>
): Buffer {
  const chunks: Buffer[] = []
  for (const entry of entries) {
    const name = Buffer.from(entry.name)
    const compressedSize = entry.compressedSize ?? 0
    const uncompressedSize = entry.uncompressedSize ?? compressedSize
    const header = Buffer.alloc(30)
    header.writeUInt32LE(0x04034b50, 0)
    header.writeUInt32LE(compressedSize, 18)
    header.writeUInt32LE(uncompressedSize, 22)
    header.writeUInt16LE(name.length, 26)
    chunks.push(header, name, Buffer.alloc(compressedSize))
  }
  return Buffer.concat(chunks)
}

function tarFixture(entries: string[]): Buffer {
  const blocks: Buffer[] = []
  for (const entry of entries) {
    const header = Buffer.alloc(512)
    header.write(entry, 0, Math.min(Buffer.byteLength(entry), 100), 'utf8')
    header.write('0000644\0', 100, 'ascii')
    header.write('0000000\0', 108, 'ascii')
    header.write('0000000\0', 116, 'ascii')
    header.write('00000000000\0', 124, 'ascii')
    header.write('00000000000\0', 136, 'ascii')
    header[156] = entry.endsWith('/') ? 0x35 : 0x30
    header.write('ustar\0', 257, 'ascii')
    header.write('00', 263, 'ascii')
    header.fill(0x20, 148, 156)
    let checksum = 0
    for (const byte of header) checksum += byte
    header.write(checksum.toString(8).padStart(6, '0'), 148, 'ascii')
    header[154] = 0
    header[155] = 0x20
    blocks.push(header)
  }
  blocks.push(Buffer.alloc(1024))
  return Buffer.concat(blocks)
}

describe('container.structure.analyze', () => {
  test('declares passive workflow handoff metadata for search profile routing', () => {
    expect(containerStructureAnalyzeToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining(['workflow-plan', 'workflow-handoff', 'nested-binaries'])
    )
    expect(containerStructureAnalyzeToolDefinition.aspects?.evidence).toEqual(
      expect.arrayContaining(['nested-binaries', 'filesystem', 'package-metadata', 'workflow'])
    )
    expect(
      containerStructureAnalyzeToolDefinition.artifacts?.map((artifact) => artifact.type)
    ).toEqual(expect.arrayContaining(['container_structure']))
    expect(
      containerStructureAnalyzeToolDefinition.evidence?.map((evidence) => evidence.category)
    ).toEqual(expect.arrayContaining(['nested-binaries', 'filesystem']))

    const recipe = containerStructureAnalyzeToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'container.passive-structure-inventory'
    )
    expect(recipe).toBeDefined()
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['container.structure.analyze'],
        requiredArtifacts: ['sample'],
        producesArtifacts: ['container_structure'],
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining([
        'metadata.extract',
        'strings.extract',
        'pe.structure.analyze',
        'elf.structure.analyze',
        'macho.structure.analyze',
        'android.package.inventory',
        'apple.container.inventory',
        'firmware.workflow.plan',
        'sbom.provenance.graph',
        'analysis.evidence.graph',
        'report.generate',
      ])
    )
    expect(recipe?.evidence).toEqual(
      expect.arrayContaining(['nested-binaries', 'filesystem', 'package-metadata', 'workflow'])
    )
    expect(recipe?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_installer_execution',
        'no_auto_mount',
        'no_live_sample_by_default',
      ])
    )
  })

  test('flags zip traversal and compression risks while routing nested binaries', () => {
    const inventory = buildContainerStructureFromBuffer(
      localZip([
        { name: '../evil.exe', compressedSize: 1, uncompressedSize: 1000 },
        { name: 'lib/libdemo.so' },
        { name: 'Payload/App.app/Frameworks/libDemo.dylib' },
        { name: 'classes.dex' },
        { name: 'module.wasm' },
      ]),
      { filename: 'bundle.zip' }
    )

    expect(inventory.container_format).toBe('zip')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_extract_to_execution_path: true,
        no_mount: true,
        no_entrypoint_run: true,
      })
    )
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining(['path-traversal', 'high-compression-ratio'])
    )
    expect(inventory.container_profile).toEqual(
      expect.objectContaining({
        schema: 'rikune.container_structure.profile.v1',
        artifact_type: 'container_structure',
        container_format: 'zip',
        zip_bomb: expect.objectContaining({
          suspected: true,
          high_compression_entry_count: 1,
          review_required: true,
          representative_paths: expect.arrayContaining(['../evil.exe']),
        }),
        path_traversal: expect.objectContaining({
          present: true,
          traversal_entry_count: 1,
          review_required: true,
          representative_paths: expect.arrayContaining(['../evil.exe']),
        }),
        nested_routes: expect.objectContaining({
          candidate_count: 5,
          formats: expect.objectContaining({ pe: 1, wasm: 1 }),
          tools: expect.objectContaining({
            'pe.structure.analyze': 1,
            'wasm.structure.analyze': 1,
          }),
        }),
      })
    )
    expect(inventory.evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.container_structure.evidence_summary.v1',
        source_tool: 'container.structure.analyze',
        artifact_type: 'container_structure',
        container_format: 'zip',
        entry_count: 5,
        nested_candidate_count: 5,
        static_only: true,
        risk_counts: expect.objectContaining({
          high_compression_ratio: 1,
          path_traversal: 1,
        }),
      })
    )
    expect(inventory.workflow_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.container_structure.workflow_handoff.v1',
        handoff_mode: 'container_structure_to_nested_artifact_evidence_and_safe_extraction',
        artifact_type: 'container_structure',
        routing: expect.arrayContaining([
          expect.objectContaining({
            goal: 'extraction-risk-review',
            priority: 'high',
            next_tools: expect.arrayContaining(['artifact.read', 'analysis.evidence.graph']),
          }),
          expect.objectContaining({
            goal: 'nested-artifact-routing',
            priority: 'high',
            next_tools: expect.arrayContaining(['pe.structure.analyze', 'wasm.structure.analyze']),
          }),
        ]),
      })
    )
    expect(inventory.workflow_handoff?.dynamic_boundary).toEqual(
      expect.objectContaining({
        sample_executed_by_tool: false,
        extraction_performed_by_tool: false,
        filesystem_mounted_by_tool: false,
        package_installed_by_tool: false,
        entrypoint_executed_by_tool: false,
      })
    )
    expect(inventory.quality_gates).toEqual(
      expect.objectContaining({
        schema: 'rikune.container_structure.quality_gates.v1',
        passive_static_inventory: true,
        bounded_preview_only: true,
        max_entries_enforced: true,
        zip_bomb_review_required: true,
        path_traversal_review_required: true,
        sample_executed_by_tool: false,
        extraction_performed_by_tool: false,
      })
    )
    expect(inventory.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: '../evil.exe',
          routed_formats: expect.arrayContaining(['pe']),
          recommended_tools: expect.arrayContaining(['pe.structure.analyze']),
        }),
        expect.objectContaining({
          path: 'module.wasm',
          recommended_tools: expect.arrayContaining(['wasm.structure.analyze']),
        }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'sbom.provenance.graph',
        'analysis.evidence.graph',
        'report.generate',
      ])
    )
    expect(ContainerStructureAnalyzeOutputSchema.parse({ ok: true, data: inventory }).data).toEqual(
      expect.objectContaining({
        container_profile: expect.any(Object),
        evidence_summary: expect.any(Object),
        workflow_handoff: expect.any(Object),
        quality_gates: expect.any(Object),
      })
    )
  })

  test('plans Docker/OCI and installer payload handling without entrypoint or install execution', () => {
    const docker = buildContainerStructureFromBuffer(
      tarFixture(['manifest.json', 'layer.tar', 'bin/tool', 'usr/lib/libdemo.so', 'Dockerfile']),
      { filename: 'image.tar' }
    )
    const installerBundle = buildContainerStructureFromBuffer(
      localZip([{ name: 'setup.msi' }, { name: 'Payload/Demo.pkg' }]),
      { filename: 'payloads.zip' }
    )

    expect(docker.container_format).toBe('docker-image')
    expect(docker.policy.no_entrypoint_run).toBe(true)
    expect(docker.risk_flags).toContain('container-entrypoint-not-run')
    expect(docker.entrypoint_candidates).toContain('Dockerfile')
    expect(docker.container_profile?.entrypoint).toEqual(
      expect.objectContaining({
        candidate_count: 1,
        representative_paths: expect.arrayContaining(['Dockerfile']),
        not_run: true,
        review_required: true,
      })
    )
    expect(docker.workflow_handoff?.dynamic_boundary).toEqual(
      expect.objectContaining({
        entrypoint_executed_by_tool: false,
        payload_executed_by_tool: false,
        mutation_performed: false,
      })
    )
    expect(installerBundle.policy.no_install).toBe(true)
    expect(installerBundle.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'setup.msi',
          recommended_tools: expect.arrayContaining(['installer.inventory']),
        }),
        expect.objectContaining({
          path: 'Payload/Demo.pkg',
          recommended_tools: expect.arrayContaining(['apple.container.inventory']),
        }),
      ])
    )
  })
})
