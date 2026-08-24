import { DATABASE_FIXTURE_CAPABILITY } from "../../src/database.js"
import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import { createHash } from 'crypto'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createEvidenceGraphHandler,
  evidenceGraphToolDefinition,
} from '../../src/plugins/visualization/tools/evidence-graph.js'
import { buildMetadataExtractProfile } from '../../src/plugins/metadata/tools/metadata-extract.js'
import { buildWindowsInstallerInventoryFromBuffer } from '../../src/plugins/windows-installer/tools/windows-installer-inventory.js'
import { createAnalysisClaimsApplyHandler } from '../../src/plugins/kb-collaboration/tools/analysis-claims-apply.js'

const SAMPLE_HASH = '4'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

function localZip(entries: string[]): Buffer {
  const chunks: Buffer[] = []
  for (const entry of entries) {
    const name = Buffer.from(entry)
    const header = Buffer.alloc(30)
    header.writeUInt32LE(0x04034b50, 0)
    header.writeUInt16LE(name.length, 26)
    chunks.push(header, name)
  }
  return Buffer.concat(chunks)
}

describe('analysis.evidence.graph tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(async () => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-evidence-graph-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    database.insertSampleFixture(DATABASE_FIXTURE_CAPABILITY, {
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '4'.repeat(32),
      size: 4096,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })

    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'static_config_carver',
      'config_carver',
      {
        schema: 'rikune.static_config_carver.v1',
        candidates: [
          {
            kind: 'url',
            value: 'http://c2.example.net/gate',
            confidence: 0.9,
            evidence: ['http_url_string'],
          },
          {
            kind: 'registry_path',
            value: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            confidence: 0.8,
            evidence: ['registry_path_string'],
          },
        ],
        blob_candidates: [],
        workflow_handoff: {
          schema: 'rikune.static_config_carver.workflow_handoff.v1',
          handoff_mode: 'static_config_to_evidence_correlation',
          routing: [
            {
              goal: 'ioc-enrichment-and-export',
              priority: 'high',
              next_tools: ['malware.intel.loop', 'ioc.export', 'report.generate'],
              required_evidence: ['static_config_carver'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'normal',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['static_config_carver'],
            },
          ],
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'static_resource_graph',
      'resource_graph',
      {
        schema: 'rikune.static_resource_graph.v1',
        resources: [
          {
            path: ['resources', 'id_10', 'id_1033'],
            size: 4096,
            magic: 'pe_or_dos',
            entropy: 6.1,
            sha256: 'a'.repeat(64),
            stringPreview: ['resource payload', 'http://payload.example.net/install'],
          },
          {
            path: ['resources', 'id_24', 'id_1033'],
            size: 2048,
            magic: 'binary',
            entropy: 7.8,
            sha256: 'b'.repeat(64),
            stringPreview: [],
          },
        ],
        workflow_handoff: {
          schema: 'rikune.static_resource_graph.workflow_handoff.v1',
          handoff_mode: 'static_resource_to_payload_correlation',
          routing: [
            {
              goal: 'embedded-payload-followup',
              priority: 'high',
              next_tools: [
                'unpack.workflow.plan',
                'static.config.carver',
                'analysis.evidence.graph',
              ],
              required_evidence: ['static_resource_graph'],
            },
            {
              goal: 'encoded-or-encrypted-resource-followup',
              priority: 'high',
              next_tools: ['entropy.analyze', 'crypto.identify', 'static.config.carver'],
              required_evidence: ['high entropy resource evidence'],
            },
          ],
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'dynamic_trace_json',
      'dynamic_trace',
      {
        schema_version: '0.1.0',
        source_format: 'generic_json',
        evidence_kind: 'trace',
        imported_at: new Date().toISOString(),
        executed: true,
        raw_event_count: 2,
        api_calls: [
          { api: 'InternetConnectW', category: 'network', count: 1, confidence: 0.9, sources: [] },
          { api: 'RegSetValueExW', category: 'registry', count: 1, confidence: 0.9, sources: [] },
        ],
        memory_regions: [],
        modules: [],
        strings: [],
        stages: ['network', 'registry_operations'],
        risk_hints: [],
        notes: [],
      }
    )
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore cleanup races in failed tests
    }
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('exports evidence graph tool definition', () => {
    expect(evidenceGraphToolDefinition.name).toBe('analysis.evidence.graph')
    expect(evidenceGraphToolDefinition.description).toContain('evidence graph')
  })

  test('correlates static expectations with runtime observations', async () => {
    const result = await createEvidenceGraphHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      session_tag: 'graph-session',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.analysis_evidence_graph.v1')
    expect(data.summary.static_artifact_count).toBe(2)
    expect(data.summary.dynamic_artifact_count).toBe(1)
    expect(data.dynamic_summary.artifact_families).toContain('dynamic_trace')
    expect(data.summary.expectation_count).toBeGreaterThanOrEqual(3)
    expect(data.summary.observation_count).toBeGreaterThanOrEqual(2)
    expect(data.summary.corroboration_edge_count).toBeGreaterThan(0)
    expect(data.summary.claim_count).toBe(0)
    expect(data.claim_overlay.schema).toBe('rikune.analysis_claim_overlay.v1')
    expect(data.claim_overlay.claims).toEqual([])
    expect(
      data.graph.nodes.some(
        (node: any) => node.kind === 'expectation' && node.category === 'network'
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) => node.kind === 'observation' && node.category === 'registry'
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.id === 'artifact:dynamic_trace_summary' &&
          node.details?.artifact_families?.includes('dynamic_trace')
      )
    ).toBe(true)
    expect(result.artifacts?.[0]?.type).toBe('analysis_evidence_graph')
  })

  test('adds evidence-backed claims as an independent overlay', async () => {
    const evidenceArtifact = database.findArtifactsByType(SAMPLE_ID, 'static_config_carver')[0]
    const applied = await createAnalysisClaimsApplyHandler(
      workspaceManager,
      database
    )({
      sample_id: SAMPLE_ID,
      producer: { kind: 'llm', client_name: 'unit-test', model_name: 'test-model' },
      claims: [
        {
          claim_id: 'claim-c2-config',
          category: 'finding',
          subject: 'C2 configuration',
          statement: 'The configuration contains a candidate C2 URL.',
          supporting_evidence: [
            {
              artifact_id: evidenceArtifact.id,
              json_pointer: '/candidates/0/value',
              summary: 'URL candidate emitted by static.config.carver',
            },
          ],
        },
      ],
    })
    expect(applied.ok).toBe(true)

    const result = await createEvidenceGraphHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.summary.claim_set_count).toBe(1)
    expect(data.summary.claim_count).toBe(1)
    expect(data.claim_overlay.claims).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          claim_id: 'claim-c2-config',
          source: 'llm',
          status: 'inferred',
        }),
      ])
    )
    expect(data.claim_overlay.edges).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          from: 'claim:claim-c2-config',
          relation: 'supported_by',
          json_pointer: '/candidates/0/value',
        }),
      ])
    )
    expect(data.graph.nodes.some((node: any) => node.kind === 'claim')).toBe(false)
    expect(
      data.graph.edges.some(
        (edge: any) => edge.from === 'claim:claim-c2-config' || edge.to === 'claim:claim-c2-config'
      )
    ).toBe(false)
    expect(data.reporting_handoff.report_sections).toContain('claim_ledger')
    expect(data.quality_gates.claim_review_required).toBe(true)
  })

  test('marks claim evidence unresolved after the referenced artifact changes', async () => {
    const evidenceArtifact = database.findArtifactsByType(SAMPLE_ID, 'static_config_carver')[0]
    const applied = await createAnalysisClaimsApplyHandler(
      workspaceManager,
      database
    )({
      sample_id: SAMPLE_ID,
      claims: [
        {
          claim_id: 'claim-integrity-regression',
          category: 'hypothesis',
          subject: 'Configuration integrity',
          statement: 'The original configuration artifact supports this hypothesis.',
          supporting_evidence: [{ artifact_id: evidenceArtifact.id }],
        },
      ],
    })
    expect(applied.ok).toBe(true)

    const workspace = await workspaceManager.getWorkspace(SAMPLE_ID)
    const evidencePath = workspaceManager.normalizePath(workspace.root, evidenceArtifact.path)
    fs.writeFileSync(evidencePath, '{}', 'utf8')

    const result = await createEvidenceGraphHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.claim_overlay.unresolved_refs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          claim_id: 'claim-integrity-regression',
          artifact_id: evidenceArtifact.id,
          relation: 'supported_by',
        }),
      ])
    )
    expect(data.claim_overlay.edges.some((edge: any) => edge.relation === 'supported_by')).toBe(
      false
    )
    expect(data.quality_gates.claim_evidence_refs_resolved).toBe(false)
    expect(result.warnings).toEqual(
      expect.arrayContaining([expect.stringContaining('claim evidence reference')])
    )
  })

  test('adds plugin evidence from malware, static triage, and cross-decompiler bundles', async () => {
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'malware_intel_loop',
      'malware_intel_loop',
      {
        result_mode: 'malware_intel_loop',
        sample_id: SAMPLE_ID,
        fusion_summary: {
          behavior_clusters: [
            {
              capability: 'network_c2',
              techniques: ['T1071'],
              confidence: 0.72,
            },
          ],
        },
        normalized_iocs: [
          {
            type: 'url',
            value: 'http://c2.example.net/gate',
            normalized_value: 'http://c2.example.net/gate',
            confidence: 0.86,
            sources: ['config', 'strings'],
            sightings: 2,
            first_seen_in: 'config',
          },
        ],
        attack_map: {
          techniques: [{ id: 'T1071', name: 'Application Layer Protocol', confidence: 0.65 }],
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'static_triage_correlation_bundle',
      'static_triage_correlation_bundle',
      {
        schema: 'rikune.static_triage.correlation_bundle.v1',
        result_mode: 'static_triage_correlation_bundle',
        sample_id: SAMPLE_ID,
        bundles: {
          behavior: {
            high_confidence_capabilities: [
              {
                rule_id: 'cap/network',
                name: 'communicates over HTTP',
                namespace: 'communication/http',
                group: 'network',
                confidence: 0.8,
                evidence_summary: 'HTTP capability was matched.',
              },
            ],
            recommended_tools: ['static.behavior.classify', 'analysis.evidence.graph'],
          },
          config: {
            signals: [
              {
                kind: 'network_config',
                confidence: 0.82,
                evidence: ['cap/network: HTTP capability was matched.'],
                recommended_tools: ['static.config.carver', 'malware.intel.loop'],
                rationale: 'Network capability findings can seed IOC export.',
              },
            ],
          },
          crypto: { signals: [] },
          packer: { signals: [] },
        },
        routing: [
          {
            goal: 'evidence-graph-and-reporting',
            priority: 'normal',
            next_tools: ['analysis.evidence.graph', 'report.generate'],
            required_evidence: ['correlation bundle', 'capability findings'],
          },
        ],
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'api_hash_resolver_plan',
      'hash_resolver_plan',
      {
        schema: 'rikune.api_hash_resolver_plan.v1',
        sample_id: SAMPLE_ID,
        resolver_indicators: [
          {
            indicator: 'GetProcAddress',
            category: 'dynamic_api_resolution',
            confidence: 0.92,
            offset: 32,
            evidence: ['resolver_api_string'],
          },
        ],
        hash_candidates: [
          {
            value: '0x6A4ABC5B',
            normalized: '0x6a4abc5b',
            source: 'string_hex',
            offset: 64,
            confidence: 0.84,
            evidence: ['hex_token_near_resolver_string'],
          },
        ],
        workflow_handoff: {
          schema: 'rikune.api_hash.resolver_workflow_handoff.v1',
          handoff_mode: 'api_hash_resolver_to_resolution',
          routing: [
            {
              goal: 'api-name-resolution',
              priority: 'high',
              next_tools: ['hash.resolve'],
              required_evidence: ['hash.identify result', 'api_hash_resolver_plan'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'normal',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['api_hash_resolver_plan'],
            },
          ],
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'static_behavior_classifier',
      'behavior_classifier',
      {
        schema: 'rikune.static_behavior_classifier.v1',
        sample_id: SAMPLE_ID,
        findings: [
          {
            id: 'persistence.run_key',
            category: 'persistence',
            technique: 'Registry Run key persistence',
            severity: 'high',
            confidence: 0.88,
            evidence: [
              {
                source: 'config_artifact',
                kind: 'registry_path',
                value: 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
              },
            ],
            recommended_next_tools: ['dynamic.behavior.diff', 'dynamic.behavior.capture'],
          },
          {
            id: 'injection.remote_thread',
            category: 'injection',
            technique: 'Remote thread process injection',
            severity: 'critical',
            confidence: 0.92,
            evidence: [
              { source: 'string', kind: 'api_match', value: 'WriteProcessMemory' },
              { source: 'string', kind: 'api_match', value: 'CreateRemoteThread' },
            ],
            recommended_next_tools: ['breakpoint.smart', 'trace.condition'],
          },
        ],
        workflow_handoff: {
          schema: 'rikune.static_behavior_classifier.workflow_handoff.v1',
          handoff_mode: 'static_behavior_to_runtime_validation',
          routing: [
            {
              goal: 'runtime-behavior-validation',
              priority: 'high',
              next_tools: ['dynamic.behavior.diff', 'dynamic.deep_plan'],
              required_evidence: ['static_behavior_classifier'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'normal',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['static_behavior_classifier'],
            },
          ],
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'crypto_identification',
      'crypto_identification',
      {
        schema: 'rikune.crypto_identification.v1',
        sample_id: SAMPLE_ID,
        algorithms: [
          {
            algorithm_family: 'aes',
            algorithm_name: 'AES-256-CBC',
            mode: 'cbc',
            confidence: 0.88,
            function: 'FUN_401500',
            address: '0x401500',
            source_apis: ['AES_encrypt', 'BCryptEncrypt'],
            evidence: [
              {
                kind: 'string',
                value: 'AES-256-CBC',
                source_tool: 'crypto.identify',
                function: 'FUN_401500',
                confidence: 0.82,
              },
              {
                kind: 'import',
                value: 'BCryptEncrypt',
                source_tool: 'crypto.identify',
                confidence: 0.76,
              },
            ],
            candidate_constants: [
              {
                kind: 'sbox',
                label: 'aes_sbox_table',
                preview: '637c777bf26b6fc5',
                encoding: 'hex',
                byte_length: 16,
                source: 'string',
                function: 'FUN_401500',
                rationale: ['AES S-box prefix near localized crypto routine'],
              },
            ],
            dynamic_support: true,
            xref_available: true,
          },
        ],
        candidate_constants: [
          {
            kind: 'sbox',
            label: 'aes_sbox_table',
            preview: '637c777bf26b6fc5',
            encoding: 'hex',
            byte_length: 16,
            source: 'string',
            function: 'FUN_401500',
            rationale: ['AES S-box prefix near localized crypto routine'],
          },
        ],
        workflow_handoff: {
          schema: 'rikune.crypto_identification.workflow_handoff.v1',
          handoff_mode: 'crypto_identification_to_runtime_tracing',
          routing: [
            {
              goal: 'crypto-breakpoint-planning',
              priority: 'high',
              next_tools: ['breakpoint.smart', 'trace.condition'],
              required_evidence: ['crypto_identification', 'explicit analyst opt-in'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'normal',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['crypto_identification'],
            },
          ],
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'compiler_packer_attribution',
      'compiler_packer',
      {
        schema: 'rikune.compiler_packer_attribution.v1',
        sample_id: SAMPLE_ID,
        status: 'ready',
        compiler_findings: [
          {
            name: 'Microsoft Visual C++',
            category: 'compiler',
            confidence: 0.78,
            evidence_summary: 'Detect It Easy compiler signature',
            source: 'die-json',
          },
        ],
        packer_findings: [
          {
            name: 'UPX',
            category: 'packer',
            confidence: 0.82,
            evidence_summary: 'Detect It Easy UPX signature',
            source: 'die-json',
          },
        ],
        protector_findings: [
          {
            name: 'VMProtect',
            category: 'protector',
            confidence: 0.76,
            evidence_summary: 'Protector signature matched',
            source: 'die-json',
          },
        ],
        file_type_findings: [
          {
            name: 'PE32 executable',
            category: 'file_type',
            confidence: 0.72,
            evidence_summary: 'PE file type signature',
            source: 'die-json',
          },
        ],
        workflow_handoff: {
          schema: 'rikune.compiler_packer_attribution.workflow_handoff.v1',
          handoff_mode: 'compiler_packer_attribution_to_unpack_and_reporting',
          routing: [
            {
              goal: 'packer-validation-and-unpack-planning',
              priority: 'high',
              next_tools: [
                'packer.detect',
                'entropy.analyze',
                'static.resource.graph',
                'unpack.workflow.plan',
              ],
              required_evidence: ['compiler_packer_attribution'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'normal',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['compiler_packer_attribution'],
            },
          ],
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'cross_decompiler_consensus',
      'cross_decompiler_consensus',
      {
        schema: 'rikune.cross_decompiler_consensus.v1',
        sample_id: SAMPLE_ID,
        function_evidence_handoff: {
          schema: 'rikune.cross_decompiler.function_evidence_handoff.v1',
          handoff_mode: 'function_evidence_consensus',
          stable_functions: [
            {
              key: 'addr:0x401080',
              confidence: 0.78,
              backends: ['ghidra', 'radare2'],
              addresses: ['0x401080'],
              names: ['helper'],
              signatures: ['int helper(int)'],
              stable_facts: ['address:0x401080', 'name:helper'],
              recommended_tools: ['code.functions.reconstruct', 'code.function.explain.prepare'],
            },
          ],
          disputed_functions: [
            {
              key: 'addr:0x401000',
              severity: 'high',
              backends: ['ghidra', 'radare2'],
              conflict_fields: ['signature', 'cfg_shape'],
              recommended_tools: ['code.function.disassemble', 'code.function.cfg'],
            },
          ],
        },
        missing_backend_gaps: [
          {
            backend: 'retdec',
            impact: 'No retdec artifact was provided.',
            recommended_tools: ['retdec.decompile'],
          },
        ],
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'enriched_string_analysis',
      'decoded_strings',
      {
        sample_id: SAMPLE_ID,
        session_tag: null,
        tool: 'strings.floss.decode',
        created_at: new Date().toISOString(),
        data: {
          decoded_strings: [
            {
              string: 'http://decoded.example.net/gate',
              offset: 0x2200,
              type: 'decoded',
              decoding_method: 'xor',
            },
            {
              string: 'campaign_id=42',
              offset: 0x2300,
              type: 'stack',
              decoding_method: 'stack',
            },
          ],
          enriched: {
            status: 'partial',
            total_records: 2,
            kept_records: 2,
            analyst_relevant_count: 2,
            runtime_noise_count: 0,
            encoded_candidate_count: 1,
            merged_sources: false,
            truncated: false,
            records: [
              {
                value: 'http://decoded.example.net/gate',
                normalized_value: 'http://decoded.example.net/gate',
                primary_offset: 0x2200,
                categories: ['url'],
                labels: ['decoded_signal', 'analyst_relevant', 'business_logic'],
                confidence: 0.8,
                score: 20,
                rationale: ['contains FLOSS-decoded evidence'],
                sources: [{ source: 'floss', source_type: 'decoded', decode_method: 'xor' }],
              },
              {
                value: 'Y2FtcGFpZ25faWQ9NDI=',
                normalized_value: 'y2ftcgfpz25fawq9ndi=',
                primary_offset: 0x2400,
                categories: ['config_like'],
                labels: ['decoded_signal', 'encoded_candidate', 'analyst_relevant'],
                confidence: 0.72,
                score: 18,
                rationale: ['resembles encoded or packed text'],
                sources: [{ source: 'floss', source_type: 'stack', decode_method: 'stack' }],
              },
            ],
            top_suspicious: [
              {
                value: 'Y2FtcGFpZ25faWQ9NDI=',
                offset: 0x2400,
                categories: ['config_like'],
                labels: ['decoded_signal', 'encoded_candidate', 'analyst_relevant'],
                confidence: 0.72,
                score: 18,
                source_labels: ['floss:stack'],
              },
            ],
            top_iocs: [
              {
                value: 'http://decoded.example.net/gate',
                offset: 0x2200,
                categories: ['url'],
                labels: ['decoded_signal', 'analyst_relevant', 'business_logic'],
                confidence: 0.8,
                score: 20,
                source_labels: ['floss:decoded'],
              },
            ],
            top_runtime_noise: [],
            top_decoded: [
              {
                value: 'http://decoded.example.net/gate',
                offset: 0x2200,
                categories: ['url'],
                labels: ['decoded_signal', 'analyst_relevant', 'business_logic'],
                confidence: 0.8,
                score: 20,
                source_labels: ['floss:decoded'],
              },
            ],
          },
          workflow_handoff: {
            schema: 'rikune.strings_floss_decode.workflow_handoff.v1',
            handoff_mode: 'decoded_strings_to_config_ioc_and_reporting',
            routing: [
              {
                goal: 'ioc-and-config-carving',
                priority: 'high',
                next_tools: ['static.config.carver', 'ioc.export', 'malware.intel.loop'],
                required_evidence: ['decoded strings', 'enriched_string_analysis'],
              },
              {
                goal: 'evidence-graph-and-reporting',
                priority: 'normal',
                next_tools: ['analysis.evidence.graph', 'report.generate'],
                required_evidence: ['enriched_string_analysis'],
              },
            ],
          },
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'yara_rule_generation',
      'yara_rule_generation',
      {
        schema: 'rikune.yara_rule_generation.v1',
        tool_version: '0.1.0',
        sample_id: SAMPLE_ID,
        strictness: 'balanced',
        deploy_requested: false,
        rules: [
          {
            type: 'hybrid',
            rule_text: 'rule hybrid_unit_test { strings: $s0 = "rare_campaign" condition: $s0 }',
            score: 82,
            breakdown: {
              string_uniqueness: 28,
              import_specificity: 20,
              byte_pattern_quality: 10,
              condition_strictness: 24,
            },
          },
        ],
        best_rule: {
          type: 'hybrid',
          rule_text: 'rule hybrid_unit_test { strings: $s0 = "rare_campaign" condition: $s0 }',
          score: 82,
          breakdown: {
            string_uniqueness: 28,
            import_specificity: 20,
            byte_pattern_quality: 10,
            condition_strictness: 24,
          },
        },
        evidence_summary: {
          schema: 'rikune.yara_rule_generation.evidence_summary.v1',
          source_tool: 'yara.generate',
          sample_id: SAMPLE_ID,
          rules_generated: 1,
          generated_rule_types: ['hybrid'],
          best_score: 82,
          evidence_counts: {
            unique_strings: 2,
            all_imports: 4,
            suspicious_imports: 2,
            byte_patterns: 1,
          },
        },
        workflow_handoff: {
          schema: 'rikune.yara_generate.workflow_handoff.v1',
          handoff_mode: 'yara_rule_generation_to_validation_and_reporting',
          routing: [
            {
              goal: 'rule-validation-and-false-positive-review',
              priority: 'high',
              next_tools: ['yara.scan'],
              required_evidence: ['yara_rule_generation', 'known benign or related sample corpus'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'normal',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['yara_rule_generation'],
            },
          ],
        },
        quality_gates: {
          schema: 'rikune.yara_generate.quality_gates.v1',
          quality_tier: 'high',
          passive_generation_only: true,
          corpus_validation_required: true,
          false_positive_review_required: true,
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'yara_family_rule',
      'yara_family_rule',
      {
        schema: 'rikune.yara_family_rule.v1',
        tool_version: '0.1.0',
        sample_ids: [SAMPLE_ID, `sha256:${'5'.repeat(64)}`],
        primary_sample_id: SAMPLE_ID,
        strictness: 'balanced',
        family_name: 'unit_family',
        family_rule: {
          type: 'family_hybrid',
          rule_text: 'rule family_unit_test { strings: $s0 = "shared_family" condition: $s0 }',
          score: 78,
          breakdown: {
            string_uniqueness: 26,
            import_specificity: 18,
            byte_pattern_quality: 8,
            condition_strictness: 24,
          },
        },
        rule_text: 'rule family_unit_test { strings: $s0 = "shared_family" condition: $s0 }',
        score: 78,
        breakdown: {
          string_uniqueness: 26,
          import_specificity: 18,
          byte_pattern_quality: 8,
          condition_strictness: 24,
        },
        common_features: {
          strings: 2,
          imports: 1,
          min_occurrence: 2,
        },
        sample_count: 2,
        evidence_summary: {
          schema: 'rikune.yara_family_rule.evidence_summary.v1',
          source_tool: 'yara.generate.batch',
          sample_count: 2,
          sample_ids: [SAMPLE_ID, `sha256:${'5'.repeat(64)}`],
          family_name: 'unit_family',
          strictness: 'balanced',
          score: 78,
          quality_tier: 'high',
          common_feature_counts: {
            strings: 2,
            imports: 1,
            min_occurrence: 2,
          },
        },
        workflow_handoff: {
          schema: 'rikune.yara_generate_batch.workflow_handoff.v1',
          handoff_mode: 'yara_family_rule_to_cluster_validation_and_reporting',
          routing: [
            {
              goal: 'family-rule-validation-and-false-positive-review',
              priority: 'high',
              next_tools: ['yara.scan'],
              required_evidence: ['yara_family_rule', 'related sample corpus', 'benign corpus'],
            },
            {
              goal: 'family-cluster-corroboration',
              priority: 'normal',
              next_tools: ['sample.family.cluster', 'binary.diff.summary'],
              required_evidence: ['yara_family_rule', 'multi-sample analysis evidence'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'normal',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['yara_family_rule'],
            },
          ],
        },
        quality_gates: {
          schema: 'rikune.yara_generate_batch.quality_gates.v1',
          quality_tier: 'high',
          passive_generation_only: true,
          corpus_validation_required: true,
          false_positive_review_required: true,
          family_cluster_review_required: true,
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'sigma_rules',
      'sigma_rules',
      {
        schema: 'rikune.sigma_rule_generation.v1',
        tool_version: '0.1.0',
        sample_id: SAMPLE_ID,
        level: 'high',
        deploy_requested: false,
        requested_rule_types: ['network_connection', 'registry_event', 'process_creation'],
        rules: [
          {
            type: 'network_connection',
            title: 'Suspicious Network Connection - unit',
            rule_yaml:
              "title: 'Suspicious Network Connection - unit'\nlogsource:\n  category: network_connection\n",
            indicator_count: 2,
          },
          {
            type: 'registry_event',
            title: 'Suspicious Registry Modification - unit',
            rule_yaml:
              "title: 'Suspicious Registry Modification - unit'\nlogsource:\n  category: registry_event\n",
            indicator_count: 1,
          },
          {
            type: 'process_creation',
            title: 'Suspicious Process Creation - unit',
            rule_yaml:
              "title: 'Suspicious Process Creation - unit'\nlogsource:\n  category: process_creation\n",
            indicator_count: 1,
          },
        ],
        total_rules: 3,
        total_indicators: 4,
        evidence_summary: {
          schema: 'rikune.sigma_rule_generation.evidence_summary.v1',
          source_tool: 'sigma.rule.generate',
          sample_id: SAMPLE_ID,
          artifact_type: 'sigma_rules',
          level: 'high',
          deploy_requested: false,
          requested_rule_types: ['network_connection', 'registry_event', 'process_creation'],
          generated_rule_types: ['network_connection', 'registry_event', 'process_creation'],
          rules_generated: 3,
          total_indicators: 4,
          evidence_counts: {
            strings: 5,
            imports: 2,
            urls: 1,
            ips: 1,
            domains: 1,
            registry_keys: 1,
            process_names: 1,
          },
        },
        workflow_handoff: {
          schema: 'rikune.sigma_rule_generation.workflow_handoff.v1',
          handoff_mode: 'sigma_rule_generation_to_validation_attack_mapping_and_reporting',
          artifact_type: 'sigma_rules',
          routing: [
            {
              goal: 'rule-validation-and-false-positive-review',
              priority: 'high',
              next_tools: ['artifact.read', 'report.generate'],
              required_evidence: ['sigma_rules', 'benign event corpus'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'high',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['sigma_rules'],
            },
            {
              goal: 'attack-and-ioc-feedback-loop',
              priority: 'normal',
              next_tools: ['attack.map', 'ioc.export', 'yara.generate'],
              required_evidence: ['generated Sigma rules'],
            },
          ],
        },
        quality_gates: {
          schema: 'rikune.sigma_rule_generation.quality_gates.v1',
          passive_generation_only: true,
          false_positive_review_required: true,
          siem_validation_required: true,
        },
      }
    )
    const yaraXRulesDigest = createHash('sha256')
      .update('rule SuspiciousUnitRule { strings: $a = "unit" condition: $a }')
      .digest('hex')
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'backend_yara_x_scan',
      'yara_x_scan',
      {
        schema: 'rikune.yara_x_scan.v1',
        tool_version: '0.1.0',
        sample_id: SAMPLE_ID,
        rules_digest: yaraXRulesDigest,
        rules_source: 'inline',
        timeout_sec: 15,
        max_matches_per_pattern: 250,
        match_count: 1,
        matching_rules: [
          {
            identifier: 'SuspiciousUnitRule',
            namespace: 'default',
            patterns: [
              { identifier: '$a', matches: [{ offset: 16, length: 4 }] },
              { identifier: '$b', matches: [{ offset: 32, length: 8 }] },
            ],
          },
        ],
        pattern_match_count: 2,
        module_outputs: { pe: { imphash: 'unit-imphash' } },
        evidence_summary: {
          schema: 'rikune.yara_x_scan.evidence_summary.v1',
          source_tool: 'yara_x.scan',
          sample_id: SAMPLE_ID,
          artifact_type: 'backend_yara_x_scan',
          rules_source: 'inline',
          rules_digest: yaraXRulesDigest,
          timeout_sec: 15,
          max_matches_per_pattern: 250,
          match_count: 1,
          pattern_match_count: 2,
          matching_rule_identifiers: ['SuspiciousUnitRule'],
          module_output_keys: ['pe'],
        },
        workflow_handoff: {
          schema: 'rikune.yara_x_scan.workflow_handoff.v1',
          handoff_mode: 'yara_x_scan_to_rule_validation_and_reporting',
          source_tool: 'yara_x.scan',
          sample_id: SAMPLE_ID,
          artifact_type: 'backend_yara_x_scan',
          rules_source: 'inline',
          rules_digest: yaraXRulesDigest,
          match_count: 1,
          pattern_match_count: 2,
          recommended_next_tools: [
            'artifact.read',
            'yara.scan',
            'analysis.evidence.graph',
            'report.generate',
          ],
          routing: [
            {
              goal: 'artifact-review-and-offset-validation',
              priority: 'high',
              next_tools: ['artifact.read'],
              required_evidence: ['backend_yara_x_scan', 'YARA-X rule match offsets'],
            },
            {
              goal: 'legacy-yara-comparison',
              priority: 'normal',
              next_tools: ['yara.scan'],
              required_evidence: ['backend_yara_x_scan', 'legacy YARA compatibility rules'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'high',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['backend_yara_x_scan'],
            },
          ],
        },
        quality_gates: {
          schema: 'rikune.yara_x_scan.quality_gates.v1',
          passive_scan_only: true,
          backend_started: true,
          sample_executed_by_tool: false,
          network_accessed_by_tool: false,
          live_sample_mutation_performed: false,
          rules_provided: true,
          rules_digest_available: true,
          match_floor_met: true,
          pattern_match_floor_met: true,
          artifact_review_required: true,
          legacy_yara_comparison_recommended: true,
          bounded_match_preview_returned: true,
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'backend_die_scan',
      'die_scan',
      {
        schema: 'rikune.die_scan.v1',
        tool_version: '0.1.0',
        sample_id: SAMPLE_ID,
        artifact_type: 'backend_die_scan',
        command_args: ['sample.exe', '-j', '-d'],
        deep_scan: true,
        timeout_sec: 20,
        exit_code: 0,
        timed_out: false,
        file_type: 'PE32 executable',
        arch: 'x86-64',
        mode: 'console',
        entropy: 7.31,
        detects: [
          { type: 'Compiler', name: 'Microsoft Visual C++', version: '19.3', options: '' },
          { type: 'Packer', name: 'UPX', version: '4.x', options: 'compressed' },
          { type: 'Crypto', name: 'AES constants', version: '', options: '' },
        ],
        compiler_findings: [
          {
            type: 'Compiler',
            name: 'Microsoft Visual C++',
            version: '19.3',
            options: '',
            category: 'compiler',
            confidence: 0.76,
            evidence_summary: 'type=Compiler, version=19.3',
            source: 'die-json',
          },
        ],
        packer_findings: [
          {
            type: 'Packer',
            name: 'UPX',
            version: '4.x',
            options: 'compressed',
            category: 'packer',
            confidence: 0.82,
            evidence_summary: 'type=Packer, version=4.x, options=compressed',
            source: 'die-json',
          },
        ],
        crypto_findings: [
          {
            type: 'Crypto',
            name: 'AES constants',
            version: '',
            options: '',
            category: 'crypto',
            confidence: 0.76,
            evidence_summary: 'type=Crypto',
            source: 'die-json',
          },
        ],
        file_type_findings: [
          {
            type: 'file_type',
            name: 'PE32 executable',
            version: '',
            options: '',
            category: 'file_type',
            confidence: 0.72,
            evidence_summary: 'die-filetype: PE32 executable',
            source: 'die-filetype',
          },
        ],
        evidence_summary: {
          schema: 'rikune.die_scan.evidence_summary.v1',
          source_tool: 'die.scan',
          sample_id: SAMPLE_ID,
          artifact_type: 'backend_die_scan',
          deep_scan: true,
          timeout_sec: 20,
          command_args: ['sample.exe', '-j', '-d'],
          exit_code: 0,
          timed_out: false,
          detect_count: 3,
          compiler_count: 1,
          packer_count: 1,
          protector_count: 0,
          linker_count: 0,
          crypto_count: 1,
          file_type_count: 1,
          unknown_count: 0,
          file_type: 'PE32 executable',
          arch: 'x86-64',
          mode: 'console',
          entropy: 7.31,
          top_compilers: ['Microsoft Visual C++'],
          top_packers: ['UPX'],
          top_protectors: [],
          top_crypto: ['AES constants'],
          stdout_bytes: 512,
          stderr_bytes: 0,
        },
        workflow_handoff: {
          schema: 'rikune.die_scan.workflow_handoff.v1',
          handoff_mode: 'die_scan_to_packer_validation_toolchain_correlation_and_reporting',
          source_tool: 'die.scan',
          sample_id: SAMPLE_ID,
          artifact_type: 'backend_die_scan',
          recommended_next_tools: [
            'artifact.read',
            'compiler.packer.detect',
            'packer.detect',
            'unpack.workflow.plan',
            'analysis.evidence.graph',
            'report.generate',
          ],
          routing: [
            {
              goal: 'packer-validation-and-unpack-planning',
              priority: 'high',
              next_tools: [
                'packer.detect',
                'entropy.analyze',
                'static.resource.graph',
                'unpack.workflow.plan',
              ],
              required_evidence: ['backend_die_scan', 'DIE packer/protector signatures'],
            },
            {
              goal: 'toolchain-aware-static-correlation',
              priority: 'normal',
              next_tools: [
                'static.capability.triage',
                'code.cross_decompiler.consensus',
                'analysis.evidence.graph',
              ],
              required_evidence: ['backend_die_scan', 'DIE compiler/linker signatures'],
            },
            {
              goal: 'crypto-followup-and-capability-correlation',
              priority: 'normal',
              next_tools: [
                'crypto.identify',
                'static.capability.triage',
                'analysis.evidence.graph',
              ],
              required_evidence: ['backend_die_scan', 'DIE crypto signatures'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'normal',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['backend_die_scan'],
            },
          ],
        },
        quality_gates: {
          schema: 'rikune.die_scan.quality_gates.v1',
          passive_static_scan: true,
          static_backend_available: true,
          static_backend_started: true,
          runtime_started_by_tool: false,
          sample_executed_by_tool: false,
          network_accessed_by_tool: false,
          mutation_performed: false,
          exit_code_ok: true,
          timed_out: false,
          compiler_evidence_present: true,
          packer_evidence_present: true,
          crypto_evidence_present: true,
          evidence_graph_handoff_ready: true,
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'backend_upx_list',
      'upx_list',
      {
        schema: 'rikune.upx_inspect.v1',
        tool_version: '0.1.0',
        sample_id: SAMPLE_ID,
        operation: 'list',
        artifact_type: 'backend_upx_list',
        command_args: ['-l', 'sample.exe'],
        exit_code: 0,
        upx_detected: true,
        stdout_preview:
          'Ultimate Packer for eXecutables\nFile size Ratio Format Name\n4096 2048 50.0% win64/pe sample.exe',
        stderr_preview: '',
        evidence_summary: {
          schema: 'rikune.upx_inspect.evidence_summary.v1',
          source_tool: 'upx.inspect',
          sample_id: SAMPLE_ID,
          artifact_type: 'backend_upx_list',
          operation: 'list',
          timeout_sec: 10,
          command_args: ['-l', 'sample.exe'],
          exit_code: 0,
          upx_detected: true,
          stdout_bytes: 96,
          stderr_bytes: 0,
          decompressed_artifact_type: null,
          decompressed_artifact_sha256: null,
        },
        workflow_handoff: {
          schema: 'rikune.upx_inspect.workflow_handoff.v1',
          handoff_mode: 'upx_inspection_to_unpack_validation_retriage_and_reporting',
          source_tool: 'upx.inspect',
          sample_id: SAMPLE_ID,
          artifact_type: 'backend_upx_list',
          operation: 'list',
          exit_code: 0,
          upx_detected: true,
          recommended_next_tools: [
            'artifact.read',
            'unpack.workflow.plan',
            'packer.detect',
            'analysis.evidence.graph',
            'report.generate',
          ],
          routing: [
            {
              goal: 'artifact-review-and-packer-validation',
              priority: 'high',
              next_tools: ['artifact.read', 'packer.detect', 'unpack.workflow.plan'],
              required_evidence: ['backend_upx_list', 'UPX stdout/stderr evidence'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'high',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['backend_upx_list'],
            },
          ],
        },
        quality_gates: {
          schema: 'rikune.upx_inspect.quality_gates.v1',
          passive_inspection_only: true,
          backend_started: true,
          sample_executed_by_tool: false,
          network_accessed_by_tool: false,
          live_sample_mutation_performed: false,
          file_transformation_performed: false,
          decompressed_artifact_created: false,
          exit_code_ok: true,
          upx_signal_present: true,
          artifact_review_required: true,
          retriage_required_after_decompress: false,
        },
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'ioc_export_json',
      'ioc_export_json',
      {
        schema: 'rikune.ioc_export.v1',
        sample_id: SAMPLE_ID,
        format: 'json',
        tool_version: '0.1.0',
        include_attack_map: true,
        include_low_confidence: false,
        max_iocs: 300,
        ioc_count: 2,
        available_ioc_count: 2,
        iocs: [
          {
            type: 'url',
            value: 'http://export.example.net/gate',
            confidence: 'high',
            source: 'triage.urls',
            tags: ['network'],
          },
          {
            type: 'registry_key',
            value: 'HKCU\\Software\\ExportTest\\Run',
            confidence: 'medium',
            source: 'triage.registry_keys',
            tags: ['persistence'],
          },
        ],
        attack_map: [
          {
            technique_id: 'T1071',
            name: 'Application Layer Protocol',
            tactics: ['Command and Control'],
            confidence: 0.74,
          },
        ],
        attack_technique_count: 1,
        evidence_summary: {
          schema: 'rikune.ioc_export.evidence_summary.v1',
          source_tool: 'ioc.export',
          sample_id: SAMPLE_ID,
          export_format: 'json',
          artifact_type: 'ioc_export_json',
          exported_ioc_count: 2,
          available_ioc_count: 2,
          attack_technique_count: 1,
        },
        workflow_handoff: {
          schema: 'rikune.ioc_export.workflow_handoff.v1',
          handoff_mode: 'ioc_export_to_enrichment_detection_and_reporting',
          artifact_type: 'ioc_export_json',
          routing: [
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'high',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['ioc_export_json'],
            },
            {
              goal: 'detection-rule-generation',
              priority: 'normal',
              next_tools: ['sigma.rule.generate', 'yara.generate'],
              required_evidence: ['normalized IOC export'],
            },
          ],
        },
        quality_gates: {
          schema: 'rikune.ioc_export.quality_gates.v1',
          passive_export_only: true,
          sharing_review_required: true,
        },
      }
    )
    const stixBundle = {
      type: 'bundle',
      id: 'bundle--11111111-1111-4111-8111-111111111111',
      spec_version: '2.1',
      objects: [
        {
          type: 'observed-data',
          spec_version: '2.1',
          id: 'observed-data--11111111-1111-4111-8111-111111111112',
          first_observed: '2026-05-26T00:00:00Z',
          last_observed: '2026-05-26T00:00:00Z',
          number_observed: 1,
          objects: {
            '0': {
              type: 'url',
              value: 'http://stix-export.example.net/c2',
            },
          },
          labels: ['network'],
          x_mcp_source: 'triage.urls',
          x_mcp_confidence_level: 'high',
        },
        {
          type: 'attack-pattern',
          spec_version: '2.1',
          id: 'attack-pattern--11111111-1111-4111-8111-111111111113',
          name: 'T1071 Application Layer Protocol',
          external_references: [{ source_name: 'mitre-attack', external_id: 'T1071' }],
          x_mcp_confidence: 0.7,
          kill_chain_phases: [
            { kill_chain_name: 'mitre-attack', phase_name: 'command-and-control' },
          ],
        },
      ],
      x_mcp_schema: 'rikune.ioc_export.v1',
      x_mcp_evidence_summary: {
        schema: 'rikune.ioc_export.evidence_summary.v1',
        source_tool: 'ioc.export',
        sample_id: SAMPLE_ID,
        export_format: 'stix2',
        artifact_type: 'ioc_export_stix2',
        exported_ioc_count: 1,
        available_ioc_count: 1,
        attack_technique_count: 1,
      },
      x_mcp_workflow_handoff: {
        schema: 'rikune.ioc_export.workflow_handoff.v1',
        handoff_mode: 'ioc_export_to_enrichment_detection_and_reporting',
        artifact_type: 'ioc_export_stix2',
        routing: [
          {
            goal: 'sharing-review',
            priority: 'high',
            next_tools: ['artifact.read', 'report.generate'],
            required_evidence: ['ioc_export_stix2', 'analyst sharing approval'],
          },
        ],
      },
      x_mcp_quality_gates: {
        schema: 'rikune.ioc_export.quality_gates.v1',
        passive_export_only: true,
        stix_review_required: true,
      },
    }
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'ioc_export_stix2',
      'ioc_export_stix2',
      stixBundle
    )
    const workspace = await workspaceManager.getWorkspace(SAMPLE_ID)
    const csvDir = path.join(workspace.reports, 'ioc_exports')
    fs.mkdirSync(csvDir, { recursive: true })
    const csvContent =
      'type,value,confidence,source,tags\n' +
      'url,http://csv-export.example.net/gate,high,triage.urls,network\n' +
      'registry_key,HKCU\\Software\\CsvExport\\Run,medium,triage.registry_keys,persistence'
    const csvPath = path.join(csvDir, 'ioc_export_unit.csv')
    fs.writeFileSync(csvPath, csvContent, 'utf8')
    database.insertArtifact({
      id: 'ioc-export-csv-unit',
      sample_id: SAMPLE_ID,
      type: 'ioc_export_csv',
      path: path.relative(workspace.root, csvPath).replace(/\\/g, '/'),
      sha256: createHash('sha256').update(csvContent).digest('hex'),
      mime: 'text/csv',
      created_at: new Date().toISOString(),
    })

    const result = await createEvidenceGraphHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.summary.static_artifact_count).toBe(19)
    expect(data.summary.plugin_evidence_count).toBeGreaterThanOrEqual(30)
    expect(data.summary.function_handoff_count).toBe(2)
    expect(data.plugin_evidence_summary).toEqual(
      expect.objectContaining({
        schema: 'rikune.analysis_evidence_graph.plugin_evidence_summary.v1',
        ioc_count: expect.any(Number),
        disputed_function_count: 1,
      })
    )
    expect(data.plugin_evidence_summary.ioc_count).toBeGreaterThanOrEqual(3)
    expect(data.plugin_evidence_summary.triage_signal_count).toBeGreaterThanOrEqual(3)
    expect(data.plugin_evidence_summary.evidence_by_kind.capability).toBeGreaterThanOrEqual(2)
    expect(data.plugin_evidence_summary.evidence_by_kind.behavior_cluster).toBeGreaterThanOrEqual(4)
    expect(data.plugin_evidence_summary.recommended_tools).toEqual(
      expect.arrayContaining([
        'malware.intel.loop',
        'ioc.export',
        'analysis.evidence.graph',
        'unpack.workflow.plan',
        'packer.detect',
        'report.generate',
      ])
    )
    expect(data.reporting_handoff).toEqual(
      expect.objectContaining({
        schema: 'rikune.analysis_evidence_graph.reporting_handoff.v1',
        handoff_mode: 'plugin_evidence_to_reporting',
        recommended_next_tools: expect.arrayContaining([
          'workflow.summarize',
          'report.summarize',
          'report.generate',
        ]),
        report_sections: expect.arrayContaining([
          'ioc_summary',
          'capability_correlation',
          'function_consensus',
        ]),
      })
    )
    expect(data.quality_gates).toEqual(
      expect.objectContaining({
        passive_correlation_only: true,
        backend_started: false,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        plugin_evidence_present: true,
        report_handoff_ready: true,
        analyst_review_required: true,
      })
    )
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'static_config_carver' &&
          node.details?.plugin_evidence_kind === 'ioc' &&
          node.details?.value === 'http://c2.example.net/gate'
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'static_config_carver' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('ioc.export')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'static_resource_graph' &&
          node.category === 'embedded_payload' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.recommended_tools?.includes('unpack.workflow.plan')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'static_resource_graph' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('crypto.identify')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'compiler_packer_attribution' &&
          node.category === 'encrypted_or_packed_resource' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.recommended_tools?.includes('unpack.workflow.plan')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'compiler_packer_attribution' &&
          node.category === 'toolchain' &&
          node.details?.plugin_evidence_kind === 'capability' &&
          node.details?.recommended_tools?.includes('code.cross_decompiler.consensus')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'compiler_packer_attribution' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('packer.detect')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.recommended_tools?.includes('malware.intel.loop')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'enriched_string_analysis' &&
          node.details?.plugin_evidence_kind === 'ioc' &&
          node.details?.value === 'http://decoded.example.net/gate' &&
          node.details?.recommended_tools?.includes('ioc.export')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'yara_rule_generation' &&
          node.category === 'signatures' &&
          node.details?.plugin_evidence_kind === 'capability' &&
          node.details?.recommended_tools?.includes('yara.scan')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'yara_family_rule' &&
          node.category === 'signatures' &&
          node.details?.plugin_evidence_kind === 'capability' &&
          node.details?.recommended_tools?.includes('yara.scan')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'yara_family_rule' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.recommended_tools?.includes('sample.family.cluster')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'yara_family_rule' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('analysis.evidence.graph')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'sigma_rules' &&
          node.category === 'network' &&
          node.details?.plugin_evidence_kind === 'behavior_cluster' &&
          node.details?.rule_type === 'network_connection' &&
          node.details?.recommended_tools?.includes('attack.map')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'sigma_rules' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.recommended_tools?.includes('artifact.read')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'sigma_rules' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('analysis.evidence.graph')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_yara_x_scan' &&
          node.category === 'signatures' &&
          node.details?.plugin_evidence_kind === 'capability' &&
          node.details?.identifier === 'SuspiciousUnitRule' &&
          node.details?.recommended_tools?.includes('yara.scan') &&
          node.details?.recommended_tools?.includes('artifact.read')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_yara_x_scan' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.recommended_tools?.includes('artifact.read')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_yara_x_scan' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('analysis.evidence.graph')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_die_scan' &&
          node.category === 'encrypted_or_packed_resource' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.recommended_tools?.includes('unpack.workflow.plan')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_die_scan' &&
          node.category === 'toolchain' &&
          node.details?.plugin_evidence_kind === 'capability' &&
          node.details?.recommended_tools?.includes('code.cross_decompiler.consensus')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_die_scan' &&
          node.category === 'crypto' &&
          node.details?.plugin_evidence_kind === 'capability' &&
          node.details?.recommended_tools?.includes('crypto.identify')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_die_scan' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('analysis.evidence.graph')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_upx_list' &&
          node.category === 'encrypted_or_packed_resource' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.recommended_tools?.includes('unpack.workflow.plan')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_upx_list' &&
          node.category === 'packed' &&
          node.details?.plugin_evidence_kind === 'capability' &&
          node.details?.recommended_tools?.includes('static.triage')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_upx_list' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('analysis.evidence.graph')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'ioc_export_json' &&
          node.details?.plugin_evidence_kind === 'ioc' &&
          node.details?.value === 'http://export.example.net/gate' &&
          node.details?.recommended_tools?.includes('malware.intel.loop')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'ioc_export_csv' &&
          node.details?.plugin_evidence_kind === 'ioc' &&
          node.details?.value === 'http://csv-export.example.net/gate'
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'ioc_export_stix2' &&
          node.details?.plugin_evidence_kind === 'behavior_cluster' &&
          node.details?.technique_id === 'T1071' &&
          node.details?.recommended_tools?.includes('sigma.rule.generate')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'ioc_export_json' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('sigma.rule.generate')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'yara_rule_generation' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('analysis.evidence.graph')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'enriched_string_analysis' &&
          node.category === 'encoded_config' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.recommended_tools?.includes('crypto.identify')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'enriched_string_analysis' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('static.config.carver')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'api_hash_resolver_plan' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.recommended_tools?.includes('hash.resolve')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'api_hash_resolver_plan' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('report.generate')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'static_behavior_classifier' &&
          node.category === 'injection' &&
          node.details?.plugin_evidence_kind === 'behavior_cluster' &&
          node.details?.recommended_tools?.includes('breakpoint.smart')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'crypto_identification' &&
          node.category === 'crypto' &&
          node.details?.plugin_evidence_kind === 'capability' &&
          node.details?.recommended_tools?.includes('crypto.lifecycle.graph')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'crypto_identification' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('trace.condition')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'static_behavior_classifier' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('dynamic.behavior.diff')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'function_handoff' &&
          node.details?.plugin_evidence_kind === 'stable_function' &&
          node.details?.names?.includes('helper')
      )
    ).toBe(true)
    expect(
      data.graph.edges.some((edge: any) => edge.label === 'supported_by_plugin_evidence')
    ).toBe(true)
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining([
        'malware.intel.loop',
        'code.cross_decompiler.consensus',
        'workflow.summarize',
        'report.generate',
      ])
    )
  })

  test('adds plugin evidence from backend_yara_scan artifacts', async () => {
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'backend_yara_scan',
      'yara_scan',
      {
        schema: 'rikune.yara_scan.v1',
        tool_version: '1.1.0',
        sample_id: SAMPLE_ID,
        rule_set: 'malware_families',
        rule_tier: 'production',
        ruleset_version: 'rules-v2',
        match_count: 1,
        string_evidence_count: 1,
        confidence_summary: { high: 1, medium: 0, low: 0 },
        matches: [
          {
            rule: 'SuspiciousUnitFamily',
            tags: ['malware-family'],
            meta: { description: 'unit family rule' },
            strings: [
              {
                identifier: '$mz_marker',
                offset: 0,
                matched_data: 'MZ',
                location: { section: '.text', rva: 4096, distance_to_entrypoint: 16 },
              },
            ],
            confidence: { level: 'high', score: 0.9 },
            evidence: {
              import_dll_hits: ['kernel32.dll'],
              import_api_hits: ['CreateFileA'],
              section_hits: ['.text'],
              near_entrypoint_hits: 1,
            },
            inference: {
              classification: 'malware-family',
              summary: 'Unit-test family confidence.',
            },
          },
        ],
        evidence_summary: {
          schema: 'rikune.yara_scan.evidence_summary.v1',
          source_tool: 'yara.scan',
          sample_id: SAMPLE_ID,
          artifact_type: 'backend_yara_scan',
          rule_provenance: {
            source: 'bundled_static_worker_yara_rules',
            rule_set: 'malware_families',
            rule_tier: 'production',
            ruleset_version: 'rules-v2',
            rule_files: ['malware_families.yar'],
          },
          rule_set: 'malware_families',
          rule_tier: 'production',
          ruleset_version: 'rules-v2',
          match_count: 1,
          matched_rule_names: ['SuspiciousUnitFamily'],
          string_evidence_count: 1,
          offset_evidence: {
            strings_with_offsets: 1,
            strings_with_location: 1,
            near_entrypoint_hits: 1,
            parser: 'pefile',
          },
          confidence_summary: { high: 1, medium: 0, low: 0 },
          timed_out: false,
        },
        workflow_handoff: {
          schema: 'rikune.yara_scan.workflow_handoff.v1',
          handoff_mode: 'yara_scan_to_validation_evidence_graph_and_reporting',
          source_tool: 'yara.scan',
          sample_id: SAMPLE_ID,
          artifact_type: 'backend_yara_scan',
          match_count: 1,
          string_evidence_count: 1,
          recommended_next_tools: [
            'artifact.read',
            'analysis.evidence.graph',
            'report.generate',
            'malware.intel.loop',
            'ioc.export',
          ],
          routing: [
            {
              goal: 'artifact-review-and-offset-validation',
              priority: 'high',
              next_tools: ['artifact.read', 'analysis.evidence.graph'],
              required_evidence: ['backend_yara_scan', 'YARA string offsets'],
            },
            {
              goal: 'evidence-graph-and-reporting',
              priority: 'high',
              next_tools: ['analysis.evidence.graph', 'report.generate'],
              required_evidence: ['backend_yara_scan'],
            },
          ],
        },
        quality_gates: {
          schema: 'rikune.yara_scan.quality_gates.v1',
          passive_local_scan_only: true,
          backend_started: true,
          sample_executed_by_tool: false,
          network_accessed_by_tool: false,
          match_floor_met: true,
          string_offset_evidence_available: true,
          dominant_confidence: 'high',
        },
        recommended_next_tools: [
          'artifact.read',
          'analysis.evidence.graph',
          'report.generate',
          'malware.intel.loop',
          'ioc.export',
        ],
      }
    )

    const result = await createEvidenceGraphHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.plugin_evidence_summary.evidence_by_source_artifact_type.backend_yara_scan).toBe(4)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_yara_scan' &&
          node.category === 'signatures' &&
          node.details?.plugin_evidence_kind === 'capability' &&
          node.details?.value === 'SuspiciousUnitFamily' &&
          node.details?.recommended_tools?.includes('malware.intel.loop') &&
          node.details?.string_evidence_count === 1
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_yara_scan' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.quality_gates?.dominant_confidence === 'high' &&
          node.details?.rule_provenance?.ruleset_version === 'rules-v2'
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'backend_yara_scan' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.recommended_tools?.includes('analysis.evidence.graph')
      )
    ).toBe(true)
  })

  test('adds generic workflow handoff evidence for allowlisted artifacts', async () => {
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'binary_diff',
      'binary_diff',
      {
        schema: 'rikune.binary_diff.result.v1',
        sample_id_a: SAMPLE_ID,
        sample_id_b: `sha256:${'5'.repeat(64)}`,
        evidence_summary: {
          schema: 'rikune.binary_diff.evidence_summary.v1',
          artifact_type: 'binary_diff',
          evidence_kind: 'binary-diff',
          source_tool: 'binary.diff',
          delta_counts: {
            sections: { added: 1, removed: 0, size_changed: 1 },
            imports: { added: 2, removed: 1, common: 8 },
          },
          recommended_next_tools: [
            'binary.diff.summary',
            'analysis.evidence.graph',
            'report.generate',
          ],
        },
        workflow_handoff: {
          schema: 'rikune.binary_diff.workflow_handoff.v1',
          handoff_mode: 'binary_diff_to_summary_graph_and_report',
          recommended_next_tools: [
            'binary.diff.summary',
            'analysis.evidence.graph',
            'report.generate',
          ],
          routing: [
            {
              goal: 'structural-delta',
              next_tools: ['analysis.evidence.graph', 'report.generate', 'artifact.read'],
              evidence: ['imports', 'exports', 'sections', 'strings'],
            },
          ],
        },
        quality_gates: {
          schema: 'rikune.binary_diff.quality_gates.v1',
          static_only: true,
          structural_delta_available: true,
          has_diff_signal: true,
        },
      }
    )

    const result = await createEvidenceGraphHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.plugin_evidence_summary.evidence_by_source_artifact_type.binary_diff).toBe(2)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'binary_diff' &&
          node.category === 'binary_diff' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.evidence_summary_schema === 'rikune.binary_diff.evidence_summary.v1' &&
          node.details?.quality_gates?.static_only === true &&
          node.details?.recommended_tools?.includes('binary.diff.summary')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'binary_diff' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.value === 'structural-delta' &&
          node.details?.recommended_tools?.includes('analysis.evidence.graph')
      )
    ).toBe(true)
  })

  test('adds generic workflow handoff evidence for passive inventory profiles', async () => {
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'metadata',
      'metadata-profile',
      buildMetadataExtractProfile({
        sampleId: SAMPLE_ID,
        metadata: {
          'File:FileType': 'ZIP',
          'File:MIMEType': 'application/zip',
          'File:FileSize': '42 KiB',
          'ZIP:ZipRequiredVersion': 20,
        },
      })
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'container_structure',
      'container-structure',
      {
        schema: 'rikune.container_structure.v1',
        evidence_summary: {
          schema: 'rikune.container_structure.evidence_summary.v1',
          artifact_type: 'container_structure',
          evidence_kind: 'container-structure',
          source_tool: 'container.structure.analyze',
          container_format: 'zip',
          entry_count: 2,
          nested_candidate_count: 1,
          risk_flags: ['path-traversal'],
          static_only: true,
        },
        workflow_handoff: {
          schema: 'rikune.container_structure.workflow_handoff.v1',
          handoff_mode: 'container_structure_to_nested_artifact_evidence_and_safe_extraction',
          recommended_next_tools: [
            'artifact.read',
            'container.structure.analyze',
            'analysis.evidence.graph',
            'report.generate',
          ],
          routing: [
            {
              goal: 'extraction-risk-review',
              priority: 'high',
              next_tools: ['artifact.read', 'analysis.evidence.graph'],
              required_evidence: ['risk_flags', 'extraction_plan', 'container_profile'],
            },
            {
              goal: 'nested-artifact-routing',
              priority: 'high',
              next_tools: ['pe.structure.analyze', 'analysis.evidence.graph'],
              required_evidence: ['nested_binary_candidates', 'nested_routes'],
            },
          ],
        },
        quality_gates: {
          schema: 'rikune.container_structure.quality_gates.v1',
          passive_static_inventory: true,
          bounded_preview_only: true,
          path_traversal_review_required: true,
          sample_executed_by_tool: false,
          extraction_performed_by_tool: false,
          entrypoint_executed_by_tool: false,
        },
        recommended_next_tools: [
          'artifact.read',
          'container.structure.analyze',
          'analysis.evidence.graph',
          'report.generate',
        ],
      }
    )
    await persistStaticAnalysisJsonArtifact(
      workspaceManager,
      database,
      SAMPLE_ID,
      'windows_installer_inventory',
      'windows-installer-inventory',
      buildWindowsInstallerInventoryFromBuffer(
        Buffer.concat([
          localZip(['AppxManifest.xml', 'VFS/Demo.exe', 'scripts/install.ps1']),
          Buffer.from('CustomAction Binary.Demo VFS/Demo.dll install.ps1'),
        ]),
        { filename: 'demo.msix', sampleId: SAMPLE_ID }
      )
    )

    const result = await createEvidenceGraphHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.plugin_evidence_summary.evidence_by_source_artifact_type.metadata).toBe(3)
    expect(data.plugin_evidence_summary.evidence_by_source_artifact_type.container_structure).toBe(
      3
    )
    expect(
      data.plugin_evidence_summary.evidence_by_source_artifact_type.windows_installer_inventory
    ).toBe(4)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'metadata' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.evidence_summary_schema === 'rikune.metadata_extract.evidence_summary.v1' &&
          node.details?.recommended_tools?.includes('container.structure.analyze')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'metadata' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.value === 'format-specific-inventory' &&
          node.details?.recommended_tools?.includes('container.structure.analyze')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'container_structure' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.evidence_summary_schema ===
            'rikune.container_structure.evidence_summary.v1' &&
          node.details?.quality_gates?.path_traversal_review_required === true
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'container_structure' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.value === 'nested-artifact-routing' &&
          node.details?.recommended_tools?.includes('pe.structure.analyze')
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'windows_installer_inventory' &&
          node.details?.plugin_evidence_kind === 'triage_signal' &&
          node.details?.evidence_summary_schema ===
            'rikune.windows_installer_inventory.evidence_summary.v1' &&
          node.details?.quality_gates?.custom_action_candidates_present === true &&
          node.details?.quality_gates?.sample_executed_by_tool === false
      )
    ).toBe(true)
    expect(
      data.graph.nodes.some(
        (node: any) =>
          node.kind === 'plugin_evidence' &&
          node.source === 'windows_installer_inventory' &&
          node.details?.plugin_evidence_kind === 'workflow_route' &&
          node.details?.value === 'windows-runtime-plan-only' &&
          node.details?.recommended_tools?.includes('windows.runtime.plan')
      )
    ).toBe(true)
  })
})
