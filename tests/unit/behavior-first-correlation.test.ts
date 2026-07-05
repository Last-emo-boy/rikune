import { describe, expect, test } from '@jest/globals'
import {
  buildBehaviorDiff,
  buildEvidenceGraph,
  categoriesCompatible,
  type EvidenceCorrelationBundle,
} from '../../src/artifacts/evidence-correlation.js'
import { createEvidenceTimelineEntry } from '../../src/plugins/sdk.js'

describe('behavior-first evidence correlation', () => {
  test('correlates static import and network expectations with runtime, PCAP, memory, and host evidence', () => {
    const bundle: EvidenceCorrelationBundle = {
      sample_id: 'sha256:behavior',
      static_artifacts: [
        {
          artifact: {
            id: 'static-imports',
            type: 'static_config_carver',
            path: 'static/imports.json',
            sha256: '1'.repeat(64),
          },
          payload: {},
        },
        {
          artifact: {
            id: 'memory-modules',
            type: 'memory_forensics',
            path: 'memory/modules.json',
            sha256: '2'.repeat(64),
          },
          payload: {},
        },
      ],
      dynamic_summary: {
        artifact_count: 3,
        artifact_types: ['dynamic_trace_json', 'pcap_analysis', 'memory_forensics'],
        artifact_families: ['dynamic_trace', 'pcap', 'memory'],
        executed: true,
        scope_note: 'unit-test',
        observed_apis: ['InternetConnectW', 'RegSetValueExW', 'VirtualQuery'],
        high_signal_apis: ['InternetConnectW'],
        stages: ['network', 'registry_operations', 'memory_map'],
        memory_regions: ['module:demo.dll'],
      } as any,
      expectations: [
        {
          id: 'expect:import:internet',
          category: 'network',
          label: 'static_import:InternetConnectW',
          value: 'InternetConnectW',
          confidence: 0.9,
          source_artifact_id: 'static-imports',
          source_artifact_type: 'static_config_carver',
          evidence: ['import_table'],
        },
        {
          id: 'expect:pcap:c2',
          category: 'network',
          label: 'network_string:c2.example.test',
          value: 'c2.example.test',
          confidence: 0.85,
          source_artifact_id: 'static-imports',
          source_artifact_type: 'static_config_carver',
          evidence: ['string_table', 'pcap_dns_hint'],
        },
        {
          id: 'expect:memory:module',
          category: 'memory',
          label: 'memory_module:demo.dll',
          value: 'demo.dll',
          confidence: 0.8,
          source_artifact_id: 'memory-modules',
          source_artifact_type: 'memory_forensics',
          evidence: ['loaded_module'],
        },
      ],
      observations: [
        {
          id: 'obs:api:internet',
          category: 'network',
          label: 'api:InternetConnectW',
          value: 'InternetConnectW',
          confidence: 0.9,
          source: 'dynamic_trace',
          evidence: ['api_call'],
        },
        {
          id: 'obs:pcap:dns',
          category: 'network',
          label: 'pcap:dns:c2.example.test',
          value: 'c2.example.test',
          confidence: 0.88,
          source: 'pcap_analysis',
          evidence: ['dns_flow'],
        },
        {
          id: 'obs:memory:module',
          category: 'memory',
          label: 'module:demo.dll',
          value: 'demo.dll',
          confidence: 0.82,
          source: 'memory_forensics',
          evidence: ['module_list'],
        },
      ],
      warnings: [],
    }

    const graph = buildEvidenceGraph(bundle)
    const diff = buildBehaviorDiff(bundle)

    expect(categoriesCompatible('network', 'network')).toBe(true)
    expect(categoriesCompatible('memory', 'memory')).toBe(true)
    expect(graph.edges.filter((edge) => edge.label === 'corroborated_by').length).toBeGreaterThanOrEqual(3)
    expect(diff.confirmed_behaviors.map((item) => item.category)).toEqual(
      expect.arrayContaining(['network', 'memory'])
    )
    expect(diff.coverage.dynamic_executed).toBe(true)
    expect(diff.recommended_next_tools).toContain('analysis.evidence.graph')
  })

  test('normalizes EvidenceTimeline coverage for cross-platform behavior sources', () => {
    const entries = [
      createEvidenceTimelineEntry({
        source: 'windows-runtime',
        toolName: 'windows.runtime.plan',
        category: 'registry',
        action: 'set-value',
        target: 'HKCU\\Software\\Run',
      }),
      createEvidenceTimelineEntry({
        source: 'linux-runtime',
        toolName: 'linux.runtime.plan',
        category: 'syscalls',
        action: 'openat',
        target: '/tmp/payload',
      }),
      createEvidenceTimelineEntry({
        source: 'macos-runtime',
        toolName: 'macos.runtime.plan',
        category: 'filesystem',
        action: 'fs_usage',
        target: '/Users/demo/Library',
      }),
      createEvidenceTimelineEntry({
        source: 'android-runtime',
        toolName: 'android.runtime.plan',
        category: 'method-calls',
        action: 'hook',
        target: 'okhttp3.CertificatePinner',
      }),
      createEvidenceTimelineEntry({
        source: 'ios-runtime',
        toolName: 'ios.runtime.plan',
        category: 'method-calls',
        action: 'hook',
        target: '-[NSURLSession dataTaskWithRequest:]',
      }),
      createEvidenceTimelineEntry({
        source: 'pcap-analysis',
        toolName: 'pcap.analyze',
        category: 'network',
        action: 'dns',
        target: 'c2.example.test',
      }),
      createEvidenceTimelineEntry({
        source: 'memory-forensics',
        toolName: 'memory-forensics.malfind',
        category: 'memory',
        action: 'module',
        target: 'demo.dll',
      }),
    ]

    expect(entries.map((entry) => entry.category)).toEqual(
      expect.arrayContaining([
        'registry',
        'syscalls',
        'filesystem',
        'method-calls',
        'network',
        'memory',
      ])
    )
    expect(entries.every((entry) => entry.source && entry.toolName)).toBe(true)
  })
})
