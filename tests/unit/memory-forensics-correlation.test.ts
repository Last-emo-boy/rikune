import { describe, expect, test } from '@jest/globals'
import { createPluginTestHarness } from '../../src/plugins/sdk.js'
import memoryForensicsPlugin from '../../src/plugins/memory-forensics/index.js'
import { buildMemoryForensicsCorrelation } from '../../src/plugins/memory-forensics/memory-correlation.js'

describe('memory-forensics.correlate', () => {
  test('correlates fixture Volatility rows without invoking Volatility', () => {
    const result = buildMemoryForensicsCorrelation({
      sample_id: 'sha256:mem',
      pslist: [
        { PID: 400, PPID: 4, ImageFileName: 'svchost.exe' },
        { PID: 1337, PPID: 400, ImageFileName: 'payload.exe' },
      ],
      cmdline: [{ PID: 1337, Process: 'payload.exe', CommandLine: 'payload.exe --install' }],
      malfind: [
        {
          PID: 1337,
          Process: 'payload.exe',
          StartVPN: '0x401000',
          Protection: 'PAGE_EXECUTE_READWRITE',
        },
      ],
      netscan: [
        {
          PID: 1337,
          Owner: 'payload.exe',
          LocalAddr: '10.0.0.4',
          LocalPort: 49712,
          ForeignAddr: '203.0.113.8',
          ForeignPort: 443,
          State: 'ESTABLISHED',
        },
      ],
      hivelist: [{ FileFullName: '\\SystemRoot\\System32\\Config\\SOFTWARE' }],
      dlllist: [{ PID: 1337, Process: 'payload.exe', Name: 'ws2_32.dll' }],
    })

    expect(result.result_mode).toBe('memory_forensics_correlation')
    expect(result.finding_bundle.process_count).toBe(2)
    expect(result.finding_bundle.suspicious_region_count).toBe(1)
    expect(result.ioc_candidates).toEqual([
      expect.objectContaining({
        type: 'network',
        value: '203.0.113.8',
        port: 443,
        source: 'memory-forensics.netscan',
      }),
    ])
    expect(result.behavior_timeline).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ action: 'command_line', pid: 1337 }),
        expect.objectContaining({ action: 'suspicious_region', pid: 1337 }),
        expect.objectContaining({ action: 'connection', pid: 1337 }),
      ])
    )
    expect(result.correlation_graph.nodes.map((node: any) => node.type)).toEqual(
      expect.arrayContaining(['process', 'network', 'module'])
    )
    expect(result.provenance_graph.sources.map((source: any) => source.source)).toEqual(
      expect.arrayContaining([
        'memory-forensics.pslist',
        'memory-forensics.malfind',
        'memory-forensics.netscan',
      ])
    )
    expect(result.recommended_next_tools).toEqual(
      expect.arrayContaining(['threat-intel.ioc-export', 'report.generate'])
    )
    expect(result.safety_notes.join(' ')).toMatch(/No memory dump acquisition/)
  })

  test('registers offline correlation metadata and workflow recipe', async () => {
    const harness = createPluginTestHarness()
    const names = harness.registerPlugin(memoryForensicsPlugin)
    const tool = harness.registeredTools.find(
      (candidate) => candidate.definition.name === 'memory-forensics.correlate'
    )

    expect(names).toContain('memory-forensics.correlate')
    expect(tool?.definition.artifacts?.map((artifact) => artifact.type)).toEqual(
      expect.arrayContaining([
        'memory_forensics_correlation',
        'behavior_timeline',
        'ioc_candidates',
      ])
    )
    expect(tool?.definition.evidence?.map((entry) => entry.category)).toEqual(
      expect.arrayContaining(['memory', 'process', 'network', 'registry', 'behavior'])
    )
    expect(tool?.definition.workflowRecipes?.[0]).toEqual(
      expect.objectContaining({
        id: 'memory-forensics.offline-correlation',
        nextTools: expect.arrayContaining(['threat-intel.ioc-export', 'report.generate']),
      })
    )

    const result = (await tool?.handler({
      sources: { netscan: [{ PID: 7, Owner: 'proc.exe', ForeignAddr: '198.51.100.2' }] },
    })) as any
    expect(result.structuredContent.result_mode).toBe('memory_forensics_correlation')
  })
})
