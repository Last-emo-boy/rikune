/**
 * Unit tests for dynamic.deep_plan.
 */

import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createDynamicDeepPlanHandler,
  dynamicDeepPlanToolDefinition,
} from '../../src/plugins/dynamic/tools/dynamic-deep-plan.js'

describe('dynamic.deep_plan tool', () => {
  test('exports a planning-only dynamic profile tool', () => {
    expect(dynamicDeepPlanToolDefinition.name).toBe('dynamic.deep_plan')
    expect(dynamicDeepPlanToolDefinition.description).toContain('Does not launch or execute')
  })

  test('includes all advanced dynamic directions when goals=all', async () => {
    const result = await createDynamicDeepPlanHandler({} as any)({
      sample_id: `sha256:${'f'.repeat(64)}`,
      goals: ['all'],
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    const profileIds = data.profiles.map((profile: any) => profile.id)
    expect(profileIds).toEqual(expect.arrayContaining([
      'behavior_capture',
      'debugger_cdb',
      'memory_dump',
      'telemetry_procmon_sysmon',
      'network_lab',
      'dotnet_runtime',
      'anti_evasion',
      'ttd_recording',
      'manual_gui_debug',
    ]))
    expect(data.safety.mcp_connect_starts_runtime).toBe(false)
    expect(data.recommended_next_tools).toContain('dynamic.toolkit.status')
  })

  test('can suppress GUI and heavy profiles for lightweight planning', async () => {
    const result = await createDynamicDeepPlanHandler({} as any)({
      goals: ['all'],
      include_gui_profiles: false,
      include_heavy_profiles: false,
    })

    const profileIds = ((result.data as any).profiles as any[]).map((profile) => profile.id)
    expect(profileIds).not.toContain('manual_gui_debug')
    expect(profileIds).not.toContain('ttd_recording')
    expect(profileIds).not.toContain('telemetry_procmon_sysmon')
  })

  test('uses static behavior classifier artifacts to infer runtime focus', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-dynamic-deep-plan-'))
    const workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    const database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    const sampleHash = '9'.repeat(64)
    const sampleId = `sha256:${sampleHash}`

    try {
      database.insertSample({
        id: sampleId,
        sha256: sampleHash,
        md5: '9'.repeat(32),
        size: 16,
        file_type: 'PE32 executable',
        created_at: new Date().toISOString(),
        source: 'unit-test',
      })
      await workspaceManager.createWorkspace(sampleId)
      await persistStaticAnalysisJsonArtifact(workspaceManager, database, sampleId, 'static_behavior_classifier', 'behavior_classifier', {
        schema: 'rikune.static_behavior_classifier.v1',
        summary: { finding_count: 1, high_or_critical_count: 1 },
        findings: [
          {
            id: 'injection.remote_thread',
            category: 'injection',
            technique: 'Remote thread process injection',
            severity: 'critical',
            confidence: 0.94,
            evidence: [
              { source: 'string', kind: 'api_match', value: 'WriteProcessMemory' },
              { source: 'string', kind: 'api_match', value: 'CreateRemoteThread' },
            ],
            recommended_next_tools: ['breakpoint.smart', 'trace.condition'],
          },
        ],
      }, 'runtime-focus')

      const result = await createDynamicDeepPlanHandler({ workspaceManager, database } as any)({
        sample_id: sampleId,
        goals: ['behavior'],
        static_artifact_scope: 'session',
        static_artifact_session_tag: 'runtime-focus',
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.selected_goals).toEqual(expect.arrayContaining(['behavior', 'debugger', 'memory']))
      expect(data.static_behavior_context.artifact_ids).toHaveLength(1)
      expect(data.static_behavior_context.breakpoint_targets).toEqual(expect.arrayContaining(['WriteProcessMemory', 'CreateRemoteThread']))
      expect(data.recommended_next_tools).toEqual(expect.arrayContaining(['breakpoint.smart', 'trace.condition']))
      const profileIds = data.profiles.map((profile: any) => profile.id)
      expect(profileIds).toEqual(expect.arrayContaining(['behavior_capture', 'debugger_cdb', 'memory_dump']))
      expect(data.profiles[0].evidence_hooks.length).toBeGreaterThan(0)
    } finally {
      database.close()
      fs.rmSync(tempRoot, { recursive: true, force: true })
    }
  })
})
