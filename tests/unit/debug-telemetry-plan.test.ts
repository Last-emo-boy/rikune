/**
 * Unit tests for debug.telemetry.plan.
 */

import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createDebugTelemetryPlanHandler,
  debugTelemetryPlanToolDefinition,
} from '../../src/plugins/dynamic/tools/debug-telemetry-plan.js'

describe('debug.telemetry.plan tool', () => {
  test('exports a planning-only telemetry tool', () => {
    expect(debugTelemetryPlanToolDefinition.name).toBe('debug.telemetry.plan')
    expect(debugTelemetryPlanToolDefinition.description).toContain('Does not install services')
  })

  test('builds ProcMon and ETW telemetry profiles without executing', async () => {
    const result = await createDebugTelemetryPlanHandler({} as any)({
      sample_id: `sha256:${'c'.repeat(64)}`,
      profiles: ['procmon', 'etw_dns'],
      runtime_backend: 'hyperv-vm',
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.debug_telemetry_plan.v1')
    expect(data.selected_profiles).toEqual(expect.arrayContaining(['procmon', 'etw_dns']))
    expect(data.profiles.find((profile: any) => profile.id === 'procmon_capture').backend_fit).toBe('preferred')
    expect(data.safety.starts_runtime).toBe(false)
    expect(data.recommended_next_tools).toContain('dynamic.behavior.diff')
  })

  test('uses static behavior artifacts to suggest persistence telemetry', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-telemetry-plan-'))
    const workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    const database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    const sampleHash = '5'.repeat(64)
    const sampleId = `sha256:${sampleHash}`

    try {
      database.insertSample({
        id: sampleId,
        sha256: sampleHash,
        md5: '5'.repeat(32),
        size: 16,
        file_type: 'PE32 executable',
        created_at: new Date().toISOString(),
        source: 'unit-test',
      })
      await workspaceManager.createWorkspace(sampleId)
      await persistStaticAnalysisJsonArtifact(workspaceManager, database, sampleId, 'static_behavior_classifier', 'behavior_classifier', {
        schema: 'rikune.static_behavior_classifier.v1',
        findings: [
          {
            id: 'persistence.service_install',
            category: 'persistence',
            severity: 'high',
            confidence: 0.89,
          },
        ],
      }, 'telemetry-session')

      const result = await createDebugTelemetryPlanHandler({ workspaceManager, database } as any)({
        sample_id: sampleId,
        profiles: ['etw_process'],
        static_artifact_scope: 'session',
        static_artifact_session_tag: 'telemetry-session',
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.static_behavior_context.artifact_ids).toHaveLength(1)
      expect(data.selected_profiles).toEqual(expect.arrayContaining(['etw_process', 'procmon', 'sysmon']))
      expect(result.artifacts?.[0]?.type).toBe('debug_telemetry_plan')
    } finally {
      database.close()
      fs.rmSync(tempRoot, { recursive: true, force: true })
    }
  })
})
