/**
 * Unit tests for debug.procdump.plan.
 */

import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createDebugProcDumpPlanHandler,
  debugProcDumpPlanToolDefinition,
} from '../../src/plugins/dynamic/tools/debug-procdump-plan.js'

describe('debug.procdump.plan tool', () => {
  test('exports a planning-only ProcDump tool', () => {
    expect(debugProcDumpPlanToolDefinition.name).toBe('debug.procdump.plan')
    expect(debugProcDumpPlanToolDefinition.description).toContain('does not start or execute')
  })

  test('builds runtime.debug.command templates for crash capture', async () => {
    const sampleId = `sha256:${'b'.repeat(64)}`
    const result = await createDebugProcDumpPlanHandler({} as any)({
      sample_id: sampleId,
      modes: ['launch_crash'],
      dump_type: 'full',
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.debug_procdump_plan.v1')
    expect(data.selected_modes).toContain('launch_crash')
    expect(data.runtime_command_sequence[0].args.tool).toBe('debug.procdump.capture')
    expect(data.runtime_command_sequence[0].args.sample_id).toBe(sampleId)
    expect(data.runtime_command_sequence[0].args.runtime_backend_hint).toMatchObject({
      type: 'inline',
      handler: 'executeProcDumpCapture',
    })
  })

  test('uses static behavior artifacts to suggest richer dump modes', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-procdump-plan-'))
    const workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    const database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    const sampleHash = '6'.repeat(64)
    const sampleId = `sha256:${sampleHash}`

    try {
      database.insertSample({
        id: sampleId,
        sha256: sampleHash,
        md5: '6'.repeat(32),
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
            id: 'injection.remote_thread',
            category: 'injection',
            severity: 'critical',
            confidence: 0.95,
          },
          {
            id: 'anti_analysis.debug_probe',
            category: 'anti_analysis',
            severity: 'high',
            confidence: 0.82,
          },
        ],
      }, 'dump-session')

      const result = await createDebugProcDumpPlanHandler({ workspaceManager, database } as any)({
        sample_id: sampleId,
        modes: ['launch_crash'],
        static_artifact_scope: 'session',
        static_artifact_session_tag: 'dump-session',
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.static_behavior_context.artifact_ids).toHaveLength(1)
      expect(data.selected_modes).toEqual(expect.arrayContaining(['launch_crash', 'launch_first_chance', 'launch_timeout']))
      expect(data.capture_plans.some((plan: any) => plan.mode === 'launch_first_chance')).toBe(true)
    } finally {
      database.close()
      fs.rmSync(tempRoot, { recursive: true, force: true })
    }
  })
})
