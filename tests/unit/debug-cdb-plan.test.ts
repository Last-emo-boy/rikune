/**
 * Unit tests for debug.cdb.plan.
 */

import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createDebugCdbPlanHandler,
  debugCdbPlanToolDefinition,
} from '../../src/plugins/dynamic/tools/debug-cdb-plan.js'

describe('debug.cdb.plan tool', () => {
  test('exports a planning-only CDB automation tool', () => {
    expect(debugCdbPlanToolDefinition.name).toBe('debug.cdb.plan')
    expect(debugCdbPlanToolDefinition.description).toContain('does not start or execute')
  })

  test('builds runtime.debug.command templates for explicit API breakpoints', async () => {
    const result = await createDebugCdbPlanHandler({} as any)({
      sample_id: `sha256:${'a'.repeat(64)}`,
      profiles: ['api_breakpoints'],
      breakpoint_apis: ['WriteProcessMemory', 'ntdll!NtCreateThreadEx'],
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.debug_cdb_plan.v1')
    expect(data.breakpoint_targets).toEqual(expect.arrayContaining(['kernel32!WriteProcessMemory', 'ntdll!NtCreateThreadEx']))
    expect(data.command_batches[0].commands.join('\n')).toContain('bm kernel32!WriteProcessMemory')
    expect(data.runtime_command_sequence[0].args.tool).toBe('debug.session.command_batch')
    expect(data.recommended_next_tools).toContain('runtime.debug.command')
  })

  test('uses static behavior classifier artifacts as breakpoint input', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-cdb-plan-'))
    const workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    const database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    const sampleHash = '7'.repeat(64)
    const sampleId = `sha256:${sampleHash}`

    try {
      database.insertSample({
        id: sampleId,
        sha256: sampleHash,
        md5: '7'.repeat(32),
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
            confidence: 0.93,
            evidence: [
              { kind: 'api_match', value: 'CreateRemoteThread' },
              { kind: 'api_match', value: 'VirtualAllocEx' },
            ],
          },
        ],
      }, 'cdb-session')

      const result = await createDebugCdbPlanHandler({ workspaceManager, database } as any)({
        sample_id: sampleId,
        profiles: ['injection_watch'],
        static_artifact_scope: 'session',
        static_artifact_session_tag: 'cdb-session',
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.static_behavior_context.artifact_ids).toHaveLength(1)
      expect(data.breakpoint_targets).toEqual(expect.arrayContaining(['kernel32!CreateRemoteThread', 'kernel32!VirtualAllocEx']))
      expect(data.command_batches.some((batch: any) => batch.id === 'injection_watch_batch')).toBe(true)
    } finally {
      database.close()
      fs.rmSync(tempRoot, { recursive: true, force: true })
    }
  })
})
