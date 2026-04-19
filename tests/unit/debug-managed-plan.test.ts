/**
 * Unit tests for debug.managed.plan.
 */

import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createDebugManagedPlanHandler,
  debugManagedPlanToolDefinition,
} from '../../src/plugins/dynamic/tools/debug-managed-plan.js'

describe('debug.managed.plan tool', () => {
  test('exports a planning-only managed runtime tool', () => {
    expect(debugManagedPlanToolDefinition.name).toBe('debug.managed.plan')
    expect(debugManagedPlanToolDefinition.description).toContain('does not execute samples')
  })

  test('builds safe-run and SOS command templates', async () => {
    const result = await createDebugManagedPlanHandler({} as any)({
      sample_id: `sha256:${'e'.repeat(64)}`,
      profiles: ['safe_run', 'sos_stack', 'managed_dump'],
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.debug_managed_plan.v1')
    expect(data.selected_profiles).toEqual(expect.arrayContaining(['safe_run', 'sos_stack', 'managed_dump']))
    expect(data.runtime_command_sequence.map((entry: any) => entry.args.tool)).toEqual(expect.arrayContaining([
      'managed.safe_run',
      'debug.session.command_batch',
      'debug.procdump.capture',
    ]))
    expect(data.safety.executes_sample).toBe(false)
  })

  test('uses .NET metadata artifacts for managed context', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-managed-plan-'))
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
        file_type: '.NET executable',
        created_at: new Date().toISOString(),
        source: 'unit-test',
      })
      await workspaceManager.createWorkspace(sampleId)
      await persistStaticAnalysisJsonArtifact(workspaceManager, database, sampleId, 'dotnet_metadata', 'metadata', {
        schema: 'rikune.dotnet_metadata.v1',
        is_dotnet: true,
        assembly_name: 'ManagedSample',
        target_framework: '.NETFramework,Version=v4.8',
        types: [{ full_name: 'ManagedSample.Program', method_count: 3 }],
        resources: [{ name: 'ManagedSample.Properties.Resources' }],
      }, 'managed-session')

      const result = await createDebugManagedPlanHandler({ workspaceManager, database } as any)({
        sample_id: sampleId,
        profiles: ['resource_review', 'dnspy_handoff'],
        static_artifact_scope: 'session',
        static_artifact_session_tag: 'managed-session',
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.dotnet_metadata_context.artifact_ids).toHaveLength(1)
      expect(data.dotnet_metadata_context.assemblies).toEqual(['ManagedSample'])
      expect(data.dotnet_metadata_context.notable_types).toEqual(['ManagedSample.Program'])
      expect(result.artifacts?.[0]?.type).toBe('debug_managed_plan')
    } finally {
      database.close()
      fs.rmSync(tempRoot, { recursive: true, force: true })
    }
  })
})
