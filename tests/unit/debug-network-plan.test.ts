/**
 * Unit tests for debug.network.plan.
 */

import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import { persistStaticAnalysisJsonArtifact } from '../../src/artifacts/static-analysis-artifacts.js'
import {
  createDebugNetworkPlanHandler,
  debugNetworkPlanToolDefinition,
} from '../../src/plugins/dynamic/tools/debug-network-plan.js'

describe('debug.network.plan tool', () => {
  test('exports a planning-only network lab tool', () => {
    expect(debugNetworkPlanToolDefinition.name).toBe('debug.network.plan')
    expect(debugNetworkPlanToolDefinition.description).toContain('does not start services')
  })

  test('builds proxy and ETW DNS runtime templates without executing', async () => {
    const result = await createDebugNetworkPlanHandler({} as any)({
      sample_id: `sha256:${'d'.repeat(64)}`,
      profiles: ['proxy_sinkhole', 'etw_dns'],
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.debug_network_plan.v1')
    expect(data.selected_profiles).toEqual(expect.arrayContaining(['proxy_sinkhole', 'etw_dns']))
    expect(data.runtime_command_sequence).toHaveLength(2)
    expect(data.runtime_command_sequence[0].args.runtime_backend_hint.handler).toBe('executeBehaviorCapture')
    expect(data.safety.starts_services).toBe(false)
  })

  test('loads static config network indicators', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-network-plan-'))
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
      await persistStaticAnalysisJsonArtifact(workspaceManager, database, sampleId, 'static_config_carver', 'config_carver', {
        schema: 'rikune.static_config_carver.v1',
        candidates: [
          { kind: 'url', value: 'http://c2.example.test/panel', confidence: 0.9 },
          { kind: 'registry_path', value: 'HKCU\\Software\\Test', confidence: 0.8 },
        ],
      }, 'network-session')

      const result = await createDebugNetworkPlanHandler({ workspaceManager, database } as any)({
        sample_id: sampleId,
        profiles: ['fakenet'],
        static_artifact_scope: 'session',
        static_artifact_session_tag: 'network-session',
      })

      expect(result.ok).toBe(true)
      const data = result.data as any
      expect(data.static_network_context.artifact_ids).toHaveLength(1)
      expect(data.static_network_context.indicators).toEqual(['http://c2.example.test/panel'])
      expect(data.profiles[0].id).toBe('fakenet_service_lab')
      expect(result.artifacts?.[0]?.type).toBe('debug_network_plan')
    } finally {
      database.close()
      fs.rmSync(tempRoot, { recursive: true, force: true })
    }
  })
})
