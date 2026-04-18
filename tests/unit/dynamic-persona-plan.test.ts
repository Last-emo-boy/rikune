import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createDynamicPersonaPlanHandler,
  dynamicPersonaPlanToolDefinition,
} from '../../src/plugins/dynamic/tools/dynamic-persona-plan.js'

const SAMPLE_HASH = '3'.repeat(64)
const SAMPLE_ID = `sha256:${SAMPLE_HASH}`

describe('dynamic.persona.plan tool', () => {
  let tempRoot: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-persona-plan-'))
    workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    database.insertSample({
      id: SAMPLE_ID,
      sha256: SAMPLE_HASH,
      md5: '3'.repeat(32),
      size: 2,
      file_type: 'PE32 executable',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
  })

  afterEach(() => {
    try {
      database.close()
    } catch {
      // ignore cleanup races in failed tests
    }
    fs.rmSync(tempRoot, { recursive: true, force: true })
  })

  test('exports a planning-only runtime persona tool definition', () => {
    expect(dynamicPersonaPlanToolDefinition.name).toBe('dynamic.persona.plan')
    expect(dynamicPersonaPlanToolDefinition.description).toContain('Does not launch')
  })

  test('builds an office persona checklist without starting runtime', async () => {
    const result = await createDynamicPersonaPlanHandler({ workspaceManager, database } as any)({
      profile: 'office_user',
      runtime_backend: 'hyperv-vm',
      include_office_artifacts: true,
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.dynamic_persona_plan.v1')
    expect(data.profile).toBe('office_user')
    expect(data.safety.planning_only).toBe(true)
    expect(data.safety.starts_runtime).toBe(false)
    expect(data.preparation_steps[1].registry).toContain('HKCU\\Software\\Microsoft\\Office')
    expect(data.recommended_next_tools).toContain('dynamic.behavior.capture')
    expect(result.artifacts).toHaveLength(0)
  })

  test('persists a sample-bound persona plan artifact when requested', async () => {
    const result = await createDynamicPersonaPlanHandler({ workspaceManager, database } as any)({
      sample_id: SAMPLE_ID,
      profile: 'developer_workstation',
      session_tag: 'persona-session',
    })

    expect(result.ok).toBe(true)
    expect(result.artifacts?.[0]?.type).toBe('dynamic_persona_plan')
    const artifacts = database.findArtifactsByType(SAMPLE_ID, 'dynamic_persona_plan')
    expect(artifacts).toHaveLength(1)
  })
})
