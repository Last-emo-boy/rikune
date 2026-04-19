/**
 * Unit tests for debug.gui.handoff.
 */

import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import os from 'os'
import path from 'path'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import {
  createDebugGuiHandoffHandler,
  debugGuiHandoffToolDefinition,
} from '../../src/plugins/dynamic/tools/debug-gui-handoff.js'

describe('debug.gui.handoff tool', () => {
  test('exports a planning-only GUI handoff tool', () => {
    expect(debugGuiHandoffToolDefinition.name).toBe('debug.gui.handoff')
    expect(debugGuiHandoffToolDefinition.description).toContain('Does not launch GUI tools')
  })

  test('builds handoff profiles and preserve_dirty runtime template', async () => {
    const result = await createDebugGuiHandoffHandler({} as any)({
      sample_id: `sha256:${'8'.repeat(64)}`,
      tools: ['all'],
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(data.schema).toBe('rikune.debug_gui_handoff.v1')
    expect(data.selected_tools).toEqual(['x64dbg', 'windbg', 'dnspy'])
    expect(data.runtime_session_template.args.hyperv_retention_policy).toBe('preserve_dirty')
    expect(data.handoff_profiles.map((profile: any) => profile.id)).toEqual(expect.arrayContaining([
      'x64dbg_manual_review',
      'windbg_manual_review',
      'dnspy_manual_review',
    ]))
    expect(data.safety.launches_gui).toBe(false)
  })

  test('persists GUI handoff artifacts when a sample exists', async () => {
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rikune-gui-handoff-'))
    const workspaceManager = new WorkspaceManager(path.join(tempRoot, 'workspaces'))
    const database = new DatabaseManager(path.join(tempRoot, 'rikune.db'))
    const sampleHash = '8'.repeat(64)
    const sampleId = `sha256:${sampleHash}`

    try {
      database.insertSample({
        id: sampleId,
        sha256: sampleHash,
        md5: '8'.repeat(32),
        size: 16,
        file_type: 'PE32 executable',
        created_at: new Date().toISOString(),
        source: 'unit-test',
      })
      await workspaceManager.createWorkspace(sampleId)

      const result = await createDebugGuiHandoffHandler({ workspaceManager, database } as any)({
        sample_id: sampleId,
        tools: ['windbg'],
        session_tag: 'gui-session',
      })

      expect(result.ok).toBe(true)
      expect(result.artifacts?.[0]?.type).toBe('debug_gui_handoff')
    } finally {
      database.close()
      fs.rmSync(tempRoot, { recursive: true, force: true })
    }
  })
})
