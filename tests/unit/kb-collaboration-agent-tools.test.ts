import { describe, expect, test } from '@jest/globals'
import kbCollaborationPlugin from '../../src/plugins/kb-collaboration/index.js'

describe('kb-collaboration agent workspace tools', () => {
  test('registers the Claim, Case Workspace, and Context Pack surfaces together', () => {
    const registered: string[] = []
    const server = {
      registerTool(definition: { name: string }) {
        registered.push(definition.name)
      },
    }
    const dependencies = {
      workspaceManager: {},
      database: {},
    }

    const returned = kbCollaborationPlugin.register(server as never, dependencies as never)

    expect(kbCollaborationPlugin.version).toBe('1.3.0')
    expect(kbCollaborationPlugin.aspects?.capabilities).toEqual(
      expect.arrayContaining(['claim-ledger', 'case-workspace', 'analysis-context-pack'])
    )
    expect(registered).toEqual(
      expect.arrayContaining([
        'analysis.claims.apply',
        'analysis.case.checkpoint',
        'analysis.case.snapshot',
        'analysis.context.pack',
      ])
    )
    expect(returned).toEqual(registered)
  })
})
