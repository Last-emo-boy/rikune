import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import {
  RUNTIME_TOOL_PROFILE_DEFINITIONS,
  RUNTIME_TOOL_SPECS,
} from '../../../packages/runtime-node/src/toolkit/manifest.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(__dirname, '../../..')

describe('runtime toolkit manifest', () => {
  test('uses unique tool and profile identifiers', () => {
    const toolIds = RUNTIME_TOOL_SPECS.map((tool) => tool.id)
    const profileIds = RUNTIME_TOOL_PROFILE_DEFINITIONS.map((profile) => profile.id)

    expect(new Set(toolIds).size).toBe(toolIds.length)
    expect(new Set(profileIds).size).toBe(profileIds.length)
  })

  test('tool profile references and profile tool references are valid', () => {
    const toolIds = new Set(RUNTIME_TOOL_SPECS.map((tool) => tool.id))
    const profileIds = new Set(RUNTIME_TOOL_PROFILE_DEFINITIONS.map((profile) => profile.id))

    const invalidToolProfiles = RUNTIME_TOOL_SPECS.flatMap((tool) =>
      tool.profiles
        .filter((profileId) => !profileIds.has(profileId))
        .map((profileId) => `${tool.id}:${profileId}`)
    )
    const invalidProfileTools = RUNTIME_TOOL_PROFILE_DEFINITIONS.flatMap((profile) =>
      [...profile.requiredTools, ...profile.optionalTools]
        .filter((toolId) => !toolIds.has(toolId))
        .map((toolId) => `${profile.id}:${toolId}`)
    )

    expect(invalidToolProfiles).toEqual([])
    expect(invalidProfileTools).toEqual([])
  })

  test('executor does not own runtime toolkit manifest data', () => {
    const executorSource = fs.readFileSync(
      path.join(repoRoot, 'packages/runtime-node/src/executor.ts'),
      'utf8'
    )

    expect(executorSource).not.toContain('const RUNTIME_TOOL_SPECS')
    expect(executorSource).not.toContain('const RUNTIME_TOOL_PROFILE_DEFINITIONS')
  })
})
