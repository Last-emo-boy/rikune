import { describe, test, expect } from '@jest/globals'
import fs from 'fs'
import path from 'path'

function collectToolDefinitions(dirPath: string): Array<{ file: string; definition: string }> {
  const results: Array<{ file: string; definition: string }> = []

  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.ts')) {
      continue
    }

    const fullPath = path.join(dirPath, entry.name)
    const content = fs.readFileSync(fullPath, 'utf-8')
    const matches = content.matchAll(/export const (\w+ToolDefinition): ToolDefinition/g)

    for (const match of matches) {
      results.push({
        file: path.relative(process.cwd(), fullPath),
        definition: match[1],
      })
    }
  }

  return results
}

describe('index.ts route coverage', () => {
  test('should register every exported tool definition', () => {
    const repoRoot = process.cwd()
    const indexPath = path.join(repoRoot, 'src', 'index.ts')
    const indexContent = fs.readFileSync(indexPath, 'utf-8')
    const registrations = new Set(
      Array.from(indexContent.matchAll(/server\.registerTool\(\s*(\w+ToolDefinition)\s*,/g)).map(
        (match) => match[1]
      )
    )

    const toolDefinitions = [
      ...collectToolDefinitions(path.join(repoRoot, 'src', 'tools')),
      ...collectToolDefinitions(path.join(repoRoot, 'src', 'workflows')),
    ]

    const missing = toolDefinitions.filter((item) => !registrations.has(item.definition))

    expect(missing).toEqual([])
  })
})
