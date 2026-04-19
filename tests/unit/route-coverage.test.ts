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

function collectRegistrationsFromFile(filePath: string): string[] {
  if (!fs.existsSync(filePath)) return []
  const content = fs.readFileSync(filePath, 'utf-8')
  return Array.from(content.matchAll(/server\.registerTool\(\s*(\w+ToolDefinition)\s*,/g)).map(
    (match) => match[1]
  )
}

function collectRegistrationsFromDir(dirPath: string): string[] {
  const results: string[] = []
  if (!fs.existsSync(dirPath)) return results
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.ts')) continue
    results.push(...collectRegistrationsFromFile(path.join(dirPath, entry.name)))
  }
  return results
}

describe('index.ts route coverage', () => {
  test('should register every exported tool definition', () => {
    const repoRoot = process.cwd()
    const registrations = new Set<string>([
      ...collectRegistrationsFromFile(path.join(repoRoot, 'src', 'tool-registry.ts')),
      ...collectRegistrationsFromFile(path.join(repoRoot, 'src', 'core', 'tool-registry.ts')),
      ...collectRegistrationsFromDir(path.join(repoRoot, 'src', 'core', 'tool-registry')),
    ])

    // Also scan plugin index files for registrations
    const pluginsDir = path.join(repoRoot, 'src', 'plugins')
    if (fs.existsSync(pluginsDir)) {
      for (const pluginEntry of fs.readdirSync(pluginsDir, { withFileTypes: true })) {
        if (!pluginEntry.isDirectory()) continue
        const pluginIndex = path.join(pluginsDir, pluginEntry.name, 'index.ts')
        if (!fs.existsSync(pluginIndex)) continue
        const pluginContent = fs.readFileSync(pluginIndex, 'utf-8')
        for (const m of pluginContent.matchAll(/server\.registerTool\(\s*(\w+ToolDefinition)\s*,/g)) {
          registrations.add(m[1])
        }
      }
    }

    const toolDefinitions = [
      ...collectToolDefinitions(path.join(repoRoot, 'src', 'tools')),
      ...collectToolDefinitions(path.join(repoRoot, 'src', 'workflows')),
    ]

    // Internal tools used only as helpers by workflow handlers, not exposed as MCP tools
    const internalOnly = new Set([
      'codeFunctionExplainReviewToolDefinition',
      'codeFunctionRenameReviewToolDefinition',
      'codeModuleReviewToolDefinition',
    ])

    const missing = toolDefinitions.filter(
      (item) => !registrations.has(item.definition) && !internalOnly.has(item.definition)
    )

    expect(missing).toEqual([])
  })
})
