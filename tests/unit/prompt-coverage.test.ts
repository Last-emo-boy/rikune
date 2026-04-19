import { describe, test, expect } from '@jest/globals'
import fs from 'fs'
import path from 'path'

function collectPromptDefinitions(dirPath: string): Array<{ file: string; definition: string }> {
  const results: Array<{ file: string; definition: string }> = []

  if (!fs.existsSync(dirPath)) {
    return results
  }

  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    if (!entry.isFile() || !entry.name.endsWith('.ts')) {
      continue
    }

    const fullPath = path.join(dirPath, entry.name)
    const content = fs.readFileSync(fullPath, 'utf-8')
    const matches = content.matchAll(/export const (\w+PromptDefinition): PromptDefinition/g)

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
  return Array.from(content.matchAll(/server\.registerPrompt\(\s*(\w+PromptDefinition)\s*,/g)).map(
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

describe('index.ts prompt coverage', () => {
  test('should register every exported prompt definition', () => {
    const repoRoot = process.cwd()
    const registrations = new Set<string>([
      ...collectRegistrationsFromFile(path.join(repoRoot, 'src', 'tool-registry.ts')),
      ...collectRegistrationsFromFile(path.join(repoRoot, 'src', 'core', 'tool-registry.ts')),
      ...collectRegistrationsFromDir(path.join(repoRoot, 'src', 'core', 'tool-registry')),
    ])

    const promptDefinitions = collectPromptDefinitions(path.join(repoRoot, 'src', 'prompts'))
    const missing = promptDefinitions.filter((item) => !registrations.has(item.definition))

    expect(missing).toEqual([])
  })
})
