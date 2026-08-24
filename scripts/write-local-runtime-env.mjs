#!/usr/bin/env node

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  readPrivateUtf8File,
  pathEntryExists,
  removeProtectedExistingFile,
  resolveAnalyzerApiKey,
  writePrivateUtf8File,
} from './write-docker-runtime-env.mjs'

const API_KEY_PLACEHOLDER = '__RIKUNE_CSPRNG_API_KEY__'

function normalizeTemplate(content) {
  const normalized = String(content ?? '').replace(/\r\n?/gu, '\n')
  if (normalized.includes('\0')) throw new Error('Local runtime env template cannot contain NUL')
  return normalized.endsWith('\n') ? normalized : `${normalized}\n`
}

export function parseStrictLocalEnv(content) {
  const values = new Map()
  for (const line of normalizeTemplate(content).split('\n')) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const separator = trimmed.indexOf('=')
    if (separator <= 0) throw new Error(`Invalid local runtime env entry: ${trimmed}`)
    const name = trimmed.slice(0, separator).trim()
    const value = trimmed.slice(separator + 1).trim()
    if (!/^[A-Z][A-Z0-9_]*$/u.test(name)) {
      throw new Error(`Invalid local runtime env variable name: ${name}`)
    }
    if (values.has(name)) throw new Error(`Duplicate local runtime env variable: ${name}`)
    values.set(name, value)
  }
  return values
}

export function renderLocalRuntimeEnv({
  template,
  existingContent = '',
  explicitApiKey = '',
  forcedKeys = [],
  randomBytes,
}) {
  const normalizedTemplate = normalizeTemplate(template)
  const placeholder = `API_KEY=${API_KEY_PLACEHOLDER}`
  if (normalizedTemplate.split(placeholder).length !== 2) {
    throw new Error(`Local runtime env template must contain exactly one ${placeholder} entry`)
  }

  const existing = existingContent ? parseStrictLocalEnv(existingContent) : new Map()
  const resolved = resolveAnalyzerApiKey({
    explicitKey: explicitApiKey,
    randomBytes,
  })
  const forced = new Set(forcedKeys)
  const templateKeys = new Set()

  const renderedLines = normalizedTemplate
    .trimEnd()
    .split('\n')
    .map((line) => {
      if (line === placeholder) {
        templateKeys.add('API_KEY')
        return `API_KEY=${resolved.key}`
      }
      const match = /^([A-Z][A-Z0-9_]*)=(.*)$/u.exec(line)
      if (!match) return line
      const [, name] = match
      templateKeys.add(name)
      if (!forced.has(name) && existing.has(name)) {
        return `${name}=${existing.get(name)}`
      }
      return line
    })

  const preserved = []
  for (const [name, value] of existing) {
    if (name === 'API_KEY' || name === 'RIKUNE_API_KEY' || templateKeys.has(name)) continue
    preserved.push(`${name}=${value}`)
  }
  if (preserved.length > 0) {
    renderedLines.push('', '# Existing user settings preserved by secure installer', ...preserved)
  }

  return { content: `${renderedLines.join('\n')}\n`, apiKey: resolved.key }
}

export function stageLocalRuntimeEnv({
  targetPath,
  platform = process.platform,
  verifyWindowsAcl,
}) {
  const normalizedTarget = String(targetPath ?? '')
  if (!normalizedTarget.trim() || /[\r\n\0]/u.test(normalizedTarget)) {
    throw new Error(
      'RIKUNE_STAGE_LOCAL_ENV_PATH is required and must not contain control characters'
    )
  }
  const absoluteTarget = path.resolve(normalizedTarget)
  if (!pathEntryExists(absoluteTarget)) return ''

  const existing = parseStrictLocalEnv(
    readPrivateUtf8File({ targetPath: absoluteTarget, platform, verifyWindowsAcl })
  )
  existing.delete('API_KEY')
  existing.delete('RIKUNE_API_KEY')
  const stagedContent =
    existing.size > 0
      ? `${Array.from(existing, ([name, value]) => `${name}=${value}`).join('\n')}\n`
      : ''

  removeProtectedExistingFile({ targetPath: absoluteTarget, platform, verifyWindowsAcl })
  return stagedContent
}

function decodeStagedExistingContent(encoded) {
  const normalized = String(encoded ?? '')
  if (
    normalized.length > 128 * 1024 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(normalized)
  ) {
    throw new Error('RIKUNE_LOCAL_EXISTING_ENV_BASE64 must contain canonical base64')
  }
  const bytes = Buffer.from(normalized, 'base64')
  if (bytes.toString('base64') !== normalized) {
    throw new Error('RIKUNE_LOCAL_EXISTING_ENV_BASE64 must contain canonical base64')
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new Error('RIKUNE_LOCAL_EXISTING_ENV_BASE64 must decode to valid UTF-8')
  }
}

export function writeLocalRuntimeEnv({
  targetPath,
  template,
  stagedExistingContent,
  explicitApiKey = '',
  forcedKeys = [],
  randomBytes,
  platform = process.platform,
  restrictWindowsAcl,
  verifyWindowsAcl,
}) {
  const normalizedTarget = String(targetPath ?? '')
  if (!normalizedTarget.trim() || /[\r\n\0]/u.test(normalizedTarget)) {
    throw new Error('RIKUNE_LOCAL_ENV_PATH is required and must not contain control characters')
  }
  for (const name of forcedKeys) {
    if (!/^[A-Z][A-Z0-9_]*$/u.test(name)) {
      throw new Error(`Invalid forced local runtime env variable name: ${name}`)
    }
  }
  const absoluteTarget = path.resolve(normalizedTarget)
  const existingContent =
    stagedExistingContent === undefined
      ? pathEntryExists(absoluteTarget)
        ? readPrivateUtf8File({ targetPath: absoluteTarget, platform, verifyWindowsAcl })
        : ''
      : String(stagedExistingContent)
  const rendered = renderLocalRuntimeEnv({
    template,
    existingContent,
    explicitApiKey,
    forcedKeys,
    randomBytes,
  })
  writePrivateUtf8File({
    targetPath: absoluteTarget,
    content: rendered.content,
    platform,
    restrictWindowsAcl,
    verifyWindowsAcl,
  })
  return { apiKey: rendered.apiKey }
}

async function readStandardInput() {
  let content = ''
  process.stdin.setEncoding('utf8')
  for await (const chunk of process.stdin) content += chunk
  return content
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : ''
if (invokedPath === fileURLToPath(import.meta.url)) {
  if (Object.hasOwn(process.env, 'RIKUNE_STAGE_LOCAL_ENV_PATH')) {
    const staged = stageLocalRuntimeEnv({
      targetPath: process.env.RIKUNE_STAGE_LOCAL_ENV_PATH,
    })
    process.stdout.write(Buffer.from(staged, 'utf8').toString('base64'))
  } else {
    const template = await readStandardInput()
    writeLocalRuntimeEnv({
      targetPath: process.env.RIKUNE_LOCAL_ENV_PATH,
      template,
      stagedExistingContent: Object.hasOwn(process.env, 'RIKUNE_LOCAL_EXISTING_ENV_BASE64')
        ? decodeStagedExistingContent(process.env.RIKUNE_LOCAL_EXISTING_ENV_BASE64)
        : undefined,
      explicitApiKey: process.env.RIKUNE_API_KEY || '',
      forcedKeys: String(process.env.RIKUNE_LOCAL_ENV_FORCE_KEYS || '')
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean),
    })
  }
}
