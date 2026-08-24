#!/usr/bin/env node

import { readFileSync } from 'node:fs'

const rawArgs = process.argv.slice(2)
if (rawArgs.length === 1 && (rawArgs[0] === '--version' || rawArgs[0] === '-v')) {
  const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
  process.stdout.write(`${packageJson.version}\n`)
  process.exit(0)
}

const { runRikuneAgentCli } = await import('../dist/rikune-agent-gateway.js')
const exitCode = await runRikuneAgentCli(rawArgs, process.env)
process.exit(exitCode)
