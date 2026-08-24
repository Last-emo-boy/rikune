#!/usr/bin/env node

import { readFileSync } from 'node:fs'

const rawArgs = process.argv.slice(2)
const subcommand = rawArgs[0]

if (rawArgs.length === 1 && (subcommand === '--version' || subcommand === '-v')) {
  const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
  process.stdout.write(`${packageJson.version}\n`)
  process.exit(0)
}

if (subcommand === 'docker-stdio' || subcommand === 'docker-run') {
  const { runDockerLauncherCli } = await import('../dist/npm-docker-launcher.js')
  const exitCode = await runDockerLauncherCli(subcommand, rawArgs.slice(1), process.env)
  process.exit(exitCode)
}

if (subcommand === 'agent' || subcommand === 'rikune-agent') {
  const { runRikuneAgentCli } = await import('../dist/rikune-agent-gateway.js')
  const exitCode = await runRikuneAgentCli(rawArgs.slice(1), process.env)
  process.exit(exitCode)
}

const { startRikuneServer } = await import('../dist/index.js')
await startRikuneServer()
