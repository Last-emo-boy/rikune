#!/usr/bin/env node

import { readFileSync } from 'node:fs'

const rawArgs = process.argv.slice(2)
if (rawArgs.length === 1 && (rawArgs[0] === '--version' || rawArgs[0] === '-v')) {
  const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
  process.stdout.write(`${packageJson.version}\n`)
  process.exit(0)
}

const { runDockerLauncherCli } = await import('../dist/npm-docker-launcher.js')
const exitCode = await runDockerLauncherCli('docker-stdio', rawArgs, process.env)
process.exit(exitCode)
