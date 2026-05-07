#!/usr/bin/env node

const { runRikuneAgentCli } = await import('../dist/rikune-agent-gateway.js')
const exitCode = await runRikuneAgentCli(process.argv.slice(2), process.env)
process.exit(exitCode)
