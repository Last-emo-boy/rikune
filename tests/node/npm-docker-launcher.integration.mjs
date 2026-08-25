import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import path from 'node:path'

const repoRoot = process.cwd()
const binPath = path.join(repoRoot, 'bin', 'rikune.js')
const agentBinPath = path.join(repoRoot, 'bin', 'rikune-agent.js')

const baseEnv = {
  PATH: process.env.PATH,
  Path: process.env.Path,
  PATHEXT: process.env.PATHEXT,
  SystemRoot: process.env.SystemRoot,
  TEMP: process.env.TEMP,
  TMP: process.env.TMP,
  USERPROFILE: process.env.USERPROFILE,
  RIKUNE_AGENT_NO_ENV_FILE: '1',
}

const printExec = spawnSync(process.execPath, [binPath, 'docker-stdio', '--print-command'], {
  cwd: repoRoot,
  encoding: 'utf8',
  env: {
    ...baseEnv,
    RIKUNE_DOCKER_CONTAINER: 'integration-mcp',
  },
})

assert.equal(printExec.status, 0)
assert.match(
  printExec.stdout.trim(),
  /^docker exec -i -e API_ENABLED=false -e NODE_ENV=production -e PYTHONUNBUFFERED=1 integration-mcp node dist\/index\.js$/
)

const printRun = spawnSync(process.execPath, [binPath, 'docker-run', '--print-command'], {
  cwd: repoRoot,
  encoding: 'utf8',
  env: {
    ...baseEnv,
    RIKUNE_DOCKER_IMAGE: 'integration-image:latest',
  },
})

assert.equal(printRun.status, 0)
assert.match(
  printRun.stdout.trim(),
  /^docker run --rm -i -e API_ENABLED=false -e NODE_ENV=production -e PYTHONUNBUFFERED=1 integration-image:latest node dist\/index\.js$/
)

const runtimeSecret = 'runtime-secret-must-not-appear-in-docker-argv'
const printRunWithRuntime = spawnSync(
  process.execPath,
  [binPath, 'docker-run', '--print-command'],
  {
    cwd: repoRoot,
    encoding: 'utf8',
    env: {
      ...baseEnv,
      RIKUNE_DOCKER_IMAGE: 'integration-image:latest',
      RUNTIME_HOST_AGENT_ENDPOINT: 'https://runtime.example.internal',
      RUNTIME_HOST_AGENT_API_KEY: runtimeSecret,
      RUNTIME_API_KEY: `${runtimeSecret}-node`,
    },
  }
)

assert.equal(printRunWithRuntime.status, 0)
assert.match(
  printRunWithRuntime.stdout.trim(),
  /-e RUNTIME_HOST_AGENT_ENDPOINT -e RUNTIME_HOST_AGENT_API_KEY -e RUNTIME_API_KEY/u
)
assert.doesNotMatch(printRunWithRuntime.stdout, /runtime-secret-must-not-appear/u)

const defaultPrintRun = spawnSync(process.execPath, [binPath, 'docker-run', '--print-command'], {
  cwd: repoRoot,
  encoding: 'utf8',
  env: baseEnv,
})

assert.equal(defaultPrintRun.status, 0)
assert.match(
  defaultPrintRun.stdout.trim(),
  /^docker run --rm -i -e API_ENABLED=false -e NODE_ENV=production -e PYTHONUNBUFFERED=1 ghcr\.io\/last-emo-boy\/rikune-analyzer-static:1\.4\.1 node dist\/index\.js$/
)

const agentHelp = spawnSync(process.execPath, [agentBinPath, '--help'], {
  cwd: repoRoot,
  encoding: 'utf8',
  env: baseEnv,
})

assert.equal(agentHelp.status, 0)
assert.match(agentHelp.stdout, /rikune-agent stdio/)

const agentPrint = spawnSync(process.execPath, [agentBinPath, 'stdio', '--print-command'], {
  cwd: repoRoot,
  encoding: 'utf8',
  env: {
    ...baseEnv,
    RIKUNE_DOCKER_CONTAINER: 'integration-agent-mcp',
  },
})

assert.equal(agentPrint.status, 0)
assert.match(
  agentPrint.stdout.trim(),
  /^docker exec -i -e API_ENABLED=false -e NODE_ENV=production -e PYTHONUNBUFFERED=1 integration-agent-mcp node dist\/index\.js$/
)

const mainAgentPrint = spawnSync(process.execPath, [binPath, 'agent', 'stdio', '--print-command'], {
  cwd: repoRoot,
  encoding: 'utf8',
  env: {
    ...baseEnv,
    RIKUNE_DOCKER_CONTAINER: 'integration-main-agent-mcp',
  },
})

assert.equal(mainAgentPrint.status, 0)
assert.match(
  mainAgentPrint.stdout.trim(),
  /^docker exec -i -e API_ENABLED=false -e NODE_ENV=production -e PYTHONUNBUFFERED=1 integration-main-agent-mcp node dist\/index\.js$/
)

console.log('npm docker launcher integration checks passed')
