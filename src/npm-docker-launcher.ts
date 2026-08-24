import { spawn } from 'child_process'
import { RIKUNE_VERSION } from './version.js'

type LauncherMode = 'docker-stdio' | 'docker-run'

interface LauncherOptions {
  printCommand: boolean
  passthroughArgs: string[]
}

const DEFAULT_CONTAINER = 'rikune-analyzer'
const DEFAULT_IMAGE = `ghcr.io/last-emo-boy/rikune-analyzer-static:${RIKUNE_VERSION}`
const SECRET_ENV_NAME_PATTERN = /(?:KEY|TOKEN|SECRET|PASSWORD)$/i

function parseOptions(args: string[]): LauncherOptions {
  const passthroughArgs: string[] = []
  let printCommand = false

  for (const arg of args) {
    if (arg === '--print-command') {
      printCommand = true
    } else {
      passthroughArgs.push(arg)
    }
  }

  return { printCommand, passthroughArgs }
}

function appendEnvArgs(args: string[], env: NodeJS.ProcessEnv): void {
  const fixed = new Map<string, string>([
    ['API_ENABLED', 'false'],
    ['NODE_ENV', env.NODE_ENV || 'production'],
    ['PYTHONUNBUFFERED', env.PYTHONUNBUFFERED || '1'],
  ])

  for (const [name, value] of fixed) {
    args.push('-e', `${name}=${value}`)
  }

  for (const name of [
    'RUNTIME_HOST_AGENT_ENDPOINT',
    'RUNTIME_HOST_AGENT_API_KEY',
    'RUNTIME_API_KEY',
  ]) {
    if (env[name]) {
      // Docker resolves a bare -e NAME from the CLI process environment. This
      // keeps credentials out of /proc/<pid>/cmdline and Windows process lists.
      args.push('-e', name)
    }
  }
}

export function buildDockerLauncherCommand(
  mode: LauncherMode,
  args: string[],
  env: NodeJS.ProcessEnv = process.env
): { command: string; args: string[] } {
  const options = parseOptions(args)
  const docker = env.RIKUNE_DOCKER_COMMAND || 'docker'

  if (mode === 'docker-run') {
    const image = env.RIKUNE_DOCKER_IMAGE || DEFAULT_IMAGE
    const dockerArgs = ['run', '--rm', '-i']
    appendEnvArgs(dockerArgs, env)
    dockerArgs.push(image, 'node', 'dist/index.js', ...options.passthroughArgs)
    return { command: docker, args: dockerArgs }
  }

  const container =
    env.RIKUNE_DOCKER_CONTAINER || env.RIKUNE_ANALYZER_CONTAINER || DEFAULT_CONTAINER
  const dockerArgs = ['exec', '-i']
  appendEnvArgs(dockerArgs, env)
  dockerArgs.push(container, 'node', 'dist/index.js', ...options.passthroughArgs)
  return { command: docker, args: dockerArgs }
}

export function formatCommand(command: string, args: string[]): string {
  return [command, ...args]
    .map((part) => {
      if (/^[A-Za-z0-9_./:=@-]+$/.test(part)) {
        return part
      }
      return JSON.stringify(part)
    })
    .join(' ')
}

export function maskDockerLauncherCommand(args: string[]): string[] {
  return args.map((arg) => {
    const match = /^([A-Za-z_][A-Za-z0-9_]*=)(.*)$/.exec(arg)
    if (!match || !SECRET_ENV_NAME_PATTERN.test(match[1].slice(0, -1))) {
      return arg
    }
    return `${match[1]}***`
  })
}

export async function runDockerLauncherCli(
  mode: LauncherMode,
  args: string[],
  env: NodeJS.ProcessEnv = process.env
): Promise<number> {
  const options = parseOptions(args)
  const cmd = buildDockerLauncherCommand(mode, args, env)

  if (options.printCommand) {
    process.stdout.write(formatCommand(cmd.command, maskDockerLauncherCommand(cmd.args)) + '\n')
    return 0
  }

  return await new Promise<number>((resolve) => {
    const child = spawn(cmd.command, cmd.args, {
      stdio: 'inherit',
      env,
      windowsHide: true,
    })
    child.on('error', (error) => {
      process.stderr.write(`Failed to launch Docker analyzer: ${error.message}\n`)
      resolve(1)
    })
    child.on('exit', (code, signal) => {
      if (typeof code === 'number') {
        resolve(code)
      } else {
        process.stderr.write(`Docker analyzer exited from signal ${signal || 'unknown'}\n`)
        resolve(1)
      }
    })
  })
}
