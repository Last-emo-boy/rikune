import { describe, expect, test } from '@jest/globals'
import {
  buildDockerLauncherCommand,
  maskDockerLauncherCommand,
} from '../../src/npm-docker-launcher.js'

describe('npm Docker launcher secret forwarding', () => {
  const runtimeEnv = {
    RIKUNE_DOCKER_IMAGE: 'rikune:test',
    RIKUNE_DOCKER_CONTAINER: 'rikune-test',
    RUNTIME_HOST_AGENT_ENDPOINT: 'https://runtime.example.internal',
    RUNTIME_HOST_AGENT_API_KEY: 'host-secret-must-never-enter-argv',
    RUNTIME_API_KEY: 'runtime-secret-must-never-enter-argv',
  }

  test.each(['docker-run', 'docker-stdio'] as const)(
    '%s forwards inherited runtime variables by name only',
    (mode) => {
      const command = buildDockerLauncherCommand(mode, [], runtimeEnv)
      const serialized = command.args.join('\n')

      expect(command.args).toEqual(
        expect.arrayContaining([
          'RUNTIME_HOST_AGENT_ENDPOINT',
          'RUNTIME_HOST_AGENT_API_KEY',
          'RUNTIME_API_KEY',
        ])
      )
      expect(serialized).not.toContain(runtimeEnv.RUNTIME_HOST_AGENT_API_KEY)
      expect(serialized).not.toContain(runtimeEnv.RUNTIME_API_KEY)
      expect(serialized).not.toContain('RUNTIME_HOST_AGENT_API_KEY=')
      expect(serialized).not.toContain('RUNTIME_API_KEY=')
    }
  )

  test('redacts defense-in-depth secret assignments before formatting', () => {
    expect(maskDockerLauncherCommand(['-e', 'RUNTIME_API_KEY=secret', 'SAFE=value'])).toEqual([
      '-e',
      'RUNTIME_API_KEY=***',
      'SAFE=value',
    ])
  })
})
