import { describe, expect, test } from '@jest/globals'
import zlib from 'zlib'
import {
  buildContainerImageSecurityProfileFromBuffer,
  ContainerImageSecurityProfileOutputSchema,
  containerImageSecurityProfileToolDefinition,
} from '../../src/plugins/container-analysis/tools/container-image-security-profile.js'

function tarEntry(name: string, data = Buffer.alloc(0), mode = 0o644, typeflag = '0'): Buffer {
  const nameBuffer = Buffer.from(name)
  const header = Buffer.alloc(512)
  header.write(name, 0, Math.min(nameBuffer.length, 100), 'utf8')
  header.write(mode.toString(8).padStart(7, '0') + '\0', 100, 'ascii')
  header.write('0000000\0', 108, 'ascii')
  header.write('0000000\0', 116, 'ascii')
  header.write(data.length.toString(8).padStart(11, '0') + '\0', 124, 'ascii')
  header.write('00000000000\0', 136, 'ascii')
  header[156] = typeflag.charCodeAt(0)
  header.write('ustar\0', 257, 'ascii')
  header.write('00', 263, 'ascii')
  header.fill(0x20, 148, 156)
  let checksum = 0
  for (const byte of header) checksum += byte
  header.write(checksum.toString(8).padStart(6, '0'), 148, 'ascii')
  header[154] = 0
  header[155] = 0x20
  const padding = Buffer.alloc((512 - (data.length % 512)) % 512)
  return Buffer.concat([header, data, padding])
}

function tar(entries: Array<{ name: string; data?: Buffer; mode?: number; typeflag?: string }>) {
  return Buffer.concat([
    ...entries.map((entry) =>
      tarEntry(entry.name, entry.data ?? Buffer.alloc(0), entry.mode ?? 0o644, entry.typeflag ?? '0')
    ),
    Buffer.alloc(1024),
  ])
}

function json(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value), 'utf8')
}

describe('container.image.security.profile', () => {
  test('declares passive Docker/OCI image workflow metadata', () => {
    expect(containerImageSecurityProfileToolDefinition.aspects?.formats).toEqual(
      expect.arrayContaining(['docker-image', 'oci-image', 'container'])
    )
    expect(containerImageSecurityProfileToolDefinition.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'container-security-profile',
        'image-config',
        'layer-inventory',
        'secret-detection',
        'supply-chain-risk',
      ])
    )
    expect(containerImageSecurityProfileToolDefinition.aspects?.safety).toEqual(
      expect.arrayContaining([
        'passive',
        'no_network_by_default',
        'no_auto_mount',
        'no_live_sample_by_default',
        'no_mutation',
      ])
    )
    expect(
      containerImageSecurityProfileToolDefinition.artifacts?.map((artifact) => artifact.type)
    ).toContain('container_image_security_profile')
    const recipe = containerImageSecurityProfileToolDefinition.workflowRecipes?.find(
      (candidate) => candidate.id === 'container.image-security-profile'
    )
    expect(recipe).toEqual(
      expect.objectContaining({
        startsWith: ['container.image.security.profile', 'container.structure.analyze'],
        producesArtifacts: ['container_image_security_profile'],
      })
    )
    expect(recipe?.nextTools).toEqual(
      expect.arrayContaining([
        'container.structure.analyze',
        'sbom.provenance.graph',
        'analysis.evidence.graph',
      ])
    )
  })

  test('profiles Docker save tar config, history, and layer header risks without execution', () => {
    const layer = tar([
      { name: 'usr/bin/suid-helper', mode: 0o4755 },
      { name: 'tmp/world.txt', mode: 0o666 },
      { name: 'root/.aws/credentials', mode: 0o600 },
      { name: 'var/lib/dpkg/status' },
      { name: 'app/libdemo.so' },
      { name: 'etc/.wh.old-secret' },
    ])
    const image = tar([
      {
        name: 'manifest.json',
        data: json([{ Config: 'config.json', RepoTags: ['demo:latest'], Layers: ['layer.tar'] }]),
      },
      {
        name: 'config.json',
        data: json({
          architecture: 'amd64',
          os: 'linux',
          config: {
            Env: ['PATH=/usr/bin', 'AWS_SECRET_ACCESS_KEY=test'],
            Entrypoint: ['/bin/sh', '-c', 'run.sh'],
            Cmd: ['--serve'],
            ExposedPorts: { '80/tcp': {} },
          },
          rootfs: { type: 'layers', diff_ids: ['sha256:diff'] },
          history: [
            { created_by: '/bin/sh -c curl https://example.invalid/install.sh | sh' },
            { created_by: '/bin/sh -c apt-get install -y curl' },
          ],
        }),
      },
      { name: 'layer.tar', data: layer },
    ])

    const profile = buildContainerImageSecurityProfileFromBuffer(image, { filename: 'image.tar' })

    expect(profile.image_format).toBe('docker-image')
    expect(profile.selected_image).toEqual(
      expect.objectContaining({
        repo_tags: ['demo:latest'],
        config_path: 'config.json',
        layer_count: 1,
      })
    )
    expect(profile.runtime_config).toEqual(
      expect.objectContaining({
        root_user_default: true,
        no_user_declared: true,
        secret_like_env_names: ['AWS_SECRET_ACCESS_KEY'],
        shell_entrypoint: true,
        privileged_ports: ['80/tcp'],
      })
    )
    expect(profile.layer_summary).toEqual(
      expect.objectContaining({
        scanned_layer_count: 1,
        suid_paths: expect.arrayContaining(['usr/bin/suid-helper']),
        world_writable_paths: expect.arrayContaining(['tmp/world.txt']),
        secret_like_paths: expect.arrayContaining(['root/.aws/credentials']),
        package_manager_paths: expect.arrayContaining(['var/lib/dpkg/status']),
        whiteout_paths: expect.arrayContaining(['etc/.wh.old-secret']),
        nested_binary_paths: expect.arrayContaining(['app/libdemo.so']),
      })
    )
    expect(profile.history_summary).toEqual(
      expect.objectContaining({
        risky_instruction_count: 2,
        risky_instructions: expect.arrayContaining([
          expect.objectContaining({
            risks: expect.arrayContaining(['download-and-execute']),
          }),
          expect.objectContaining({
            risks: expect.arrayContaining(['package-install-history']),
          }),
        ]),
      })
    )
    expect(profile.risk_flags).toEqual(
      expect.arrayContaining([
        'root-user-default',
        'no-user-declared',
        'secret-like-env',
        'shell-entrypoint',
        'privileged-port-exposed',
        'suid-files',
        'world-writable-files',
        'secret-like-path',
        'package-manager-traces',
        'layer-whiteouts-present',
        'download-and-execute-history',
        'package-install-history',
      ])
    )
    expect(profile.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_registry_network: true,
        no_docker_daemon: true,
        no_layer_extract: true,
        no_mount: true,
        no_install: true,
        no_entrypoint_run: true,
        no_mutation: true,
      })
    )
    expect(profile.workflow_handoff?.dynamic_boundary).toEqual(
      expect.objectContaining({
        registry_contacted_by_tool: false,
        docker_daemon_contacted_by_tool: false,
        image_loaded_by_tool: false,
        layer_extracted_by_tool: false,
        filesystem_mounted_by_tool: false,
        scripts_executed_by_tool: false,
        package_install_performed: false,
        entrypoint_executed_by_tool: false,
      })
    )
    expect(ContainerImageSecurityProfileOutputSchema.parse({ ok: true, data: profile }).data).toEqual(
      expect.objectContaining({
        evidence_summary: expect.objectContaining({ static_only: true }),
        quality_gates: expect.objectContaining({ passive_static_inventory: true }),
      })
    )
  })

  test('profiles OCI layout config and gzip layer without root-user findings', () => {
    const layer = zlib.gzipSync(tar([{ name: 'app/server', mode: 0o755 }]))
    const manifestDigest = 'a'.repeat(64)
    const configDigest = 'b'.repeat(64)
    const layerDigest = 'c'.repeat(64)
    const image = tar([
      { name: 'oci-layout', data: json({ imageLayoutVersion: '1.0.0' }) },
      {
        name: 'index.json',
        data: json({
          manifests: [
            {
              mediaType: 'application/vnd.oci.image.manifest.v1+json',
              digest: `sha256:${manifestDigest}`,
              platform: { os: 'linux', architecture: 'arm64' },
            },
          ],
        }),
      },
      {
        name: `blobs/sha256/${manifestDigest}`,
        data: json({
          config: {
            digest: `sha256:${configDigest}`,
            mediaType: 'application/vnd.oci.image.config.v1+json',
          },
          layers: [
            {
              digest: `sha256:${layerDigest}`,
              mediaType: 'application/vnd.oci.image.layer.v1.tar+gzip',
              size: layer.length,
            },
          ],
        }),
      },
      {
        name: `blobs/sha256/${configDigest}`,
        data: json({
          architecture: 'arm64',
          os: 'linux',
          config: {
            User: '1000:1000',
            Env: ['PATH=/usr/bin'],
            Entrypoint: ['/app/server'],
            ExposedPorts: { '8080/tcp': {} },
          },
          rootfs: { type: 'layers', diff_ids: ['sha256:diff'] },
        }),
      },
      { name: `blobs/sha256/${layerDigest}`, data: layer },
    ])

    const profile = buildContainerImageSecurityProfileFromBuffer(image, { filename: 'layout.oci' })

    expect(profile.image_format).toBe('oci-image')
    expect(profile.platform).toEqual(
      expect.objectContaining({ os: 'linux', architecture: 'arm64', diff_id_count: 1 })
    )
    expect(profile.runtime_config).toEqual(
      expect.objectContaining({
        root_user_default: false,
        no_user_declared: false,
        exposed_ports: ['8080/tcp'],
        privileged_ports: [],
      })
    )
    expect(profile.layer_summary?.layers?.[0]).toEqual(
      expect.objectContaining({
        scanned: true,
        compressed: true,
        entry_count: 1,
      })
    )
    expect(profile.risk_flags).not.toEqual(expect.arrayContaining(['root-user-default']))
    expect(profile.risk_flags).not.toEqual(expect.arrayContaining(['secret-like-env']))
    expect(profile.quality_gates).toEqual(
      expect.objectContaining({
        registry_contacted_by_tool: false,
        docker_daemon_contacted_by_tool: false,
        layer_extracted_by_tool: false,
        filesystem_mounted_by_tool: false,
      })
    )
  })
})
