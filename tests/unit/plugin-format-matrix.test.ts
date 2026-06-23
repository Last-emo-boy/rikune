import { describe, expect, test } from '@jest/globals'
import { detectFileType } from '../../src/sample/sample-finalization.js'
import { discoverBuiltInPlugins } from '../../src/core/plugin-system/discovery.js'
import {
  createPluginTestHarness,
  type Plugin,
  type PluginTestHarnessOptions,
  type ToolDefinition,
  type WorkflowRecipeSpec,
} from '../../src/plugins/sdk.js'
import { buildLinuxPackageInventoryFromBuffer } from '../../src/plugins/linux-package/tools/linux-package-inventory.js'
import { buildAppleContainerInventoryFromBuffer } from '../../src/plugins/apple-container/tools/apple-container-inventory.js'
import { buildJvmStructureFromBuffer } from '../../src/plugins/jvm/tools/jvm-structure-analyze.js'
import { buildWasmStructureFromBuffer } from '../../src/plugins/wasm/tools/wasm-structure-analyze.js'
import { buildBytecodeMetadataFromBuffer } from '../../src/plugins/bytecode/tools/bytecode-metadata-inspect.js'
import { buildWindowsInstallerInventoryFromBuffer } from '../../src/plugins/windows-installer/tools/windows-installer-inventory.js'
import { buildWindowsDebugMetadataFromBuffer } from '../../src/plugins/windows-debug-symbols/tools/windows-debug-metadata-inspect.js'
import { buildDotnetAssemblyInventoryFromBuffer } from '../../src/plugins/dotnet-managed/tools/dotnet-assembly-inspect.js'
import { buildUnityMetadataInventoryFromBuffer } from '../../src/plugins/unity-managed/tools/unity-metadata-inspect.js'
import { buildContainerStructureFromBuffer } from '../../src/plugins/container-analysis/tools/container-structure-analyze.js'
import { buildNativeObjectInventoryFromBuffer } from '../../src/plugins/native-object/tools/native-object-inventory.js'
import { buildAndroidPackageInventoryFromBuffer } from '../../src/plugins/android-package/tools/android-package-inventory.js'
import { buildAppleSigningInspectFromBuffer } from '../../src/plugins/apple-signing/tools/apple-signing-inspect.js'
import { buildLinuxBinaryInventoryFromBuffer } from '../../src/plugins/linux-binary/tools/linux-binary-inventory.js'
import {
  buildPluginAspectMatrix,
  buildToolAspectSummary,
} from '../../src/tools/tool-aspect-matrix.js'

function localZip(entries: string[]): Buffer {
  const chunks: Buffer[] = []
  for (const entry of entries) {
    const name = Buffer.from(entry)
    const header = Buffer.alloc(30)
    header.writeUInt32LE(0x04034b50, 0)
    header.writeUInt16LE(name.length, 26)
    chunks.push(header, name)
  }
  return Buffer.concat(chunks)
}

function arMember(name: string, body: Buffer = Buffer.alloc(0)): Buffer {
  const header = Buffer.alloc(60, ' ')
  header.write(`${name}/`.slice(0, 16), 0, 'ascii')
  header.write(String(body.length).padEnd(10, ' '), 48, 'ascii')
  header.write('`\n', 58, 'ascii')
  return Buffer.concat([header, body, body.length % 2 ? Buffer.from('\n') : Buffer.alloc(0)])
}

function cabFixture(): Buffer {
  const data = Buffer.alloc(36)
  data.write('MSCF', 0, 'ascii')
  data.writeUInt32LE(data.length, 8)
  data.writeUInt32LE(36, 16)
  data[24] = 3
  data[25] = 1
  data.writeUInt16LE(1, 26)
  data.writeUInt16LE(2, 28)
  return data
}

function tarFixture(entries: string[]): Buffer {
  const blocks: Buffer[] = []
  for (const entry of entries) {
    const header = Buffer.alloc(512)
    header.write(entry, 0, Math.min(Buffer.byteLength(entry), 100), 'utf8')
    header.write('0000644\0', 100, 'ascii')
    header.write('0000000\0', 108, 'ascii')
    header.write('0000000\0', 116, 'ascii')
    header.write('00000000000\0', 124, 'ascii')
    header.write('00000000000\0', 136, 'ascii')
    header[156] = entry.endsWith('/') ? 0x35 : 0x30
    header.write('ustar\0', 257, 'ascii')
    header.write('00', 263, 'ascii')
    header.fill(0x20, 148, 156)
    let checksum = 0
    for (const byte of header) checksum += byte
    header.write(checksum.toString(8).padStart(6, '0'), 148, 'ascii')
    header[154] = 0
    header[155] = 0x20
    blocks.push(header)
  }
  blocks.push(Buffer.alloc(1024))
  return Buffer.concat(blocks)
}

function isoFixture(): Buffer {
  const data = Buffer.alloc(0x8006)
  data.write('CD001', 0x8001, 'ascii')
  return data
}

function elfFixture(type: number, machine = 62): Buffer {
  const data = Buffer.alloc(64)
  data[0] = 0x7f
  data[1] = 0x45
  data[2] = 0x4c
  data[3] = 0x46
  data[4] = 2
  data[5] = 1
  data[6] = 1
  data.writeUInt16LE(type, 16)
  data.writeUInt16LE(machine, 18)
  return data
}

function machoObjectFixture(): Buffer {
  const data = Buffer.alloc(32)
  data.writeUInt32BE(0xfeedfacf, 0)
  data.writeUInt32BE(0x01000007, 4)
  data.writeUInt32BE(3, 8)
  data.writeUInt32BE(1, 12)
  return data
}

function cpioNewcFixture(entries: Array<{ name: string; body?: Buffer }>): Buffer {
  const chunks: Buffer[] = []
  for (const entry of entries) {
    const name = Buffer.from(`${entry.name}\0`, 'utf8')
    const body = entry.body ?? Buffer.alloc(0)
    const header = Buffer.alloc(110, '0')
    header.write('070701', 0, 'ascii')
    header.write(body.length.toString(16).padStart(8, '0'), 54, 'ascii')
    header.write(name.length.toString(16).padStart(8, '0'), 94, 'ascii')
    chunks.push(header, name)
    const namePad = (4 - (chunks.reduce((sum, chunk) => sum + chunk.length, 0) % 4)) % 4
    if (namePad) chunks.push(Buffer.alloc(namePad))
    chunks.push(body)
    const bodyPad = (4 - (body.length % 4)) % 4
    if (bodyPad) chunks.push(Buffer.alloc(bodyPad))
  }
  const trailer = Buffer.from('TRAILER!!!\0', 'utf8')
  const header = Buffer.alloc(110, '0')
  header.write('070701', 0, 'ascii')
  header.write(trailer.length.toString(16).padStart(8, '0'), 94, 'ascii')
  chunks.push(header, trailer)
  return Buffer.concat(chunks)
}

function requirePlugin(plugins: Plugin[], id: string): Plugin {
  const plugin = plugins.find((candidate) => candidate.id === id)
  expect(plugin).toBeDefined()
  return plugin as Plugin
}

function registeredToolDefinitions(plugin: Plugin, options?: PluginTestHarnessOptions) {
  const harness = createPluginTestHarness(options)
  harness.registerPlugin(plugin)
  return new Map(harness.registeredTools.map((tool) => [tool.definition.name, tool.definition]))
}

function requireRegisteredTool(
  plugins: Plugin[],
  pluginId: string,
  toolName: string,
  options?: PluginTestHarnessOptions
): ToolDefinition {
  const plugin = requirePlugin(plugins, pluginId)
  const tools = registeredToolDefinitions(plugin, options)
  const definition = tools.get(toolName)
  expect(definition).toBeDefined()
  return definition as ToolDefinition
}

function requireWorkflowRecipe(definition: ToolDefinition, recipeId: string): WorkflowRecipeSpec {
  const recipe = definition.workflowRecipes?.find((candidate) => candidate.id === recipeId)
  expect(recipe).toBeDefined()
  return recipe as WorkflowRecipeSpec
}

function expectWorkflowRecipeMetadata(
  plugins: Plugin[],
  expected: {
    pluginId: string
    toolName: string
    recipeId: string
    startsWith?: string[]
    nextTools?: string[]
    producesArtifacts?: string[]
    evidence?: string[]
    safety?: string[]
    runtimeBackends?: string[]
    harnessOptions?: PluginTestHarnessOptions
  }
) {
  const definition = requireRegisteredTool(
    plugins,
    expected.pluginId,
    expected.toolName,
    expected.harnessOptions
  )
  const recipe = requireWorkflowRecipe(definition, expected.recipeId)

  expect(recipe.startsWith ?? []).toEqual(expect.arrayContaining(expected.startsWith ?? []))
  expect(recipe.nextTools ?? []).toEqual(expect.arrayContaining(expected.nextTools ?? []))
  expect(recipe.producesArtifacts ?? []).toEqual(
    expect.arrayContaining(expected.producesArtifacts ?? [])
  )
  expect(recipe.evidence ?? []).toEqual(expect.arrayContaining(expected.evidence ?? []))
  expect(recipe.safety ?? []).toEqual(expect.arrayContaining(expected.safety ?? []))
  expect(recipe.runtimeBackends ?? []).toEqual(
    expect.arrayContaining(expected.runtimeBackends ?? [])
  )
}

function expectToolMetadata(
  plugin: Plugin,
  toolName: string,
  expected: {
    formats?: string[]
    artifacts?: string[]
    evidence?: string[]
  }
) {
  const tools = registeredToolDefinitions(plugin)
  const definition = tools.get(toolName)
  expect(definition).toBeDefined()
  if (expected.formats) {
    expect(definition?.aspects?.formats).toEqual(expect.arrayContaining(expected.formats))
  }
  if (expected.artifacts) {
    expect(definition?.artifacts?.map((artifact) => artifact.type)).toEqual(
      expect.arrayContaining(expected.artifacts)
    )
  }
  if (expected.evidence) {
    expect(definition?.evidence?.map((evidence) => evidence.category)).toEqual(
      expect.arrayContaining(expected.evidence)
    )
  }
}

test('aspect matrix indexes workflow recipe metadata', () => {
  const toolDefinition = {
    name: 'fixture.workflow.seed',
    description: 'Fixture workflow seed',
    inputSchema: {},
    aspects: {
      formats: ['PE'],
      platforms: ['Windows'],
      execution: ['Static', 'Correlation'],
      evidence: ['workflow'],
    },
    artifacts: [{ type: 'fixture_workflow_seed' }],
    evidence: [{ category: 'workflow', artifactTypes: ['fixture_workflow_seed'] }],
    workflowRecipes: [
      {
        id: 'fixture.workflow.review',
        title: 'Fixture workflow review',
        startsWith: ['fixture.workflow.seed'],
        nextTools: ['analysis.evidence.graph'],
      },
    ],
    workerBackend: {
      version: 'backend-worker.v1',
      backendName: 'FixtureMatrixWorker',
      backendKind: 'external',
      adapter: 'fixture.matrix.worker',
      availability: 'optional',
      defaultMode: 'builtin',
      supportedModes: ['builtin', 'external'],
      outputArtifactTypes: ['fixture_workflow_seed'],
      policy: {
        passiveByDefault: true,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      },
      readiness: {
        doesNotStartBackend: true,
      },
    },
  }

  const summary = buildToolAspectSummary(toolDefinition)
  expect(summary.format_matrix.pe.workflow_recipes).toEqual(['fixture.workflow.review'])
  expect(summary.workflow_recipes).toEqual([
    expect.objectContaining({ id: 'fixture.workflow.review' }),
  ])
  expect(summary.worker_backend).toEqual(
    expect.objectContaining({
      version: 'backend-worker.v1',
      backendName: 'FixtureMatrixWorker',
      adapter: 'fixture.matrix.worker',
    })
  )

  const matrix = buildPluginAspectMatrix([
    {
      id: 'fixture-workflow',
      status: 'loaded',
      aspects: toolDefinition.aspects,
      tools: [{ name: toolDefinition.name, definition: toolDefinition }],
    },
  ])
  expect(matrix.summary.workflow_recipe_count).toBe(1)
  expect(matrix.by_workflow['fixture.workflow.review'].tools).toEqual(['fixture.workflow.seed'])
})

describe('cross-platform file type detection', () => {
  test('detects Android package and bytecode formats', () => {
    expect(detectFileType(localZip(['AndroidManifest.xml', 'classes.dex']), 'sample.apk')).toBe(
      'APK'
    )
    expect(detectFileType(localZip(['base/manifest/AndroidManifest.xml']), 'sample.aab')).toBe(
      'AAB'
    )
    expect(detectFileType(localZip(['splits/base.apk']), 'sample.apks')).toBe('APKS')
    expect(detectFileType(localZip(['base.apk']), 'sample.xapk')).toBe('XAPK')
    expect(detectFileType(Buffer.from('dex\n035\0'), 'classes.dex')).toBe('DEX')
    expect(detectFileType(Buffer.from('vdex035\0'), 'classes.vdex')).toBe('VDEX')
    expect(detectFileType(Buffer.from('oat\n000\0'), 'boot.oat')).toBe('OAT')
    expect(detectFileType(Buffer.from('dey\n036\0'), 'classes.odex')).toBe('ODEX')
    expect(detectFileType(Buffer.from('art\n000\0'), 'boot.art')).toBe('ART')
  })

  test('detects Apple and Linux package formats', () => {
    expect(detectFileType(localZip(['Payload/App.app/Info.plist']), 'sample.ipa')).toBe('IPA')
    expect(detectFileType(Buffer.from('xar!0000'), 'sample.pkg')).toBe('PKG')
    expect(
      detectFileType(Buffer.concat([Buffer.alloc(512), Buffer.from('koly')]), 'sample.dmg')
    ).toBe('DMG')
    expect(
      detectFileType(Buffer.concat([Buffer.from('!<arch>\n'), arMember('debian-binary')]), 'x.deb')
    ).toBe('DEB')
    expect(detectFileType(Buffer.from([0xed, 0xab, 0xee, 0xdb]), 'x.rpm')).toBe('RPM')
    expect(detectFileType(Buffer.from([0x1f, 0x8b, 0x08, 0x00]), 'x.apk')).toBe('APK-Alpine')
    expect(detectFileType(Buffer.alloc(16), 'Demo.app')).toBe('App-Bundle')
    expect(detectFileType(Buffer.alloc(16), 'Demo.framework')).toBe('Framework')
    expect(detectFileType(Buffer.alloc(16), 'Demo.xcframework')).toBe('XCFramework')
    expect(detectFileType(Buffer.alloc(16), 'Demo.dSYM')).toBe('dSYM')
    expect(detectFileType(Buffer.alloc(16), 'embedded.mobileprovision')).toBe('MobileProvision')
  })

  test('detects AppImage and WASM without breaking ELF detection', () => {
    const appImage = Buffer.alloc(16)
    appImage[0] = 0x7f
    appImage[1] = 0x45
    appImage[2] = 0x4c
    appImage[3] = 0x46
    appImage.write('AI', 8, 'ascii')

    const elf = Buffer.from('\x7fELF\x02\x01\x01\x00')
    expect(detectFileType(appImage, 'tool.AppImage')).toBe('AppImage')
    expect(detectFileType(elf, 'tool.bin')).toBe('ELF')
    expect(detectFileType(elfFixture(2), 'tool')).toBe('ELF-Executable')
    expect(detectFileType(elfFixture(3), 'libdemo.so')).toBe('ELF-SO')
    expect(detectFileType(elfFixture(4), 'core.123')).toBe('ELF-Core')
    expect(detectFileType(Buffer.from([0x00, 0x61, 0x73, 0x6d]), 'module.wasm')).toBe('WASM')
    expect(detectFileType(Buffer.alloc(16), 'program.bpf')).toBe('eBPF-Bytecode')
    expect(detectFileType(Buffer.alloc(16), 'program.ebpf')).toBe('eBPF-Bytecode')
  })

  test('detects JVM archives/classes and script bytecode formats', () => {
    expect(detectFileType(localZip(['META-INF/MANIFEST.MF', 'demo/Main.class']), 'demo.jar')).toBe(
      'JAR'
    )
    expect(
      detectFileType(localZip(['WEB-INF/web.xml', 'WEB-INF/classes/demo/Main.class']), 'demo.war')
    ).toBe('WAR')
    expect(detectFileType(localZip(['classes/module-info.class']), 'demo.jmod')).toBe('JMOD')
    expect(detectFileType(Buffer.from([0xca, 0xfe, 0xba, 0xbe]), 'Main.class')).toBe('CLASS')
    expect(detectFileType(Buffer.alloc(16), 'module.pyc')).toBe('PYC')
    expect(detectFileType(Buffer.from([0x1b, 0x4c, 0x75, 0x61, 0x54]), 'chunk.luac')).toBe(
      'Lua-Bytecode'
    )
    expect(detectFileType(Buffer.alloc(16), 'cache.jsc')).toBe('V8-Cache')
    expect(detectFileType(Buffer.from('function demo(){}'), 'demo.js')).toBe('JavaScript')
    expect(detectFileType(Buffer.from('export const demo = 1'), 'demo.mjs')).toBe('MJS')
    expect(detectFileType(Buffer.from('module.exports = {}'), 'demo.cjs')).toBe('CJS')
    expect(detectFileType(Buffer.from('{"version":3}'), 'bundle.map')).toBe('Source-Map')
    expect(detectFileType(Buffer.from('(module)'), 'module.wat')).toBe('WAT')
  })

  test('detects Windows installer, debug symbol, and managed runtime formats', () => {
    const ole = Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
    const pdb = Buffer.concat([
      Buffer.from('Microsoft C/C++ MSF 7.00\r\n', 'ascii'),
      Buffer.alloc(64),
    ])
    const peClr = Buffer.concat([Buffer.from('MZ'), Buffer.from('mscoree.dll\0BSJB')])
    const nsis = Buffer.concat([Buffer.from('MZ'), Buffer.from('NullsoftInst')])
    const inno = Buffer.concat([Buffer.from('MZ'), Buffer.from('Inno Setup')])
    const unityMetadata = Buffer.alloc(16)
    unityMetadata[0] = 0xfa
    unityMetadata[1] = 0xb1
    unityMetadata[2] = 0x1b
    unityMetadata[3] = 0xaf

    expect(detectFileType(ole, 'setup.msi')).toBe('MSI')
    expect(detectFileType(localZip(['AppxManifest.xml', 'VFS/Demo.exe']), 'sample.msix')).toBe(
      'MSIX'
    )
    expect(
      detectFileType(
        localZip(['package/services/metadata/core-properties/1.psmdcp']),
        'sample.appx'
      )
    ).toBe('APPX')
    expect(detectFileType(cabFixture(), 'payload.cab')).toBe('CAB')
    expect(detectFileType(nsis, 'setup.exe')).toBe('NSIS')
    expect(detectFileType(inno, 'setup.exe')).toBe('Inno')
    expect(detectFileType(pdb, 'demo.pdb')).toBe('PDB')
    expect(detectFileType(Buffer.alloc(20), 'demo.obj')).toBe('COFF')
    expect(detectFileType(peClr, 'managed.exe')).toBe('PE-CLR')
    expect(detectFileType(localZip(['lib/net8.0/Demo.dll', 'Demo.nuspec']), 'Demo.nupkg')).toBe(
      'NUPKG'
    )
    expect(detectFileType(unityMetadata, 'global-metadata.dat')).toBe('Unity-Metadata')
    expect(detectFileType(Buffer.from('MZ il2cpp'), 'GameAssembly.dll')).toBe('IL2CPP')
  })

  test('detects generic archive and container formats', () => {
    expect(detectFileType(localZip(['bin/tool.exe', 'lib/libdemo.so']), 'bundle.zip')).toBe('ZIP')
    expect(detectFileType(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), 'bundle.7z')).toBe(
      '7z'
    )
    expect(detectFileType(Buffer.from('Rar!\x1a\x07\x00'), 'bundle.rar')).toBe('RAR')
    expect(detectFileType(tarFixture(['manifest.json', 'layer.tar']), 'image.tar')).toBe(
      'Docker-Image'
    )
    expect(
      detectFileType(tarFixture(['oci-layout', 'blobs/sha256/config.json']), 'image.tar')
    ).toBe('OCI-Image')
    expect(detectFileType(Buffer.from([0x1f, 0x8b, 0x08, 0x00]), 'bundle.gz')).toBe('GZ')
    expect(detectFileType(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]), 'bundle.xz')).toBe(
      'XZ'
    )
    expect(detectFileType(Buffer.from([0x28, 0xb5, 0x2f, 0xfd]), 'bundle.zst')).toBe('ZSTD')
    expect(detectFileType(isoFixture(), 'bundle.iso')).toBe('ISO')
  })

  test('detects object, static library, kernel module, and firmware filesystem formats', () => {
    const uimage = Buffer.alloc(16)
    uimage.writeUInt32BE(0x27051956, 0)
    const dtb = Buffer.alloc(16)
    dtb.writeUInt32BE(0xd00dfeed, 0)
    const cramfs = Buffer.alloc(16)
    cramfs.writeUInt32LE(0x28cd3d45, 0)
    const ubifs = Buffer.alloc(16)
    ubifs.writeUInt32LE(0x06101831, 0)

    expect(detectFileType(elfFixture(1), 'demo.o')).toBe('ELF-Object')
    expect(detectFileType(elfFixture(1, 247), 'xdp.o')).toBe('eBPF-ELF')
    expect(detectFileType(elfFixture(1, 247), 'xdp.bpf')).toBe('eBPF-ELF')
    expect(
      detectFileType(Buffer.concat([elfFixture(1), Buffer.from('vermagic=6.1')]), 'demo.ko')
    ).toBe('Linux-Kernel-Module')
    expect(detectFileType(machoObjectFixture(), 'demo.o')).toBe('Mach-O-Object')
    expect(
      detectFileType(Buffer.concat([Buffer.from('!<arch>\n'), arMember('demo.o')]), 'libdemo.a')
    ).toBe('AR-Static-Lib')
    expect(detectFileType(uimage, 'firmware.uImage')).toBe('U-Boot-uImage')
    expect(detectFileType(dtb, 'board.dtb')).toBe('DTB')
    expect(detectFileType(dtb, 'kernel.itb')).toBe('FIT-Image')
    expect(detectFileType(Buffer.from('070701demo'), 'initramfs.cpio')).toBe('CPIO')
    expect(detectFileType(Buffer.from('hsqs'), 'rootfs.squashfs')).toBe('SquashFS')
    expect(detectFileType(cramfs, 'rootfs.cramfs')).toBe('CramFS')
    expect(detectFileType(Buffer.from([0x85, 0x19]), 'rootfs.jffs2')).toBe('JFFS2')
    expect(detectFileType(Buffer.from('UBI#'), 'rootfs.ubi')).toBe('UBI')
    expect(detectFileType(ubifs, 'rootfs.ubifs')).toBe('UBIFS')
    expect(detectFileType(Buffer.from('-rom1fs-'), 'rootfs.romfs')).toBe('ROMFS')
  })
})

describe('passive package and Apple container inventory', () => {
  test('builds Android package inventory without install/runtime/decompiler semantics', () => {
    const data = localZip([
      'AndroidManifest.xml',
      'classes.dex',
      'classes2.dex',
      'resources.arsc',
      'META-INF/CERT.RSA',
      'lib/arm64-v8a/libdemo.so',
      'splits/base.apk',
    ])

    const inventory = buildAndroidPackageInventoryFromBuffer(data, { filename: 'demo.apk' })

    expect(inventory.package_format).toBe('apk')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_install: true,
        no_runtime_start: true,
        no_decompiler_launch: true,
        no_device_connection: true,
      })
    )
    expect(inventory.manifest_candidates).toContain('AndroidManifest.xml')
    expect(inventory.dex_candidates).toEqual(
      expect.arrayContaining(['classes.dex', 'classes2.dex'])
    )
    expect(inventory.signing_candidates).toContain('META-INF/CERT.RSA')
    expect(inventory.native_library_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'lib/arm64-v8a/libdemo.so',
          recommended_tools: expect.arrayContaining(['linux.binary.inventory']),
        }),
      ])
    )
    expect(inventory.nested_package_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'splits/base.apk',
          recommended_tools: expect.arrayContaining(['android.package.inventory']),
        }),
      ])
    )
  })

  test('builds Linux package inventory without install or script execution semantics', () => {
    const data = Buffer.concat([
      Buffer.from('!<arch>\n'),
      arMember('debian-binary'),
      arMember('control.tar', Buffer.from('postinst\nusr/lib/libdemo.so\n')),
    ])

    const inventory = buildLinuxPackageInventoryFromBuffer(data, { filename: 'demo.deb' })

    expect(inventory.package_format).toBe('deb')
    expect(inventory.policy).toEqual(
      expect.objectContaining({ passive: true, no_execute: true, no_install: true })
    )
    expect(inventory.archive_members).toEqual(
      expect.arrayContaining(['debian-binary', 'control.tar'])
    )
    expect(inventory.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: expect.stringContaining('libdemo.so'),
          recommended_tools: expect.arrayContaining(['elf.structure.analyze']),
        }),
      ])
    )
  })

  test('builds Apple container inventory without mount/install/device actions', () => {
    const data = localZip([
      'Payload/Demo.app/Info.plist',
      'Payload/Demo.app/embedded.mobileprovision',
      'Payload/Demo.app/Frameworks/libDemo.dylib',
    ])

    const inventory = buildAppleContainerInventoryFromBuffer(data, { filename: 'Demo.ipa' })

    expect(inventory.container_format).toBe('ipa')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_install: true,
        no_mount: true,
        no_device_connection: true,
      })
    )
    expect(inventory.plist_candidates).toContain('Payload/Demo.app/Info.plist')
    expect(inventory.provisioning_candidates).toContain('Payload/Demo.app/embedded.mobileprovision')
    expect(inventory.nested_macho_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'Payload/Demo.app/Frameworks/libDemo.dylib',
          recommended_tools: expect.arrayContaining(['macho.structure.analyze']),
        }),
      ])
    )
  })

  test('builds Apple signing inventory without codesign/keychain/device/network actions', () => {
    const data = localZip([
      'Payload/Demo.app/Info.plist',
      'Payload/Demo.app/embedded.mobileprovision',
      'Payload/Demo.app/archived-expanded-entitlements.xcent',
      'Payload/Demo.app/Frameworks/libDemo.dylib',
      'Payload/Demo.app/_CodeSignature/CodeResources',
    ])

    const inventory = buildAppleSigningInspectFromBuffer(
      Buffer.concat([
        data,
        Buffer.from(
          'application-identifier com.apple.developer.team-identifier Apple Distribution'
        ),
      ]),
      { filename: 'Demo.ipa' }
    )

    expect(inventory.format).toBe('ipa')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_codesign_verification: true,
        no_keychain_access: true,
        no_device_connection: true,
        no_network_lookup: true,
      })
    )
    expect(inventory.bundle_metadata_candidates).toContain('Payload/Demo.app/Info.plist')
    expect(inventory.provisioning_candidates).toContain('Payload/Demo.app/embedded.mobileprovision')
    expect(inventory.entitlement_hints).toEqual(
      expect.arrayContaining(['application-identifier', 'com.apple.developer.team-identifier'])
    )
    expect(inventory.certificate_hints).toEqual(expect.arrayContaining(['Apple Distribution']))
    expect(inventory.nested_code_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'Payload/Demo.app/Frameworks/libDemo.dylib',
          recommended_tools: expect.arrayContaining(['macho.structure.analyze']),
        }),
      ])
    )
  })

  test('builds Linux binary inventory without execute/load/core replay/module load semantics', () => {
    const elf = Buffer.concat([
      elfFixture(2),
      Buffer.from('/lib64/ld-linux-x86-64.so.2\0libc.so.6\0GLIBC_2.34\0_start'),
    ])
    const kernelModule = Buffer.concat([
      elfFixture(1),
      Buffer.from('vermagic=6.1.0 depends=usbcore name=demo'),
    ])
    const initramfs = cpioNewcFixture([
      { name: 'init' },
      { name: 'lib/modules/demo.ko' },
      { name: 'usr/bin/tool.elf' },
    ])

    const elfInventory = buildLinuxBinaryInventoryFromBuffer(elf, { filename: 'tool' })
    const moduleInventory = buildLinuxBinaryInventoryFromBuffer(kernelModule, {
      filename: 'demo.ko',
    })
    const initramfsInventory = buildLinuxBinaryInventoryFromBuffer(initramfs, {
      filename: 'initramfs.cpio',
    })

    expect(elfInventory.format).toBe('elf-executable')
    expect(elfInventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_load: true,
        no_core_replay: true,
        no_kernel_module_load: true,
        no_mount: true,
        no_runtime_start: true,
      })
    )
    expect(elfInventory.interpreter_hints).toContain('/lib64/ld-linux-x86-64.so.2')
    expect(elfInventory.shared_library_hints).toContain('libc.so.6')
    expect(moduleInventory.format).toBe('linux-kernel-module')
    expect(moduleInventory.kernel_module_hints).toEqual(
      expect.arrayContaining(['vermagic=6.1.0', 'depends=usbcore', 'name=demo'])
    )
    expect(initramfsInventory.format).toBe('cpio')
    expect(initramfsInventory.initramfs_members).toEqual(
      expect.arrayContaining(['init', 'lib/modules/demo.ko', 'usr/bin/tool.elf'])
    )
    expect(initramfsInventory.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'lib/modules/demo.ko',
          recommended_tools: expect.arrayContaining(['linux.binary.inventory']),
        }),
        expect.objectContaining({
          path: 'usr/bin/tool.elf',
          recommended_tools: expect.arrayContaining(['elf.structure.analyze']),
        }),
      ])
    )
  })
})

describe('passive bytecode and portable runtime inventory', () => {
  test('builds JVM inventory without executing bytecode or launching a decompiler', () => {
    const inventory = buildJvmStructureFromBuffer(
      localZip(['META-INF/MANIFEST.MF', 'com/example/Main.class', 'lib/helper.jar']),
      { filename: 'demo.jar' }
    )

    expect(inventory.format).toBe('jar')
    expect(inventory.policy).toEqual(
      expect.objectContaining({ passive: true, no_execute: true, no_decompiler_launch: true })
    )
    expect(inventory.class_files).toContain('com/example/Main.class')
    expect(inventory.packages).toContain('com.example')
    expect(inventory.nested_archive_candidates).toContain('lib/helper.jar')
  })

  test('builds WASM inventory without starting a runtime', () => {
    const wasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x07, 0x01, 0x00])
    const inventory = buildWasmStructureFromBuffer(wasm, { filename: 'module.wasm' })

    expect(inventory.format).toBe('wasm')
    expect(inventory.valid_magic).toBe(true)
    expect(inventory.version).toBe(1)
    expect(inventory.sections).toEqual([
      expect.objectContaining({ id: 7, name: 'export', size: 1 }),
    ])
    expect(inventory.policy).toEqual(
      expect.objectContaining({ passive: true, no_execute: true, no_runtime_start: true })
    )
  })

  test('builds script bytecode metadata without starting interpreters', () => {
    const pyc = Buffer.alloc(32)
    pyc.writeUInt32LE(0x0a0d0da7, 0)
    pyc.writeUInt32LE(0, 4)
    pyc.writeUInt32LE(1234567890, 8)
    pyc.writeUInt32LE(42, 12)
    Buffer.from('module.path').copy(pyc, 16)

    const inventory = buildBytecodeMetadataFromBuffer(pyc, { filename: 'module.pyc' })

    expect(inventory.format).toBe('pyc')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_interpreter_start: true,
        no_decompiler_launch: true,
      })
    )
    expect(inventory.header).toEqual(expect.objectContaining({ source_size: 42 }))
    expect(inventory.version_hints).toEqual(expect.arrayContaining(['CPython 3.11']))
    expect(inventory.string_hints).toContain('module.path')
  })
})

describe('passive Windows and managed format inventory', () => {
  test('builds Windows installer inventory without install or payload execution semantics', () => {
    const data = localZip(['AppxManifest.xml', 'VFS/Demo.exe', 'scripts/install.ps1'])

    const inventory = buildWindowsInstallerInventoryFromBuffer(data, { filename: 'demo.msix' })

    expect(inventory.installer_format).toBe('msix')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_install: true,
        no_payload_launch: true,
      })
    )
    expect(inventory.archive_members).toEqual(
      expect.arrayContaining(['AppxManifest.xml', 'VFS/Demo.exe', 'scripts/install.ps1'])
    )
    expect(inventory.script_candidates).toContain('scripts/install.ps1')
    expect(inventory.nested_payload_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'VFS/Demo.exe',
          recommended_tools: expect.arrayContaining(['pe.structure.analyze']),
        }),
      ])
    )
  })

  test('builds Windows debug metadata without symbol server access', () => {
    const data = Buffer.alloc(96)
    Buffer.from('Microsoft C/C++ MSF 7.00\r\n', 'ascii').copy(data, 0)
    data.writeUInt32LE(4096, 32)
    data.writeUInt32LE(0, 36)
    data.writeUInt32LE(12, 40)
    data.writeUInt32LE(128, 44)

    const inventory = buildWindowsDebugMetadataFromBuffer(data, { filename: 'demo.pdb' })

    expect(inventory.format).toBe('pdb')
    expect(inventory.header).toEqual(expect.objectContaining({ page_size: 4096 }))
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_symbol_server_download: true,
        no_source_fetch: true,
      })
    )
  })

  test('builds .NET inventory without runtime start, package restore, or decompiler launch', () => {
    const data = localZip([
      'Demo.nuspec',
      'lib/net8.0/Demo.dll',
      'runtimes/win-x64/native/helper.dll',
      'contentFiles/any/net8.0/appsettings.json',
    ])

    const inventory = buildDotnetAssemblyInventoryFromBuffer(data, { filename: 'Demo.nupkg' })

    expect(inventory.format).toBe('nupkg')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_runtime_start: true,
        no_package_restore: true,
        no_decompiler_launch: true,
      })
    )
    expect(inventory.assembly_hints).toContain('lib/net8.0/Demo.dll')
    expect(inventory.target_framework_hints).toContain('net8.0')
    expect(inventory.dependency_hints).toEqual(
      expect.arrayContaining(['lib/net8.0/Demo.dll', 'runtimes/win-x64/native/helper.dll'])
    )
  })

  test('builds Unity metadata inventory without runtime or native library loading', () => {
    const data = Buffer.concat([
      Buffer.from([0xfa, 0xb1, 0x1b, 0xaf, 0x1d, 0x00, 0x00, 0x00]),
      Buffer.from('GameAssembly.dll global-metadata.dat Assembly-CSharp.dll Unity 2022.3.1f1'),
    ])

    const inventory = buildUnityMetadataInventoryFromBuffer(data, {
      filename: 'global-metadata.dat',
    })

    expect(inventory.format).toBe('unity-metadata')
    expect(inventory.header).toEqual(expect.objectContaining({ metadata_version: 29 }))
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_runtime_start: true,
        no_native_load: true,
      })
    )
    expect(inventory.managed_assembly_candidates).toContain('Assembly-CSharp.dll')
    expect(inventory.il2cpp_candidates).toContain('GameAssembly.dll')
    expect(inventory.metadata_candidates).toContain('global-metadata.dat')
  })
})

describe('passive generic container inventory', () => {
  test('builds ZIP inventory with traversal guard and nested routing', () => {
    const data = localZip([
      '../evil.exe',
      'bin/tool.elf',
      'lib/module.ko',
      'obj/demo.o',
      'lib/libdemo.a',
      'Payload/App.app/Frameworks/libDemo.dylib',
      'Payload/App.app.dSYM',
      'classes/demo.jar',
      'module.wasm',
      'rootfs.squashfs',
    ])

    const inventory = buildContainerStructureFromBuffer(data, { filename: 'bundle.zip' })

    expect(inventory.container_format).toBe('zip')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_extract_to_execution_path: true,
        no_install: true,
        no_mount: true,
        no_entrypoint_run: true,
      })
    )
    expect(inventory.risk_flags).toContain('path-traversal')
    expect(inventory.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: '../evil.exe',
          recommended_tools: expect.arrayContaining(['pe.structure.analyze']),
        }),
        expect.objectContaining({
          path: 'bin/tool.elf',
          recommended_tools: expect.arrayContaining([
            'linux.binary.inventory',
            'elf.structure.analyze',
          ]),
        }),
        expect.objectContaining({
          path: 'lib/module.ko',
          recommended_tools: expect.arrayContaining([
            'linux.binary.inventory',
            'native.object.inventory',
          ]),
        }),
        expect.objectContaining({
          path: 'obj/demo.o',
          recommended_tools: expect.arrayContaining(['native.object.inventory']),
        }),
        expect.objectContaining({
          path: 'lib/libdemo.a',
          recommended_tools: expect.arrayContaining(['native.object.inventory']),
        }),
        expect.objectContaining({
          path: 'Payload/App.app/Frameworks/libDemo.dylib',
          recommended_tools: expect.arrayContaining([
            'apple.signing.inspect',
            'macho.structure.analyze',
          ]),
        }),
        expect.objectContaining({
          path: 'Payload/App.app.dSYM',
          recommended_tools: expect.arrayContaining(['native.object.inventory']),
        }),
        expect.objectContaining({
          path: 'classes/demo.jar',
          recommended_tools: expect.arrayContaining(['jvm.structure.analyze']),
        }),
        expect.objectContaining({
          path: 'module.wasm',
          recommended_tools: expect.arrayContaining(['wasm.structure.analyze']),
        }),
        expect.objectContaining({
          path: 'rootfs.squashfs',
          recommended_tools: expect.arrayContaining(['firmware.scan']),
        }),
      ])
    )
  })

  test('builds Docker and OCI inventories without running entrypoints', () => {
    const docker = buildContainerStructureFromBuffer(
      tarFixture(['manifest.json', 'layer.tar', 'config.json', 'bin/entrypoint.sh']),
      { filename: 'image.tar' }
    )
    const oci = buildContainerStructureFromBuffer(
      tarFixture(['oci-layout', 'index.json', 'blobs/sha256/layer.tar']),
      { filename: 'oci.tar' }
    )

    expect(docker.container_format).toBe('docker-image')
    expect(docker.policy.no_entrypoint_run).toBe(true)
    expect(docker.risk_flags).toContain('container-entrypoint-not-run')
    expect(docker.entrypoint_candidates).toContain('bin/entrypoint.sh')
    expect(oci.container_format).toBe('oci-image')
    expect(oci.policy.no_mount).toBe(true)
  })
})

describe('passive native object inventory', () => {
  test('builds object/static-library inventory without linking or loading content', () => {
    const data = Buffer.concat([
      Buffer.from('!<arch>\n'),
      arMember('demo.o', Buffer.from('Java_com_example_Main_run')),
      arMember('module.ko', Buffer.from('vermagic=6.1.0')),
      arMember('debug.dSYM'),
    ])

    const inventory = buildNativeObjectInventoryFromBuffer(data, { filename: 'libdemo.a' })

    expect(inventory.format).toBe('ar-static-lib')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_link: true,
        no_load: true,
        no_strip_or_sign: true,
      })
    )
    expect(inventory.member_names).toEqual(
      expect.arrayContaining(['demo.o', 'module.ko', 'debug.dSYM'])
    )
    expect(inventory.symbol_hints).toEqual(expect.arrayContaining(['Java_com_example_Main_run']))
    expect(inventory.nested_binary_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: 'demo.o',
          recommended_tools: expect.arrayContaining(['native.object.inventory']),
        }),
        expect.objectContaining({
          path: 'module.ko',
          recommended_tools: expect.arrayContaining(['elf.structure.analyze']),
        }),
        expect.objectContaining({
          path: 'debug.dSYM',
          recommended_tools: expect.arrayContaining(['native.object.inventory']),
        }),
      ])
    )
  })
})

describe('built-in plugin format matrix discovery', () => {
  test('discovers cross-platform format plugins with declared aspects', async () => {
    const plugins = await discoverBuiltInPlugins()
    const linuxPackage = plugins.find((plugin) => plugin.id === 'linux-package')
    const appleContainer = plugins.find((plugin) => plugin.id === 'apple-container')
    const jvm = plugins.find((plugin) => plugin.id === 'jvm')
    const wasm = plugins.find((plugin) => plugin.id === 'wasm')
    const bytecode = plugins.find((plugin) => plugin.id === 'bytecode')
    const ebpfBytecode = plugins.find((plugin) => plugin.id === 'ebpf-bytecode')
    const windowsInstaller = plugins.find((plugin) => plugin.id === 'windows-installer')
    const windowsDebugSymbols = plugins.find((plugin) => plugin.id === 'windows-debug-symbols')
    const dotnetManaged = plugins.find((plugin) => plugin.id === 'dotnet-managed')
    const unityManaged = plugins.find((plugin) => plugin.id === 'unity-managed')
    const containerAnalysis = plugins.find((plugin) => plugin.id === 'container-analysis')
    const nativeObject = plugins.find((plugin) => plugin.id === 'native-object')
    const androidPackage = plugins.find((plugin) => plugin.id === 'android-package')
    const appleSigning = plugins.find((plugin) => plugin.id === 'apple-signing')
    const linuxBinary = plugins.find((plugin) => plugin.id === 'linux-binary')

    expect(linuxPackage?.aspects?.formats).toEqual(
      expect.arrayContaining(['deb', 'rpm', 'apk-alpine', 'appimage'])
    )
    expect(linuxPackage?.tools?.map((tool) => tool.definition.name)).toContain(
      'linux.package.inventory'
    )
    expect(appleContainer?.aspects?.formats).toEqual(
      expect.arrayContaining(['ipa', 'dmg', 'pkg', 'dsym', 'mobileprovision'])
    )
    expect(appleContainer?.tools?.map((tool) => tool.definition.name)).toContain(
      'apple.container.inventory'
    )
    expect(jvm?.aspects?.formats).toEqual(expect.arrayContaining(['jar', 'class', 'war', 'jmod']))
    expect(jvm?.tools?.map((tool) => tool.definition.name)).toContain('jvm.structure.analyze')
    expect(wasm?.aspects?.formats).toEqual(expect.arrayContaining(['wasm', 'wasi']))
    expect(wasm?.tools?.map((tool) => tool.definition.name)).toContain('wasm.structure.analyze')
    expect(bytecode?.aspects?.formats).toEqual(
      expect.arrayContaining(['pyc', 'lua-bytecode', 'v8-cache'])
    )
    expect(bytecode?.tools?.map((tool) => tool.definition.name)).toContain(
      'bytecode.metadata.inspect'
    )
    expect(ebpfBytecode?.aspects?.formats).toEqual(
      expect.arrayContaining(['ebpf', 'bpf', 'raw-ebpf', 'ebpf-elf'])
    )
    expect(ebpfBytecode?.tools?.map((tool) => tool.definition.name)).toContain(
      'ebpf.bytecode.inventory'
    )
    expect(windowsInstaller?.aspects?.formats).toEqual(
      expect.arrayContaining(['msi', 'msix', 'appx', 'cab', 'nsis', 'inno'])
    )
    expect(windowsInstaller?.tools?.map((tool) => tool.definition.name)).toContain(
      'installer.inventory'
    )
    expect(windowsDebugSymbols?.aspects?.formats).toEqual(expect.arrayContaining(['pdb', 'coff']))
    expect(windowsDebugSymbols?.tools?.map((tool) => tool.definition.name)).toContain(
      'windows.debug.metadata.inspect'
    )
    expect(dotnetManaged?.aspects?.formats).toEqual(
      expect.arrayContaining(['dotnet', 'pe-clr', 'nupkg', 'mono', 'winmd'])
    )
    expect(dotnetManaged?.tools?.map((tool) => tool.definition.name)).toContain(
      'dotnet.assembly.inspect'
    )
    expect(unityManaged?.aspects?.formats).toEqual(
      expect.arrayContaining(['unity', 'unity-metadata', 'il2cpp'])
    )
    expect(unityManaged?.tools?.map((tool) => tool.definition.name)).toContain(
      'unity.metadata.inspect'
    )
    expect(containerAnalysis?.aspects?.formats).toEqual(
      expect.arrayContaining([
        'archive',
        'container',
        'zip',
        'tar',
        'ar-static-lib',
        'docker-image',
        'oci-image',
      ])
    )
    expect(containerAnalysis?.tools?.map((tool) => tool.definition.name)).toContain(
      'container.structure.analyze'
    )
    expect(nativeObject?.aspects?.formats).toEqual(
      expect.arrayContaining(['object', 'ar-static-lib', 'elf-object', 'linux-kernel-module'])
    )
    expect(nativeObject?.tools?.map((tool) => tool.definition.name)).toContain(
      'native.object.inventory'
    )
    expect(androidPackage?.aspects?.formats).toEqual(
      expect.arrayContaining(['apk', 'aab', 'apks', 'xapk', 'dex', 'oat', 'vdex'])
    )
    expect(androidPackage?.tools?.map((tool) => tool.definition.name)).toContain(
      'android.package.inventory'
    )
    expect(appleSigning?.aspects?.formats).toEqual(
      expect.arrayContaining(['apple-signing', 'codesignature', 'entitlements', 'mobileprovision'])
    )
    expect(appleSigning?.tools?.map((tool) => tool.definition.name)).toContain(
      'apple.signing.inspect'
    )
    expect(linuxBinary?.aspects?.formats).toEqual(
      expect.arrayContaining(['elf-executable', 'elf-so', 'elf-core', 'linux-kernel-module'])
    )
    expect(linuxBinary?.tools?.map((tool) => tool.definition.name)).toContain(
      'linux.binary.inventory'
    )
  })

  test('discovers native reverse engineering adapters with tool-level metadata', async () => {
    const plugins = await discoverBuiltInPlugins()
    const ghidra = requirePlugin(plugins, 'ghidra')
    const rizin = requirePlugin(plugins, 'rizin')
    const retdec = requirePlugin(plugins, 'retdec')
    const capstone = requirePlugin(plugins, 'capstone')
    const elfMacho = requirePlugin(plugins, 'elf-macho')
    const apkSmali = requirePlugin(plugins, 'apk-smali')
    const firmware = requirePlugin(plugins, 'firmware')
    const nativeObject = requirePlugin(plugins, 'native-object')
    const ebpfBytecode = requirePlugin(plugins, 'ebpf-bytecode')
    const androidPackage = requirePlugin(plugins, 'android-package')
    const appleSigning = requirePlugin(plugins, 'apple-signing')
    const linuxBinary = requirePlugin(plugins, 'linux-binary')
    const codeAnalysis = requirePlugin(plugins, 'code-analysis')
    const apiHash = requirePlugin(plugins, 'api-hash')

    expect(ghidra.aspects?.formats).toEqual(expect.arrayContaining(['pe', 'elf', 'macho']))
    expect(rizin.aspects?.formats).toEqual(expect.arrayContaining(['pe', 'elf', 'macho']))
    expect(retdec.aspects?.execution).toEqual(expect.arrayContaining(['static', 'decompilation']))
    expect(capstone.aspects?.formats).toEqual(expect.arrayContaining(['shellcode', 'pe', 'elf']))
    expect(elfMacho.aspects?.formats).toEqual(
      expect.arrayContaining(['elf-object', 'linux-kernel-module', 'macho-object', 'dsym'])
    )
    expect(apkSmali.aspects?.formats).toEqual(expect.arrayContaining(['apk', 'aab', 'aar']))
    expect(firmware.aspects?.formats).toEqual(expect.arrayContaining(['cpio', 'squashfs', 'ubi']))
    expect(nativeObject.aspects?.formats).toEqual(
      expect.arrayContaining(['object', 'static-lib', 'linux-kernel-module'])
    )
    expect(androidPackage.aspects?.formats).toEqual(
      expect.arrayContaining(['android-package', 'apk', 'dex', 'apk-signature'])
    )
    expect(appleSigning.aspects?.formats).toEqual(
      expect.arrayContaining(['apple-signing', 'macho', 'mobileprovision'])
    )
    expect(linuxBinary.aspects?.formats).toEqual(
      expect.arrayContaining(['linux-binary', 'elf-executable', 'elf-core'])
    )
    expect(codeAnalysis.aspects?.capabilities).toEqual(
      expect.arrayContaining(['cross-decompiler-consensus', 'ir-comparison'])
    )

    expectToolMetadata(ghidra, 'ghidra.analyze', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['ghidra_analysis'],
      evidence: ['symbols', 'structure'],
    })
    expectToolMetadata(rizin, 'rizin.analyze', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['backend_rizin_imports', 'backend_rizin_functions'],
      evidence: ['structure', 'symbols', 'imports', 'exports', 'strings'],
    })
    expectToolMetadata(retdec, 'retdec.decompile', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['backend_retdec_decompile_plain', 'backend_retdec_decompile_json-human'],
      evidence: ['artifact'],
    })
    expectToolMetadata(capstone, 'shellcode.disasm', {
      formats: ['shellcode', 'pe'],
      artifacts: ['backend_capstone_shellcode'],
      evidence: ['structure'],
    })
    expectToolMetadata(elfMacho, 'elf.structure.analyze', {
      formats: ['elf', 'elf-object', 'linux-kernel-module'],
      artifacts: ['elf_structure'],
      evidence: ['structure'],
    })
    expectToolMetadata(elfMacho, 'macho.structure.analyze', {
      formats: ['macho', 'macho-object', 'dsym'],
      artifacts: ['macho_structure'],
      evidence: ['structure'],
    })
    expectToolMetadata(apkSmali, 'apk.manifest.parse', {
      formats: ['apk', 'aab', 'aar'],
      artifacts: ['backend_apk_manifest'],
      evidence: ['manifest'],
    })
    expectToolMetadata(firmware, 'firmware.scan', {
      formats: ['firmware', 'squashfs', 'ubi'],
      artifacts: ['firmware_scan'],
      evidence: ['signatures'],
    })
    expectToolMetadata(nativeObject, 'native.object.inventory', {
      formats: ['object', 'ar-static-lib', 'linux-kernel-module'],
      artifacts: ['native_object_inventory'],
      evidence: ['structure', 'symbols'],
    })
    expectToolMetadata(ebpfBytecode, 'ebpf.bytecode.inventory', {
      formats: ['ebpf', 'bpf', 'raw-ebpf', 'ebpf-elf'],
      artifacts: ['ebpf_bytecode_inventory'],
      evidence: ['structure', 'bytecode', 'control-flow', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'ebpf-bytecode',
      toolName: 'ebpf.bytecode.inventory',
      recipeId: 'ebpf.bytecode-static-inventory',
      startsWith: ['ebpf.bytecode.inventory'],
      nextTools: ['artifact.read', 'elf.structure.analyze', 'linux.runtime.plan'],
      producesArtifacts: ['ebpf_bytecode_inventory'],
      evidence: ['bytecode', 'control-flow', 'workflow'],
      safety: ['no_bpf_syscall', 'no_kernel_verifier_run', 'no_program_load'],
      runtimeBackends: ['linux-runtime'],
    })
    expectToolMetadata(androidPackage, 'android.package.inventory', {
      formats: ['android-package', 'apk', 'dex'],
      artifacts: ['android_package_inventory'],
      evidence: ['structure', 'manifest', 'signatures'],
    })
    expectToolMetadata(appleSigning, 'apple.signing.inspect', {
      formats: ['apple-signing', 'codesignature', 'mobileprovision'],
      artifacts: ['apple_signing_inventory'],
      evidence: ['manifest', 'certificates', 'package-metadata'],
    })
    expectToolMetadata(linuxBinary, 'linux.binary.inventory', {
      formats: ['linux-binary', 'elf-executable', 'elf-core'],
      artifacts: ['linux_binary_inventory'],
      evidence: ['structure', 'symbols', 'memory'],
    })
    expectToolMetadata(codeAnalysis, 'code.cross_decompiler.consensus', {
      formats: ['pe', 'elf', 'macho', 'firmware', 'object'],
      artifacts: ['cross_decompiler_consensus', 'function_evidence_handoff'],
      evidence: ['functions', 'cfg', 'artifact', 'workflow', 'correlation-graph'],
    })
    expectToolMetadata(apiHash, 'hash.resolver.plan', {
      formats: ['pe', 'shellcode', 'raw-bytes'],
      artifacts: ['api_hash_resolver_plan'],
      evidence: ['imports', 'strings', 'shellcode', 'workflow', 'provenance'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'code-analysis',
      toolName: 'code.cross_decompiler.consensus',
      recipeId: 'reverse.cross-decompiler.consensus',
      startsWith: ['code.cross_decompiler.consensus', 'ghidra.analyze'],
      nextTools: [
        'radare2.pipeline.run',
        'gtirb.ir.generate',
        'code.functions.reconstruct',
        'code.function.explain.prepare',
        'analysis.evidence.graph',
        'report.generate',
      ],
      producesArtifacts: ['cross_decompiler_consensus', 'function_evidence_handoff'],
      evidence: [
        'functions',
        'cfg',
        'symbols',
        'artifact',
        'workflow',
        'correlation-graph',
        'provenance',
      ],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      runtimeBackends: ['ghidra', 'retdec', 'rizin', 'radare2', 'angr', 'revng', 'remill', 'gtirb'],
    })
  })

  test('discovers cross-format enrichment plugins with artifact and evidence declarations', async () => {
    const plugins = await discoverBuiltInPlugins()
    const yara = requirePlugin(plugins, 'yara')
    const yaraX = requirePlugin(plugins, 'yara-x')
    const upx = requirePlugin(plugins, 'upx')
    const die = requirePlugin(plugins, 'die')
    const strings = requirePlugin(plugins, 'strings')
    const sbom = requirePlugin(plugins, 'sbom')
    const vulnScanner = requirePlugin(plugins, 'vuln-scanner')
    const threatIntel = requirePlugin(plugins, 'threat-intel')
    const javascriptDeobfuscation = requirePlugin(plugins, 'javascript-deobfuscation')
    const staticTriage = requirePlugin(plugins, 'static-triage')

    expect(yara.aspects?.formats).toEqual(expect.arrayContaining(['pe', 'elf', 'macho', 'apk']))
    expect(strings.aspects?.formats).toEqual(expect.arrayContaining(['apk', 'wasm', 'pyc']))
    expect(sbom.aspects?.formats).toEqual(
      expect.arrayContaining(['apk', 'nupkg', 'deb', 'docker-image'])
    )
    expect(threatIntel.aspects?.safety).toEqual(expect.arrayContaining(['no_network_by_default']))
    expect(javascriptDeobfuscation.aspects?.formats).toEqual(
      expect.arrayContaining(['js', 'javascript', 'source-map', 'v8-cache'])
    )
    expect(javascriptDeobfuscation.aspects?.capabilities).toEqual(
      expect.arrayContaining(['javascript-deobfuscation', 'jsvmp-triage'])
    )

    expectToolMetadata(yara, 'yara.scan', {
      formats: ['pe', 'elf', 'macho'],
      evidence: ['signatures', 'imports'],
    })
    expectToolMetadata(yara, 'yara.generate', {
      artifacts: ['yara_rule_generation'],
      evidence: ['signatures', 'strings', 'imports', 'workflow', 'provenance'],
    })
    expectToolMetadata(yara, 'yara.generate.batch', {
      artifacts: ['yara_family_rule'],
      evidence: ['signatures', 'strings', 'imports', 'workflow', 'provenance'],
    })
    expectToolMetadata(yaraX, 'yara_x.scan', {
      artifacts: ['backend_yara_x_scan'],
      evidence: ['signatures', 'strings', 'workflow', 'provenance'],
    })
    expectToolMetadata(upx, 'upx.inspect', {
      artifacts: ['backend_upx_list', 'backend_upx_test', 'backend_upx_decompress'],
      evidence: ['packed', 'structure', 'unpacked-binary', 'workflow', 'provenance'],
    })
    expectToolMetadata(die, 'die.scan', {
      artifacts: ['backend_die_scan'],
      evidence: [
        'signatures',
        'structure',
        'toolchain',
        'packer',
        'protector',
        'file-type',
        'workflow',
        'provenance',
      ],
    })
    expectToolMetadata(strings, 'strings.extract', {
      artifacts: ['enriched_string_analysis'],
      evidence: ['strings', 'network', 'encoded-config', 'workflow', 'provenance'],
    })
    expectToolMetadata(strings, 'strings.floss.decode', {
      artifacts: ['enriched_string_analysis'],
      evidence: ['strings', 'network', 'encoded-config', 'workflow', 'provenance'],
    })
    expectToolMetadata(sbom, 'sbom.generate', {
      evidence: ['sbom', 'package-metadata'],
    })
    expectToolMetadata(vulnScanner, 'vuln.pattern.scan', {
      artifacts: ['vuln_pattern_scan'],
      evidence: ['vulnerabilities'],
    })
    expectToolMetadata(threatIntel, 'ioc.export', {
      artifacts: ['ioc_export_json', 'ioc_export_csv', 'ioc_export_stix2'],
      evidence: ['network', 'filesystem', 'registry', 'signatures', 'workflow', 'provenance'],
    })
    expectToolMetadata(threatIntel, 'sigma.rule.generate', {
      artifacts: ['sigma_rules'],
      evidence: ['behavior', 'network', 'registry', 'strings', 'imports', 'workflow', 'provenance'],
    })
    expectToolMetadata(javascriptDeobfuscation, 'javascript.obfuscation.profile', {
      formats: ['js', 'javascript', 'source-map'],
      artifacts: ['javascript_obfuscation_profile'],
      evidence: ['structure', 'strings', 'behavior', 'workflow'],
    })
    expectToolMetadata(staticTriage, 'static.behavior.classify', {
      formats: ['pe', 'dll', 'dotnet'],
      artifacts: ['static_behavior_classifier'],
      evidence: ['behavior', 'strings', 'imports', 'registry', 'process', 'workflow'],
    })
    expectToolMetadata(staticTriage, 'crypto.identify', {
      formats: ['pe', 'dll', 'elf', 'shellcode'],
      artifacts: ['crypto_identification'],
      evidence: ['crypto', 'strings', 'imports', 'constants', 'functions', 'workflow'],
    })
    expectToolMetadata(staticTriage, 'static.config.carver', {
      formats: ['pe', 'dll', 'elf', 'shellcode'],
      artifacts: ['static_config_carver'],
      evidence: ['network', 'registry', 'strings', 'encoded-config', 'workflow'],
    })
    expectToolMetadata(staticTriage, 'static.resource.graph', {
      formats: ['pe', 'dll', 'dotnet', 'raw-bytes'],
      artifacts: ['static_resource_graph'],
      evidence: ['resources', 'embedded-payload', 'entropy', 'strings', 'workflow'],
    })
    expectToolMetadata(staticTriage, 'compiler.packer.detect', {
      formats: ['pe', 'dll', 'elf', 'macho'],
      artifacts: ['compiler_packer_attribution'],
      evidence: ['toolchain', 'signatures', 'packer', 'protector', 'workflow'],
    })
  })

  test('discovers advanced external backend planning plugins as passive plan-only surfaces', async () => {
    const plugins = await discoverBuiltInPlugins()
    const jsvmpAnalysis = requirePlugin(plugins, 'jsvmp-analysis')
    const revng = requirePlugin(plugins, 'revng')
    const triton = requirePlugin(plugins, 'triton')
    const miasm = requirePlugin(plugins, 'miasm')
    const lief = requirePlugin(plugins, 'lief')
    const radare2 = requirePlugin(plugins, 'radare2')
    const wabt = requirePlugin(plugins, 'wabt')
    const jsimplifier = requirePlugin(plugins, 'jsimplifier')
    const jsirCascade = requirePlugin(plugins, 'jsir-cascade')
    const restringer = requirePlugin(plugins, 'restringer')
    const remill = requirePlugin(plugins, 'remill')
    const gtirb = requirePlugin(plugins, 'gtirb')
    const qbdi = requirePlugin(plugins, 'qbdi')
    const manifold = requirePlugin(plugins, 'manifold')
    const culifter = requirePlugin(plugins, 'culifter')

    expect(jsvmpAnalysis.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'jsvmp-bytecode-recovery',
        'handler-map-recovery',
        'vm-dispatch-analysis',
      ])
    )

    expect(revng.aspects?.capabilities).toEqual(
      expect.arrayContaining(['binary-lifting', 'decompilation', 'cross-backend-comparison'])
    )
    expect(triton.aspects?.capabilities).toEqual(
      expect.arrayContaining(['symbolic-execution', 'taint-analysis', 'constraint-solving'])
    )
    expect(miasm.aspects?.capabilities).toEqual(
      expect.arrayContaining(['ir-lifting', 'data-flow', 'deobfuscation-plan'])
    )
    expect(lief.aspects?.capabilities).toEqual(
      expect.arrayContaining(['binary-format-abstraction', 'patch-plan'])
    )
    expect(radare2.aspects?.capabilities).toEqual(
      expect.arrayContaining(['r2pipe-integration-plan', 'cross-backend-comparison'])
    )
    expect(wabt.aspects?.capabilities).toEqual(
      expect.arrayContaining(['wasm-disassembly-plan', 'wasm2c-plan'])
    )
    expect(jsimplifier.aspects?.capabilities).toEqual(
      expect.arrayContaining(['javascript-deobfuscation-pipeline', 'ast-static-analysis-plan'])
    )
    expect(jsirCascade.aspects?.capabilities).toEqual(
      expect.arrayContaining(['javascript-ir-normalization', 'ast-deobfuscation-plan'])
    )
    expect(restringer.aspects?.capabilities).toEqual(
      expect.arrayContaining(['string-array-recovery', 'javascript-expression-simplification'])
    )
    expect(remill.aspects?.capabilities).toEqual(
      expect.arrayContaining(['llvm-bitcode-lifting', 'instruction-semantics'])
    )
    expect(gtirb.aspects?.capabilities).toEqual(
      expect.arrayContaining(['binary-ir', 'binary-rewriting-plan'])
    )
    expect(qbdi.aspects?.capabilities).toEqual(
      expect.arrayContaining(['dynamic-binary-instrumentation-plan', 'instruction-trace-plan'])
    )
    expect(manifold.aspects?.capabilities).toEqual(
      expect.arrayContaining(['superset-decompilation-plan', 'declarative-reverse-engineering'])
    )
    expect(culifter.aspects?.capabilities).toEqual(
      expect.arrayContaining(['gpu-binary-lifting-plan', 'sass-lifting-plan'])
    )

    for (const plugin of [
      jsvmpAnalysis,
      revng,
      triton,
      miasm,
      lief,
      radare2,
      wabt,
      jsimplifier,
      jsirCascade,
      restringer,
      remill,
      gtirb,
      qbdi,
      manifold,
      culifter,
    ]) {
      expect(plugin.executionDomain).toBe('static')
      expect(plugin.aspects?.safety).toEqual(
        expect.arrayContaining(['passive', 'no_live_sample_by_default', 'no_network_by_default'])
      )
    }

    expect(jsvmpAnalysis.surfaceRules?.tier).toBe(2)
    for (const plugin of [
      revng,
      triton,
      miasm,
      lief,
      radare2,
      wabt,
      jsimplifier,
      jsirCascade,
      restringer,
      remill,
      gtirb,
      qbdi,
      manifold,
      culifter,
    ]) {
      expect(plugin.surfaceRules?.tier).toBe(3)
    }

    expectToolMetadata(jsvmpAnalysis, 'jsvmp.bytecode.plan', {
      formats: ['js', 'javascript', 'source-map'],
      artifacts: ['jsvmp_bytecode_plan'],
      evidence: ['structure', 'strings', 'behavior', 'workflow'],
    })
    expectToolMetadata(revng, 'revng.pipeline.plan', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['revng_pipeline_plan'],
      evidence: ['structure', 'symbols', 'artifact', 'workflow'],
    })
    expectToolMetadata(triton, 'triton.symbolic.plan', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['triton_symbolic_plan'],
      evidence: ['structure', 'behavior', 'memory', 'workflow'],
    })
    expectToolMetadata(miasm, 'miasm.ir.plan', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['miasm_ir_plan'],
      evidence: ['structure', 'behavior', 'artifact', 'workflow'],
    })
    expectToolMetadata(lief, 'lief.binary.plan', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['lief_binary_plan'],
      evidence: ['structure', 'symbols', 'imports', 'exports', 'workflow'],
    })
    expectToolMetadata(radare2, 'radare2.pipeline.plan', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['radare2_pipeline_plan'],
      evidence: ['structure', 'symbols', 'strings', 'workflow'],
    })
    expectToolMetadata(wabt, 'wabt.toolchain.plan', {
      formats: ['wasm', 'wasi', 'wat'],
      artifacts: ['wabt_toolchain_plan'],
      evidence: ['structure', 'imports', 'exports', 'workflow'],
    })
    expectToolMetadata(jsimplifier, 'jsimplifier.pipeline.plan', {
      formats: ['js', 'javascript', 'source-map'],
      artifacts: ['jsimplifier_pipeline_plan'],
      evidence: ['structure', 'strings', 'behavior', 'workflow'],
    })
    expectToolMetadata(jsirCascade, 'jsir.cascade.plan', {
      formats: ['js', 'javascript', 'source-map'],
      artifacts: ['jsir_cascade_plan'],
      evidence: ['structure', 'strings', 'behavior', 'workflow'],
    })
    expectToolMetadata(restringer, 'restringer.deobfuscation.plan', {
      formats: ['js', 'javascript', 'typescript'],
      artifacts: ['restringer_deobfuscation_plan'],
      evidence: ['structure', 'strings', 'behavior', 'workflow'],
    })
    expectToolMetadata(remill, 'remill.lift.plan', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['remill_lift_plan'],
      evidence: ['structure', 'symbols', 'behavior', 'workflow'],
    })
    expectToolMetadata(gtirb, 'gtirb.ir.plan', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['gtirb_ir_plan'],
      evidence: ['structure', 'symbols', 'artifact', 'workflow'],
    })
    expectToolMetadata(qbdi, 'qbdi.instrumentation.plan', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['qbdi_instrumentation_plan'],
      evidence: ['structure', 'behavior', 'memory', 'timeline', 'workflow'],
    })
    expectToolMetadata(manifold, 'manifold.decompilation.plan', {
      formats: ['pe', 'elf', 'macho'],
      artifacts: ['manifold_decompilation_plan'],
      evidence: ['structure', 'symbols', 'behavior', 'workflow'],
    })
    expectToolMetadata(culifter, 'culifter.gpu.plan', {
      formats: ['elf', 'linux-binary', 'object'],
      artifacts: ['culifter_gpu_plan'],
      evidence: ['structure', 'symbols', 'imports', 'exports', 'workflow'],
    })
  })

  test('discovers correlation, evidence, memory, network, and reporting plugins', async () => {
    const plugins = await discoverBuiltInPlugins()
    const pcapAnalysis = requirePlugin(plugins, 'pcap-analysis')
    const hostCorrelation = requirePlugin(plugins, 'host-correlation')
    const memoryForensics = requirePlugin(plugins, 'memory-forensics')
    const visualization = requirePlugin(plugins, 'visualization')
    const reporting = requirePlugin(plugins, 'reporting')

    expect(pcapAnalysis.aspects?.formats).toEqual(
      expect.arrayContaining(['pcap', 'pcapng', 'network-capture'])
    )
    expect(pcapAnalysis.aspects?.safety).toEqual(
      expect.arrayContaining(['passive', 'no_network_by_default'])
    )
    expect(hostCorrelation.aspects?.formats).toEqual(
      expect.arrayContaining(['pe', 'dll', 'windows-host-artifacts'])
    )
    expect(hostCorrelation.aspects?.execution).toEqual(
      expect.arrayContaining(['static', 'correlation'])
    )
    expect(memoryForensics.aspects?.formats).toEqual(
      expect.arrayContaining(['memory-dump', 'vmem', 'elf-core'])
    )
    expect(memoryForensics.aspects?.evidence).toEqual(
      expect.arrayContaining(['memory', 'process', 'registry', 'network'])
    )
    expect(visualization.aspects?.execution).toEqual(
      expect.arrayContaining(['static', 'correlation'])
    )
    expect(visualization.aspects?.evidence).toEqual(
      expect.arrayContaining(['timeline', 'behavior', 'network', 'provenance'])
    )
    expect(reporting.aspects?.formats).toEqual(
      expect.arrayContaining(['artifact', 'report', 'analysis-evidence'])
    )
    expect(reporting.aspects?.capabilities).toEqual(
      expect.arrayContaining(['report-summary', 'workflow-summary', 'evidence-selection'])
    )

    expectToolMetadata(pcapAnalysis, 'pcap.analyze', {
      formats: ['pcap', 'pcapng'],
      artifacts: ['pcap_analysis'],
      evidence: ['network', 'timeline'],
    })
    expectToolMetadata(pcapAnalysis, 'pcap.dns.list', {
      artifacts: ['pcap_dns_records'],
      evidence: ['network'],
    })
    expectToolMetadata(hostCorrelation, 'host.correlate', {
      formats: ['pe', 'dll'],
      artifacts: ['host_correlation'],
      evidence: ['process', 'filesystem', 'registry', 'imports'],
    })
    expectToolMetadata(memoryForensics, 'memory-forensics.malfind', {
      formats: ['memory-dump', 'vmem'],
      artifacts: ['memory_suspicious_regions'],
      evidence: ['memory', 'process', 'behavior'],
    })
    expectToolMetadata(memoryForensics, 'memory-forensics.netscan', {
      artifacts: ['memory_network_scan'],
      evidence: ['memory', 'network', 'process'],
    })
    expectToolMetadata(visualization, 'analysis.evidence.graph', {
      artifacts: ['analysis_evidence_graph'],
      evidence: ['provenance', 'timeline', 'behavior', 'workflow'],
    })
    expectToolMetadata(visualization, 'crypto.lifecycle.graph', {
      artifacts: ['crypto_lifecycle_graph'],
      evidence: ['behavior', 'memory', 'timeline'],
    })

    const reportingHarness = createPluginTestHarness({
      deps: {
        workspaceManager: {},
        database: {},
        server: {},
      },
    })
    reportingHarness.registerPlugin(reporting)
    const reportGenerate = reportingHarness.registeredTools.find(
      (tool) => tool.definition.name === 'report.generate'
    )
    const workflowSummarize = reportingHarness.registeredTools.find(
      (tool) => tool.definition.name === 'workflow.summarize'
    )
    expect(reportGenerate?.definition.artifacts?.map((artifact) => artifact.type)).toContain(
      'analysis_report'
    )
    expect(workflowSummarize?.definition.evidence?.map((entry) => entry.category)).toContain(
      'artifact'
    )
  })

  test('release guard covers completed capability workflow recipes', async () => {
    const plugins = await discoverBuiltInPlugins()
    const passiveDeps = {
      deps: {
        workspaceManager: {},
        database: {},
        config: { workers: { static: { pythonPath: 'python3' } } },
        cacheManager: {},
        generateCacheKey: () => 'cache-key',
        resolvePackagePath: (...parts: string[]) => parts.join('/'),
      },
    }

    const expectations = [
      {
        pluginId: 'memory-forensics',
        toolName: 'memory-forensics.correlate',
        recipeId: 'memory-forensics.offline-correlation',
        startsWith: ['memory-forensics.correlate'],
        nextTools: ['analysis.evidence.graph', 'report.generate'],
        producesArtifacts: ['memory_forensics_correlation', 'behavior_timeline'],
        evidence: ['memory', 'process', 'network', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'vm-analysis',
        toolName: 'vm.workflow.plan',
        recipeId: 'vm.symbolic.workflow',
        startsWith: ['vm.detect', 'vm.workflow.plan'],
        nextTools: ['constraint.extract', 'smt.solve', 'keygen.synthesize'],
        producesArtifacts: ['vm_workflow_plan', 'smt_solution'],
        evidence: ['structure', 'behavior', 'workflow', 'provenance'],
        safety: ['passive'],
      },
      {
        pluginId: 'kb-collaboration',
        toolName: 'kb.context.suggest',
        recipeId: 'kb.analysis-memory.reuse',
        startsWith: ['kb.context.suggest', 'analysis.notes'],
        nextTools: ['kb.function.match', 'rule.library', 'kb.export'],
        producesArtifacts: ['analysis_memory'],
        evidence: ['analysis-memory', 'workflow', 'provenance'],
        safety: ['passive', 'no_network_by_default'],
      },
      {
        pluginId: 'sbom',
        toolName: 'sbom.provenance.graph',
        recipeId: 'supply-chain.sbom.provenance',
        startsWith: ['container.structure.analyze', 'firmware.workflow.plan'],
        nextTools: ['sbom.generate', 'vuln.pattern.summary', 'report.generate'],
        producesArtifacts: ['sbom_provenance_graph'],
        evidence: ['sbom', 'package-metadata', 'nested-binaries', 'provenance'],
        safety: ['passive', 'no_installer_execution', 'no_auto_mount', 'no_network_by_default'],
      },
      {
        pluginId: 'android',
        toolName: 'android.behavior.graph',
        recipeId: 'android.static.behavior-graph',
        startsWith: ['android.package.inventory', 'android.behavior.graph'],
        nextTools: ['dex.classes.list', 'android.runtime.plan'],
        producesArtifacts: ['android_behavior_graph'],
        evidence: ['manifest', 'classes', 'behavior', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default'],
        harnessOptions: passiveDeps,
      },
      {
        pluginId: 'apple-signing',
        toolName: 'apple.security.profile',
        recipeId: 'apple.security.runtime-profile',
        startsWith: ['apple.container.inventory', 'apple.signing.inspect'],
        nextTools: ['macho.structure.analyze', 'macos.runtime.plan', 'ios.runtime.plan'],
        producesArtifacts: ['apple_security_profile'],
        evidence: ['manifest', 'certificates', 'package-metadata', 'workflow', 'provenance'],
        safety: ['passive', 'no_auto_mount', 'no_installer_execution', 'no_live_sample_by_default'],
      },
      {
        pluginId: 'firmware',
        toolName: 'firmware.workflow.plan',
        recipeId: 'firmware.iot.passive-workflow',
        startsWith: ['firmware.scan', 'firmware.workflow.plan'],
        nextTools: ['firmware.entropy', 'sbom.provenance.graph', 'qiling.inspect'],
        producesArtifacts: ['firmware_workflow_plan'],
        evidence: ['signatures', 'filesystem', 'package-metadata', 'workflow', 'provenance'],
        safety: ['passive', 'no_installer_execution', 'no_auto_mount', 'no_live_sample_by_default'],
      },
      {
        pluginId: 'office-analysis',
        toolName: 'office.behavior.profile',
        recipeId: 'office.macro.static-profile',
        startsWith: ['office.ole.analyze', 'office.behavior.profile'],
        nextTools: ['ioc.export', 'yara.generate', 'sigma.rule.generate', 'report.generate'],
        producesArtifacts: ['office_behavior_profile'],
        evidence: ['structure', 'strings', 'behavior', 'network', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default'],
      },
      {
        pluginId: 'static-triage',
        toolName: 'static.capability.triage',
        recipeId: 'static-triage.capability-correlation',
        startsWith: ['static.capability.triage', 'strings.extract'],
        nextTools: ['static.config.carver', 'crypto.identify', 'packer.detect'],
        producesArtifacts: ['static_capability_triage', 'static_triage_correlation_bundle'],
        evidence: ['behavior', 'crypto', 'workflow', 'correlation-graph'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
        harnessOptions: passiveDeps,
      },
      {
        pluginId: 'static-triage',
        toolName: 'static.config.carver',
        recipeId: 'static-triage.config-evidence-correlation',
        startsWith: ['static.config.carver', 'strings.extract'],
        nextTools: [
          'malware.intel.loop',
          'ioc.export',
          'static.behavior.classify',
          'analysis.evidence.graph',
        ],
        producesArtifacts: ['static_config_carver'],
        evidence: ['network', 'registry', 'strings', 'encoded-config', 'workflow'],
        safety: ['passive', 'opt_in_dynamic', 'no_live_sample_by_default', 'no_network_by_default'],
        harnessOptions: passiveDeps,
      },
      {
        pluginId: 'static-triage',
        toolName: 'static.resource.graph',
        recipeId: 'static-triage.resource-payload-correlation',
        startsWith: ['static.resource.graph'],
        nextTools: [
          'static.config.carver',
          'entropy.analyze',
          'crypto.identify',
          'unpack.workflow.plan',
          'analysis.evidence.graph',
        ],
        producesArtifacts: ['static_resource_graph'],
        evidence: ['resources', 'embedded-payload', 'entropy', 'strings', 'workflow'],
        safety: ['passive', 'opt_in_dynamic', 'no_live_sample_by_default', 'no_network_by_default'],
        harnessOptions: passiveDeps,
      },
      {
        pluginId: 'static-triage',
        toolName: 'compiler.packer.detect',
        recipeId: 'static-triage.compiler-packer-attribution',
        startsWith: ['compiler.packer.detect', 'die.scan', 'packer.detect'],
        nextTools: [
          'packer.detect',
          'entropy.analyze',
          'static.resource.graph',
          'unpack.workflow.plan',
          'analysis.evidence.graph',
        ],
        producesArtifacts: ['compiler_packer_attribution'],
        evidence: ['toolchain', 'signatures', 'packer', 'protector', 'file-type', 'workflow'],
        safety: [
          'passive',
          'external_static_backend',
          'no_live_sample_by_default',
          'no_network_by_default',
        ],
        runtimeBackends: ['detect-it-easy'],
        harnessOptions: passiveDeps,
      },
      {
        pluginId: 'static-triage',
        toolName: 'static.behavior.classify',
        recipeId: 'static-triage.behavior-runtime-validation',
        startsWith: ['static.behavior.classify', 'strings.extract'],
        nextTools: [
          'dynamic.behavior.diff',
          'dynamic.deep_plan',
          'breakpoint.smart',
          'analysis.evidence.graph',
        ],
        producesArtifacts: ['static_behavior_classifier'],
        evidence: ['behavior', 'strings', 'imports', 'registry', 'process', 'workflow'],
        safety: ['passive', 'opt_in_dynamic', 'no_live_sample_by_default', 'no_network_by_default'],
        harnessOptions: passiveDeps,
      },
      {
        pluginId: 'static-triage',
        toolName: 'crypto.identify',
        recipeId: 'static-triage.crypto-runtime-tracing',
        startsWith: ['crypto.identify', 'strings.extract'],
        nextTools: [
          'breakpoint.smart',
          'trace.condition',
          'crypto.lifecycle.graph',
          'analysis.evidence.graph',
        ],
        producesArtifacts: ['crypto_identification'],
        evidence: ['crypto', 'strings', 'imports', 'constants', 'functions', 'workflow'],
        safety: ['passive', 'opt_in_dynamic', 'no_live_sample_by_default', 'no_network_by_default'],
        runtimeBackends: ['frida', 'debugger', 'sandbox'],
        harnessOptions: passiveDeps,
      },
      {
        pluginId: 'yara',
        toolName: 'yara.generate',
        recipeId: 'yara.rule-generation-handoff',
        startsWith: ['yara.generate', 'strings.extract'],
        nextTools: ['yara.scan', 'analysis.evidence.graph', 'report.generate'],
        producesArtifacts: ['yara_rule_generation'],
        evidence: ['signatures', 'strings', 'imports', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'yara',
        toolName: 'yara.generate.batch',
        recipeId: 'yara.family-rule-generation-handoff',
        startsWith: ['yara.generate.batch', 'sample.family.cluster'],
        nextTools: ['yara.scan', 'sample.family.cluster', 'analysis.evidence.graph'],
        producesArtifacts: ['yara_family_rule'],
        evidence: ['signatures', 'strings', 'imports', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'yara-x',
        toolName: 'yara_x.scan',
        recipeId: 'yara-x.scan-validation-handoff',
        startsWith: ['yara_x.scan', 'yara.generate'],
        nextTools: ['artifact.read', 'yara.scan', 'analysis.evidence.graph'],
        producesArtifacts: ['backend_yara_x_scan'],
        evidence: ['signatures', 'strings', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'upx',
        toolName: 'upx.inspect',
        recipeId: 'upx.inspect-validation-handoff',
        startsWith: ['upx.inspect', 'packer.detect', 'die.scan'],
        nextTools: ['artifact.read', 'unpack.workflow.plan', 'analysis.evidence.graph'],
        producesArtifacts: ['backend_upx_list', 'backend_upx_test', 'backend_upx_decompress'],
        evidence: ['packed', 'structure', 'unpacked-binary', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
        runtimeBackends: ['upx'],
      },
      {
        pluginId: 'die',
        toolName: 'die.scan',
        recipeId: 'die.scan-validation-handoff',
        startsWith: ['die.scan', 'compiler.packer.detect', 'packer.detect'],
        nextTools: ['artifact.read', 'compiler.packer.detect', 'analysis.evidence.graph'],
        producesArtifacts: ['backend_die_scan'],
        evidence: ['signatures', 'toolchain', 'packer', 'protector', 'file-type', 'workflow'],
        safety: [
          'passive',
          'external_static_backend',
          'no_live_sample_by_default',
          'no_network_by_default',
        ],
        runtimeBackends: ['detect-it-easy'],
      },
      {
        pluginId: 'unpacking',
        toolName: 'unpack.workflow.plan',
        recipeId: 'unpacking.detect-plan-retriage',
        startsWith: ['die.scan', 'unpack.workflow.plan'],
        nextTools: ['unpack.auto', 'runtime.deobfuscate.plan', 'static.triage'],
        producesArtifacts: ['unpack_plan', 'reanalysis_request'],
        evidence: ['signatures', 'workflow', 'provenance'],
        safety: ['passive', 'opt_in_dynamic', 'requires_isolation', 'no_live_sample_by_default'],
        runtimeBackends: ['debugger', 'sandbox', 'qiling', 'frida'],
      },
      {
        pluginId: 'similarity',
        toolName: 'sample.family.cluster',
        recipeId: 'similarity.family-cluster',
        startsWith: ['sample.similarity', 'binary.diff', 'sample.family.cluster'],
        nextTools: ['binary.diff.summary', 'kb.context.suggest', 'report.generate'],
        producesArtifacts: ['sample_family_cluster'],
        evidence: ['hashes', 'imports', 'strings', 'functions', 'provenance'],
        safety: ['passive', 'no_network_by_default'],
      },
      {
        pluginId: 'strings',
        toolName: 'strings.extract',
        recipeId: 'strings.raw-extraction-evidence',
        startsWith: ['strings.extract', 'analysis.context.link'],
        nextTools: [
          'analysis.context.link',
          'strings.floss.decode',
          'static.config.carver',
          'analysis.evidence.graph',
        ],
        producesArtifacts: ['enriched_string_analysis'],
        evidence: ['strings', 'network', 'encoded-config', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'strings',
        toolName: 'strings.floss.decode',
        recipeId: 'strings.floss-decoded-evidence',
        startsWith: ['strings.floss.decode', 'strings.extract'],
        nextTools: ['analysis.context.link', 'static.config.carver', 'analysis.evidence.graph'],
        producesArtifacts: ['enriched_string_analysis'],
        evidence: ['strings', 'network', 'encoded-config', 'workflow', 'provenance'],
        safety: [
          'passive',
          'external_static_backend',
          'no_live_sample_by_default',
          'no_network_by_default',
        ],
      },
      {
        pluginId: 'api-hash',
        toolName: 'hash.resolver.plan',
        recipeId: 'api-hash.resolver-recovery',
        startsWith: ['hash.resolver.plan', 'strings.extract'],
        nextTools: ['hash.identify', 'hash.resolve', 'analysis.evidence.graph', 'report.generate'],
        producesArtifacts: ['api_hash_resolver_plan'],
        evidence: ['imports', 'strings', 'shellcode', 'workflow', 'provenance'],
        safety: ['passive', 'opt_in_dynamic', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'threat-intel',
        toolName: 'ioc.export',
        recipeId: 'threat-intel.ioc-export-handoff',
        startsWith: ['ioc.export', 'workflow.triage'],
        nextTools: [
          'analysis.evidence.graph',
          'malware.intel.loop',
          'attack.map',
          'sigma.rule.generate',
          'report.generate',
        ],
        producesArtifacts: ['ioc_export_json', 'ioc_export_csv', 'ioc_export_stix2'],
        evidence: ['network', 'filesystem', 'registry', 'signatures', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'threat-intel',
        toolName: 'sigma.rule.generate',
        recipeId: 'threat-intel.sigma-rule-generation-handoff',
        startsWith: ['sigma.rule.generate', 'strings.extract'],
        nextTools: [
          'analysis.evidence.graph',
          'attack.map',
          'ioc.export',
          'yara.generate',
          'report.generate',
        ],
        producesArtifacts: ['sigma_rules'],
        evidence: ['behavior', 'network', 'registry', 'strings', 'imports', 'workflow'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'malware',
        toolName: 'malware.intel.loop',
        recipeId: 'malware.intel.feedback-loop',
        startsWith: ['malware.config.extract', 'c2.extract', 'malware.intel.loop'],
        nextTools: ['ioc.export', 'attack.map', 'sigma.rule.generate', 'yara.generate'],
        producesArtifacts: ['malware_intel_loop'],
        evidence: ['behavior', 'network', 'strings', 'signatures', 'provenance'],
        safety: ['passive', 'no_network_by_default'],
        harnessOptions: passiveDeps,
      },
      {
        pluginId: 'visualization',
        toolName: 'analysis.evidence.graph',
        recipeId: 'visualization.plugin-evidence-reporting',
        startsWith: [
          'analysis.evidence.graph',
          'malware.intel.loop',
          'code.cross_decompiler.consensus',
        ],
        nextTools: ['workflow.summarize', 'report.summarize', 'report.generate'],
        producesArtifacts: ['analysis_evidence_graph'],
        evidence: ['provenance', 'behavior', 'network', 'functions', 'workflow'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'javascript-deobfuscation',
        toolName: 'javascript.obfuscation.profile',
        recipeId: 'javascript.deobfuscation.jsvmp-triage',
        startsWith: ['javascript.obfuscation.profile', 'strings.extract'],
        nextTools: ['strings.extract', 'yara.generate', 'analysis.evidence.graph'],
        producesArtifacts: ['javascript_obfuscation_profile'],
        evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'jsvmp-analysis',
        toolName: 'jsvmp.bytecode.plan',
        recipeId: 'jsvmp.bytecode.recovery-plan',
        startsWith: ['javascript.obfuscation.profile', 'jsvmp.bytecode.plan'],
        nextTools: ['strings.extract', 'yara.generate', 'analysis.evidence.graph'],
        producesArtifacts: ['jsvmp_bytecode_plan', 'jsvmp_handler_map'],
        evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'revng',
        toolName: 'revng.pipeline.plan',
        recipeId: 'revng.lift-decompile.plan',
        startsWith: ['revng.pipeline.plan', 'pe.structure.analyze'],
        nextTools: ['rizin.analyze', 'ghidra.analyze', 'retdec.decompile'],
        producesArtifacts: ['revng_pipeline_plan', 'revng_lift_model'],
        evidence: ['structure', 'symbols', 'artifact', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'triton',
        toolName: 'triton.symbolic.plan',
        recipeId: 'triton.symbolic.recovery-plan',
        startsWith: ['triton.symbolic.plan', 'vm.workflow.plan'],
        nextTools: ['constraint.extract', 'smt.solve', 'vm.workflow.plan'],
        producesArtifacts: ['triton_symbolic_plan', 'path_constraints'],
        evidence: ['structure', 'behavior', 'memory', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
        runtimeBackends: ['unicorn'],
      },
      {
        pluginId: 'miasm',
        toolName: 'miasm.ir.plan',
        recipeId: 'miasm.ir.deobfuscation-plan',
        startsWith: ['miasm.ir.plan', 'obfuscation.detect'],
        nextTools: ['code.function.cfg', 'constraint.extract', 'smt.solve'],
        producesArtifacts: ['miasm_ir_plan', 'miasm_ir_graph'],
        evidence: ['structure', 'behavior', 'artifact', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'lief',
        toolName: 'lief.binary.plan',
        recipeId: 'lief.binary.structure-plan',
        startsWith: ['lief.binary.plan', 'pe.structure.analyze'],
        nextTools: ['pe.signature.verify', 'native.object.inventory', 'sbom.provenance.graph'],
        producesArtifacts: ['lief_binary_plan', 'binary_transformation_plan'],
        evidence: [
          'structure',
          'symbols',
          'imports',
          'exports',
          'certificates',
          'workflow',
          'provenance',
        ],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'radare2',
        toolName: 'radare2.pipeline.plan',
        recipeId: 'radare2.cross-backend.plan',
        startsWith: ['radare2.pipeline.plan', 'rizin.analyze'],
        nextTools: ['rizin.analyze', 'ghidra.analyze', 'retdec.decompile'],
        producesArtifacts: ['radare2_pipeline_plan', 'radare2_function_index'],
        evidence: ['structure', 'symbols', 'strings', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'wabt',
        toolName: 'wabt.toolchain.plan',
        recipeId: 'wabt.wasm.toolchain-plan',
        startsWith: ['wasm.structure.analyze', 'wabt.toolchain.plan'],
        nextTools: ['strings.extract', 'sbom.generate', 'wasm.runtime.plan'],
        producesArtifacts: ['wabt_toolchain_plan', 'wat_disassembly_plan'],
        evidence: ['structure', 'imports', 'exports', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'jsimplifier',
        toolName: 'jsimplifier.pipeline.plan',
        recipeId: 'jsimplifier.javascript.pipeline-plan',
        startsWith: ['javascript.obfuscation.profile', 'jsimplifier.pipeline.plan'],
        nextTools: ['restringer.deobfuscation.plan', 'jsir.cascade.plan'],
        producesArtifacts: ['jsimplifier_pipeline_plan', 'javascript_static_pass_plan'],
        evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'jsir-cascade',
        toolName: 'jsir.cascade.plan',
        recipeId: 'jsir.cascade.normalization-plan',
        startsWith: ['javascript.obfuscation.profile', 'jsir.cascade.plan'],
        nextTools: ['jsvmp.bytecode.plan', 'strings.extract'],
        producesArtifacts: ['jsir_cascade_plan', 'javascript_ir_plan'],
        evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'restringer',
        toolName: 'restringer.deobfuscation.plan',
        recipeId: 'restringer.javascript.preprocess-plan',
        startsWith: ['javascript.obfuscation.profile', 'restringer.deobfuscation.plan'],
        nextTools: ['jsir.cascade.plan', 'jsvmp.bytecode.plan'],
        producesArtifacts: ['restringer_deobfuscation_plan', 'javascript_string_array_plan'],
        evidence: ['structure', 'strings', 'behavior', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'remill',
        toolName: 'remill.lift.plan',
        recipeId: 'remill.llvm.lift-plan',
        startsWith: ['remill.lift.plan', 'code.function.disassemble'],
        nextTools: ['revng.pipeline.plan', 'gtirb.ir.plan'],
        producesArtifacts: ['remill_lift_plan', 'llvm_bitcode_lift_plan'],
        evidence: ['structure', 'symbols', 'behavior', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'gtirb',
        toolName: 'gtirb.ir.plan',
        recipeId: 'gtirb.binary.ir-plan',
        startsWith: ['gtirb.ir.plan', 'pe.structure.analyze'],
        nextTools: ['remill.lift.plan', 'revng.pipeline.plan'],
        producesArtifacts: ['gtirb_ir_plan', 'gtirb_cfg_plan'],
        evidence: ['structure', 'symbols', 'artifact', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'qbdi',
        toolName: 'qbdi.instrumentation.plan',
        recipeId: 'qbdi.dbi.opt-in-plan',
        startsWith: ['qbdi.instrumentation.plan', 'dynamic.runtime.status'],
        nextTools: ['windows.runtime.plan', 'linux.runtime.plan', 'dynamic.runtime.status'],
        producesArtifacts: ['qbdi_instrumentation_plan', 'dbi_trace_plan'],
        evidence: ['structure', 'behavior', 'memory', 'timeline', 'workflow', 'provenance'],
        safety: ['passive', 'opt_in_dynamic', 'requires_isolation', 'no_live_sample_by_default'],
        runtimeBackends: ['qbdi'],
      },
      {
        pluginId: 'manifold',
        toolName: 'manifold.decompilation.plan',
        recipeId: 'manifold.superset.decompilation-plan',
        startsWith: ['manifold.decompilation.plan', 'code.function.cfg'],
        nextTools: ['revng.pipeline.plan', 'gtirb.ir.plan', 'miasm.ir.plan'],
        producesArtifacts: ['manifold_decompilation_plan', 'declarative_fact_plan'],
        evidence: ['structure', 'symbols', 'behavior', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
      {
        pluginId: 'culifter',
        toolName: 'culifter.gpu.plan',
        recipeId: 'culifter.gpu.lift-plan',
        startsWith: ['culifter.gpu.plan', 'linux.binary.inventory'],
        nextTools: ['linux.binary.inventory', 'native.object.inventory'],
        producesArtifacts: ['culifter_gpu_plan', 'sass_lift_plan'],
        evidence: ['structure', 'symbols', 'imports', 'exports', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
      },
    ]

    for (const expected of expectations) {
      expectWorkflowRecipeMetadata(plugins, expected)
    }
  })

  test('discovers platform runtime plan plugins as passive dynamic planning tools', async () => {
    const plugins = await discoverBuiltInPlugins()
    const windowsRuntime = requirePlugin(plugins, 'windows-runtime')
    const linuxRuntime = requirePlugin(plugins, 'linux-runtime')
    const macosRuntime = requirePlugin(plugins, 'macos-runtime')
    const iosRuntime = requirePlugin(plugins, 'ios-runtime')
    const androidRuntime = requirePlugin(plugins, 'android-runtime')
    const wasmRuntime = requirePlugin(plugins, 'wasm-runtime')

    expect(windowsRuntime.aspects?.formats).toEqual(expect.arrayContaining(['pe', 'dotnet', 'msi']))
    expect(windowsRuntime.aspects?.runtimes).toEqual(
      expect.arrayContaining(['windows-sandbox', 'hyperv', 'wine', 'speakeasy'])
    )
    expect(linuxRuntime.aspects?.formats).toEqual(
      expect.arrayContaining(['elf', 'elf-core', 'deb'])
    )
    expect(linuxRuntime.aspects?.runtimes).toEqual(
      expect.arrayContaining(['qiling', 'gdb', 'strace', 'ebpf'])
    )
    expect(macosRuntime.aspects?.formats).toEqual(expect.arrayContaining(['macho', 'dmg', 'pkg']))
    expect(macosRuntime.aspects?.runtimes).toEqual(
      expect.arrayContaining(['lldb', 'dtrace', 'fs-usage', 'sandbox-exec'])
    )
    expect(iosRuntime.aspects?.formats).toEqual(
      expect.arrayContaining(['ipa', 'mobileprovision', 'entitlements'])
    )
    expect(iosRuntime.aspects?.runtimes).toEqual(
      expect.arrayContaining(['frida', 'idevice-tools', 'lldb'])
    )
    expect(androidRuntime.aspects?.formats).toEqual(
      expect.arrayContaining(['apk', 'aab', 'apks', 'dex'])
    )
    expect(androidRuntime.aspects?.runtimes).toEqual(
      expect.arrayContaining(['adb', 'android-emulator', 'frida', 'frida-server'])
    )
    expect(wasmRuntime.aspects?.formats).toEqual(expect.arrayContaining(['wasm', 'wasi']))
    expect(wasmRuntime.aspects?.runtimes).toEqual(expect.arrayContaining(['wasmtime']))

    for (const plugin of [
      windowsRuntime,
      linuxRuntime,
      macosRuntime,
      iosRuntime,
      androidRuntime,
      wasmRuntime,
    ]) {
      expect(plugin.executionDomain).toBe('dynamic')
      expect(plugin.runtimePolicy).toEqual(
        expect.objectContaining({
          passiveByDefault: true,
          requiresUserOptIn: true,
          requiresIsolation: true,
          networkPolicy: 'disabled',
        })
      )
      const tool = plugin.tools?.[0]?.definition
      expect(tool?.name).toMatch(/\.runtime\.plan$/)
      expect(tool?.runtime).toBeUndefined()
      expect(tool?.runtimePolicy).toEqual(
        expect.objectContaining({
          passiveByDefault: true,
          requiresUserOptIn: true,
        })
      )
      const recipe = requireWorkflowRecipe(
        tool as ToolDefinition,
        `${plugin.id.replace('-runtime', '')}.runtime.opt-in`
      )
      expect(recipe.startsWith).toEqual(expect.arrayContaining([tool?.name, 'tool.readiness']))
      expect(recipe.safety).toEqual(
        expect.arrayContaining([
          'passive',
          'opt_in_dynamic',
          'requires_isolation',
          'no_live_sample_by_default',
          'no_network_by_default',
        ])
      )
      expect(recipe.runtimeBackends).toEqual(expect.arrayContaining(plugin.aspects?.runtimes ?? []))
      expect(tool?.artifacts?.[0]?.type).toMatch(/_runtime_plan$/)
      expect(tool?.evidence?.map((entry) => entry.category)).toContain('timeline')
    }

    const harness = createPluginTestHarness()
    harness.registerPlugin(androidRuntime)
    const androidPlan = harness.registeredTools.find(
      (tool) => tool.definition.name === 'android.runtime.plan'
    )
    expect(androidPlan).toBeDefined()

    const result = await androidPlan!.handler({
      sample_id: 'sha256:test',
      requested_backends: ['frida'],
      static_evidence: ['android.permission.INTERNET', 'classes.dex'],
    })

    expect((result as any).ok).toBe(true)
    expect((result as any).data).toEqual(
      expect.objectContaining({
        platform: 'android',
        execution_semantics: expect.objectContaining({
          actual_mode: 'plan_only',
          live_execution: false,
        }),
        readiness: expect.objectContaining({
          status: 'plan_only',
          opt_in_required: true,
          requires_isolation: true,
          policy_denied: true,
        }),
        selected_backends: [
          expect.objectContaining({
            backend: 'frida',
            execution_tools: expect.arrayContaining(['frida.script.inject']),
          }),
        ],
      })
    )
    expect((result as any).data.safety_notes).toEqual(
      expect.arrayContaining([expect.stringContaining('No sample was installed')])
    )
  })
})
