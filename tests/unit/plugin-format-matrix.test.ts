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
import { buildWasmComponentInventoryFromBuffer } from '../../src/plugins/wasm-component/tools/wasm-component-inventory.js'
import { buildAppleObjcSwiftMetadataFromBuffer } from '../../src/plugins/apple-objc-swift/tools/apple-objc-swift-metadata-inspect.js'
import { buildBytecodeMetadataFromBuffer } from '../../src/plugins/bytecode/tools/bytecode-metadata-inspect.js'
import { buildBtfInventoryFromBuffer } from '../../src/plugins/btf/tools/btf-type-inventory.js'
import { buildBinaryHardeningInventoryFromBuffer } from '../../src/plugins/binary-hardening/tools/binary-hardening-inventory.js'
import { buildCompilerCodegenFingerprintFromBuffer } from '../../src/plugins/compiler-codegen/tools/compiler-codegen-fingerprint.js'
import { buildCppAbiLayoutInventoryFromBuffer } from '../../src/plugins/cpp-abi-layout/tools/cpp-abi-layout-inventory.js'
import { buildKernelDriverSurfaceInventoryFromBuffer } from '../../src/plugins/kernel-driver-surface/tools/kernel-driver-surface-inventory.js'
import { buildLlvmBitcodeInventoryFromBuffer } from '../../src/plugins/llvm-bitcode/tools/llvm-bitcode-inventory.js'
import { buildMlModelInventoryFromBuffer } from '../../src/plugins/ml-model/tools/ml-model-inventory.js'
import { buildNativeDebugTypesInventoryFromBuffer } from '../../src/plugins/native-debug-types/tools/native-debug-types-inventory.js'
import { buildRustBinaryInventoryFromBuffer } from '../../src/plugins/rust-binary/tools/rust-binary-inventory.js'
import { buildShaderIrInventoryFromBuffer } from '../../src/plugins/shader-ir/tools/shader-ir-inventory.js'
import { buildSyscallAbiSurfaceInventoryFromBuffer } from '../../src/plugins/syscall-abi-surface/tools/syscall-abi-surface-inventory.js'
import { buildTeeEnclaveInventoryFromBuffer } from '../../src/plugins/tee-enclave/tools/tee-enclave-inventory.js'
import { buildUefiSmmSurfaceInventoryFromBuffer } from '../../src/plugins/uefi-smm-surface/tools/uefi-smm-surface-inventory.js'
import { buildWindowsInterfaceSurfaceInventoryFromBuffer } from '../../src/plugins/windows-interface-surface/tools/windows-interface-surface-inventory.js'
import { buildWindowsInstallerInventoryFromBuffer } from '../../src/plugins/windows-installer/tools/windows-installer-inventory.js'
import { buildWindowsDebugMetadataFromBuffer } from '../../src/plugins/windows-debug-symbols/tools/windows-debug-metadata-inspect.js'
import { buildDotnetAssemblyInventoryFromBuffer } from '../../src/plugins/dotnet-managed/tools/dotnet-assembly-inspect.js'
import { buildUnityMetadataInventoryFromBuffer } from '../../src/plugins/unity-managed/tools/unity-metadata-inspect.js'
import { buildContainerStructureFromBuffer } from '../../src/plugins/container-analysis/tools/container-structure-analyze.js'
import { buildContainerImageSecurityProfileFromBuffer } from '../../src/plugins/container-analysis/tools/container-image-security-profile.js'
import { buildNativeObjectInventoryFromBuffer } from '../../src/plugins/native-object/tools/native-object-inventory.js'
import { buildAndroidPackageInventoryFromBuffer } from '../../src/plugins/android-package/tools/android-package-inventory.js'
import { buildAppleSigningInspectFromBuffer } from '../../src/plugins/apple-signing/tools/apple-signing-inspect.js'
import { buildLinuxBinaryInventoryFromBuffer } from '../../src/plugins/linux-binary/tools/linux-binary-inventory.js'
import { buildCudaBinaryInventoryFromBuffer } from '../../src/plugins/cuda-binary/tools/cuda-binary-inventory.js'
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

function tarDataEntry(name: string, data = Buffer.alloc(0), mode = 0o644, typeflag = '0'): Buffer {
  const header = Buffer.alloc(512)
  header.write(name, 0, Math.min(Buffer.byteLength(name), 100), 'utf8')
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
  return Buffer.concat([header, data, Buffer.alloc((512 - (data.length % 512)) % 512)])
}

function tarDataFixture(
  entries: Array<{ name: string; data?: Buffer; mode?: number; typeflag?: string }>
): Buffer {
  return Buffer.concat([
    ...entries.map((entry) =>
      tarDataEntry(
        entry.name,
        entry.data ?? Buffer.alloc(0),
        entry.mode ?? 0o644,
        entry.typeflag ?? '0'
      )
    ),
    Buffer.alloc(1024),
  ])
}

function jsonFixture(value: unknown): Buffer {
  return Buffer.from(JSON.stringify(value), 'utf8')
}

function isoFixture(): Buffer {
  const data = Buffer.alloc(0x8006)
  data.write('CD001', 0x8001, 'ascii')
  return data
}

function llvmBitcodeFixture(): Buffer {
  return Buffer.concat([
    Buffer.from([0x42, 0x43, 0xc0, 0xde, 0x03, 0x41, 0x10, 0x00]),
    Buffer.from('target triple=x86_64-unknown-linux-gnu', 'ascii'),
  ])
}

function shaderSpirvStringWords(value: string): number[] {
  const bytes = Buffer.from(`${value}\0`, 'utf8')
  const padded = Buffer.concat([bytes, Buffer.alloc((4 - (bytes.length % 4)) % 4)])
  const words: number[] = []
  for (let offset = 0; offset < padded.length; offset += 4) {
    words.push(padded.readUInt32LE(offset))
  }
  return words
}

function shaderSpirvInstruction(opcode: number, operands: number[]): number[] {
  return [((operands.length + 1) << 16) | opcode, ...operands]
}

function shaderSpirvFixture(): Buffer {
  const words = [
    0x07230203,
    0x00010300,
    0,
    16,
    0,
    ...shaderSpirvInstruction(17, [1]),
    ...shaderSpirvInstruction(14, [0, 1]),
    ...shaderSpirvInstruction(15, [5, 7, ...shaderSpirvStringWords('main')]),
  ]
  const data = Buffer.alloc(words.length * 4)
  words.forEach((word, index) => data.writeUInt32LE(word >>> 0, index * 4))
  return data
}

function wasmComponentU32Leb(value: number): number[] {
  const bytes: number[] = []
  let remaining = value >>> 0
  do {
    let byte = remaining & 0x7f
    remaining >>>= 7
    if (remaining !== 0) byte |= 0x80
    bytes.push(byte)
  } while (remaining !== 0)
  return bytes
}

function wasmComponentName(value: string): number[] {
  const bytes = [...Buffer.from(value, 'utf8')]
  return [...wasmComponentU32Leb(bytes.length), ...bytes]
}

function wasmComponentExternName(value: string): number[] {
  return [0x00, ...wasmComponentName(value)]
}

function wasmComponentSection(id: number, payload: number[]): number[] {
  return [id, ...wasmComponentU32Leb(payload.length), ...payload]
}

function wasmComponentFixture(): Buffer {
  return Buffer.from([
    0x00,
    0x61,
    0x73,
    0x6d,
    0x0d,
    0x00,
    0x01,
    0x00,
    ...wasmComponentSection(0, wasmComponentName('component-name')),
    ...wasmComponentSection(1, [0x00]),
    ...wasmComponentSection(8, [0x01, 0x00]),
    ...wasmComponentSection(10, [
      0x01,
      ...wasmComponentExternName('wasi:http/outgoing-handler@0.2.0'),
      0x01,
      0x00,
    ]),
    ...wasmComponentSection(11, [
      0x01,
      ...wasmComponentExternName('example:component/run@1.0.0'),
      0x01,
      0x00,
    ]),
  ])
}

function btfFixture(): Buffer {
  const strings = Buffer.from('\0int\0task_struct\0pid\0', 'utf8')
  const intType = Buffer.alloc(16)
  intType.writeUInt32LE(1, 0)
  intType.writeUInt32LE(1 << 24, 4)
  intType.writeUInt32LE(4, 8)
  intType.writeUInt32LE(32, 12)
  const structType = Buffer.alloc(24)
  structType.writeUInt32LE(5, 0)
  structType.writeUInt32LE((4 << 24) | 1, 4)
  structType.writeUInt32LE(4, 8)
  structType.writeUInt32LE(17, 12)
  structType.writeUInt32LE(1, 16)
  structType.writeUInt32LE(0, 20)
  const types = Buffer.concat([intType, structType])
  const header = Buffer.alloc(24)
  header.writeUInt16LE(0xeb9f, 0)
  header[2] = 1
  header.writeUInt32LE(24, 4)
  header.writeUInt32LE(0, 8)
  header.writeUInt32LE(types.length, 12)
  header.writeUInt32LE(types.length, 16)
  header.writeUInt32LE(strings.length, 20)
  return Buffer.concat([header, types, strings])
}

function ctfDictionaryFixture(): Buffer {
  const data = Buffer.alloc(48)
  data.writeUInt16LE(0xdff2, 0)
  data[2] = 4
  data.writeUInt32LE(8, 16)
  data.writeUInt32LE(12, 20)
  data.writeUInt32LE(16, 24)
  data.writeUInt32LE(24, 36)
  data.writeUInt32LE(32, 40)
  data.writeUInt32LE(8, 44)
  return data
}

function mlSafeTensorsFixture(): Buffer {
  const header = Buffer.from(
    JSON.stringify({
      weight: { dtype: 'F32', shape: [2, 2], data_offsets: [0, 16] },
      __metadata__: { source: 'https://example.invalid/model' },
    }),
    'utf8'
  )
  const length = Buffer.alloc(8)
  length.writeBigUInt64LE(BigInt(header.length), 0)
  return Buffer.concat([length, header, Buffer.alloc(16)])
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

function fixedMachOName(data: Buffer, offset: number, value: string): void {
  data.fill(0, offset, offset + 16)
  data.write(value, offset, Math.min(Buffer.byteLength(value), 16), 'ascii')
}

function appleMetadataSection(
  data: Buffer,
  offset: number,
  section: string,
  segment: string,
  fileOffset: number,
  size: number
): void {
  fixedMachOName(data, offset, section)
  fixedMachOName(data, offset + 16, segment)
  data.writeBigUInt64LE(BigInt(fileOffset), offset + 32)
  data.writeBigUInt64LE(BigInt(size), offset + 40)
  data.writeUInt32LE(fileOffset, offset + 48)
}

function appleMetadataCStringBlob(data: Buffer, offset: number, values: string[]): number {
  const blob = Buffer.from(`${values.join('\0')}\0`, 'utf8')
  blob.copy(data, offset)
  return blob.length
}

function appleObjcSwiftMetadataFixture(): Buffer {
  const data = Buffer.alloc(0x500)
  const sectionCount = 4
  const commandSize = 72 + sectionCount * 80
  const sectionTableOffset = 32 + 72
  data.writeUInt32LE(0xfeedfacf, 0)
  data.writeInt32LE(0x0100000c, 4)
  data.writeInt32LE(0, 8)
  data.writeUInt32LE(6, 12)
  data.writeUInt32LE(1, 16)
  data.writeUInt32LE(commandSize, 20)
  data.writeUInt32LE(0x19, 32)
  data.writeUInt32LE(commandSize, 36)
  fixedMachOName(data, 40, '__TEXT')
  data.writeUInt32LE(sectionCount, 96)
  const methSize = appleMetadataCStringBlob(data, 0x280, ['viewDidLoad', 'performSelector:'])
  const classSize = appleMetadataCStringBlob(data, 0x2c0, ['DemoController'])
  const swiftSize = appleMetadataCStringBlob(data, 0x300, ['$s4Demo5ModelV', 'Swift.Task'])
  appleMetadataSection(data, sectionTableOffset, '__objc_classlist', '__DATA_CONST', 0x260, 8)
  appleMetadataSection(data, sectionTableOffset + 80, '__objc_methname', '__TEXT', 0x280, methSize)
  appleMetadataSection(
    data,
    sectionTableOffset + 160,
    '__objc_classname',
    '__TEXT',
    0x2c0,
    classSize
  )
  appleMetadataSection(
    data,
    sectionTableOffset + 240,
    '__swift5_reflstr',
    '__TEXT',
    0x300,
    swiftSize
  )
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
    expect(detectFileType(Buffer.from('target arm64-apple-ios'), 'Demo.swiftmodule')).toBe(
      'SwiftModule'
    )
    expect(detectFileType(Buffer.from('public interface Demo'), 'Demo.swiftinterface')).toBe(
      'SwiftInterface'
    )
    expect(detectFileType(Buffer.from('Swift doc'), 'Demo.swiftdoc')).toBe('SwiftDoc')
    expect(detectFileType(Buffer.from('{}'), 'Demo.abi.json')).toBe('Swift-ABI')
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
    expect(detectFileType(wasmComponentFixture(), 'component.wasm')).toBe('WASM-Component')
    expect(detectFileType(Buffer.from([0x00, 0x61, 0x73, 0x6d]), 'module.wasm')).toBe('WASM')
    expect(detectFileType(Buffer.alloc(16), 'demo.component.wasm')).toBe('WASM-Component')
    expect(detectFileType(Buffer.alloc(16), 'program.bpf')).toBe('eBPF-Bytecode')
    expect(detectFileType(Buffer.alloc(16), 'program.ebpf')).toBe('eBPF-Bytecode')
    expect(detectFileType(Buffer.alloc(16), 'sample.ta')).toBe('OP-TEE-TA')
    expect(detectFileType(Buffer.alloc(16), 'sample.sigstruct')).toBe('SGX-SIGSTRUCT')
    expect(detectFileType(Buffer.alloc(16), 'sample.enclave')).toBe('SGX-Enclave')
    expect(detectFileType(Buffer.alloc(16), 'ntdll.stub')).toBe('Syscall-Stub')
    expect(detectFileType(Buffer.alloc(16), 'direct.syscall')).toBe('Syscall-Stub')
    expect(detectFileType(Buffer.alloc(16), 'payload.shellcode')).toBe('Raw-Shellcode')
    expect(detectFileType(Buffer.from('VZ\0\0'), 'SmmDriver.te')).toBe('UEFI-TE')
    expect(detectFileType(Buffer.alloc(16), 'firmware.cap')).toBe('UEFI-Capsule')
    expect(detectFileType(Buffer.concat([Buffer.alloc(64), Buffer.from('_FVH')]), 'bios.fd')).toBe(
      'UEFI-Firmware-Volume'
    )
    expect(detectFileType(Buffer.from([0x42, 0x43, 0xc0, 0xde]), 'module.bc')).toBe('LLVM-Bitcode')
    const wrapper = Buffer.alloc(20)
    wrapper.writeUInt32LE(0x0b17c0de, 0)
    expect(detectFileType(wrapper, 'module.bc')).toBe('LLVM-Bitcode-Wrapper')
    expect(detectFileType(Buffer.from('rustc metadata'), 'libdemo.rlib')).toBe('Rust-RLIB')
    expect(detectFileType(Buffer.from('rust metadata'), 'libdemo.rmeta')).toBe('Rust-RMETA')
    expect(detectFileType(shaderSpirvFixture(), 'shader.spv')).toBe('SPIR-V')
    expect(detectFileType(Buffer.from('DXBC'), 'shader.dxil')).toBe('DXContainer')
    expect(detectFileType(Buffer.from('fn main() {}'), 'shader.wgsl')).toBe('WGSL')
    expect(detectFileType(Buffer.from('MTLB'), 'default.metallib')).toBe('Metal-Metallib')
    expect(detectFileType(btfFixture(), 'vmlinux.btf')).toBe('BTF')
    expect(detectFileType(Buffer.alloc(16), 'main.dwo')).toBe('DWO')
    expect(detectFileType(Buffer.alloc(16), 'package.dwp')).toBe('DWP')
    expect(detectFileType(Buffer.alloc(16), 'main.debug')).toBe('DWARF-Debug')
    expect(detectFileType(ctfDictionaryFixture(), 'types.bin')).toBe('CTF')
    expect(detectFileType(Buffer.alloc(16), 'types.ctf')).toBe('CTF')
  })

  test('detects CUDA PTX, CUBIN, and fatbin formats without masking host binaries', () => {
    const ptx = Buffer.from(
      '.version 8.1\n.target sm_90\n.address_size 64\n.visible .entry _Z6kernelv() {}\n',
      'utf8'
    )
    const cubin = elfFixture(1, 190)
    const host = Buffer.concat([Buffer.from('MZ'), Buffer.from('__cudaRegisterFatBinary')])

    expect(detectFileType(ptx, 'kernel.ptx')).toBe('CUDA-PTX')
    expect(detectFileType(ptx, 'kernel.txt')).toBe('CUDA-PTX')
    expect(detectFileType(cubin, 'kernel.cubin')).toBe('CUDA-CUBIN')
    expect(detectFileType(Buffer.from('__cudaFatCubin'), 'bundle.fatbin')).toBe('CUDA-Fatbin')
    expect(detectFileType(host, 'host.exe')).toBe('PE')
  })

  test('detects ML model artifact formats for static routing', () => {
    const tflite = Buffer.alloc(8)
    tflite.write('TFL3', 4, 'ascii')
    const npy = Buffer.concat([
      Buffer.from([0x93]),
      Buffer.from('NUMPY', 'ascii'),
      Buffer.from([0x01, 0x00, 0x00, 0x00]),
    ])

    expect(detectFileType(mlSafeTensorsFixture(), 'model.safetensors')).toBe('SafeTensors')
    expect(detectFileType(Buffer.from('GGUF\x03\x00\x00\x00'), 'model.gguf')).toBe('GGUF')
    expect(detectFileType(Buffer.from('ggml'), 'model.ggml')).toBe('GGML')
    expect(detectFileType(tflite, 'model.tflite')).toBe('TFLite-Model')
    expect(detectFileType(Buffer.alloc(16), 'model.onnx')).toBe('ONNX-Model')
    expect(detectFileType(npy, 'array.npy')).toBe('NumPy-NPY')
    expect(detectFileType(localZip(['array.npy']), 'arrays.npz')).toBe('NumPy-NPZ')
    expect(detectFileType(localZip(['archive/data.pkl', 'archive/version']), 'model.pt')).toBe(
      'PyTorch-Checkpoint'
    )
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
    expect(detectFileType(Buffer.from('TYPELIB\0LIBID'), 'demo.tlb')).toBe('TypeLib')
    expect(detectFileType(Buffer.from('interface IDemo : IUnknown {};'), 'demo.idl')).toBe('IDL')
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

  test('builds Apple ObjC/Swift metadata inventory without demangle/runtime tooling', () => {
    const inventory = buildAppleObjcSwiftMetadataFromBuffer(appleObjcSwiftMetadataFixture(), {
      filename: 'Demo.framework/Demo',
    })

    expect(inventory.format).toBe('macho')
    expect(inventory.objc.present).toBe(true)
    expect(inventory.objc.pointer_reference_counts.classlist).toBe(1)
    expect(inventory.objc.class_name_hints).toContain('DemoController')
    expect(inventory.objc.selector_hints).toContain('performSelector:')
    expect(inventory.swift.present).toBe(true)
    expect(inventory.swift.section_hints).toContain('__TEXT.__swift5_reflstr')
    expect(inventory.swift.module_hints).toContain('Demo')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_debug_attach: true,
        no_app_launch: true,
        no_external_tool: true,
        no_runtime_start: true,
      })
    )
    expect(inventory.demangle_plan).toEqual(
      expect.objectContaining({
        status: 'plan_only',
        external_tool_invoked_by_tool: false,
      })
    )
    expect(inventory.workflow_handoff.dynamic_boundary).toEqual(
      expect.objectContaining({
        app_launch_allowed: false,
        debugger_attach_allowed: false,
        external_tool_allowed: false,
        runtime_started_by_tool: false,
      })
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

  test('builds Wasm Component Model inventory without external tools or instantiation', () => {
    const inventory = buildWasmComponentInventoryFromBuffer(wasmComponentFixture(), {
      filename: 'component.wasm',
    })

    expect(inventory.format).toBe('wasm-component')
    expect(inventory.component_preamble).toEqual(
      expect.objectContaining({ version_field: 13, layer_field: 1, is_component: true })
    )
    expect(inventory.custom_sections).toContain('component-name')
    expect(inventory.embedded_core_module_count).toBe(1)
    expect(inventory.canonical_abi_definition_count).toBe(1)
    expect(inventory.imports.map((item) => item.name)).toContain('wasi:http/outgoing-handler@0.2.0')
    expect(inventory.exports.map((item) => item.name)).toContain('example:component/run@1.0.0')
    expect(inventory.wasi_capability_hints).toEqual(expect.arrayContaining(['http', 'wasi']))
    expect(inventory.capability_risk_summary.risk_level).toBe('high')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_runtime_start: true,
        no_instantiation: true,
        no_wasi_grants: true,
        no_external_tool: true,
      })
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

  test('builds CUDA binary inventory without starting CUDA tools or GPU drivers', () => {
    const inventory = buildCudaBinaryInventoryFromBuffer(
      Buffer.from(
        '.version 8.1\n.target sm_90\n.address_size 64\n.visible .entry _Z6kernelv() {}\n',
        'utf8'
      ),
      { filename: 'kernel.ptx' }
    )

    expect(inventory.format).toBe('ptx')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_cuda_driver: true,
        no_gpu_access: true,
        no_external_tool: true,
      })
    )
    expect(inventory.target_arches).toEqual(
      expect.arrayContaining([expect.objectContaining({ value: 'sm_90' })])
    )
    expect(inventory.kernels).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: '_Z6kernelv' })])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['culifter.gpu.plan', 'culifter.gpu.artifact.inventory'])
    )
  })

  test('builds LLVM bitcode inventory without invoking LLVM tools', () => {
    const inventory = buildLlvmBitcodeInventoryFromBuffer(llvmBitcodeFixture(), {
      filename: 'module.bc',
    })

    expect(inventory.format).toBe('llvm-bitcode')
    expect(inventory.policy.no_llvm_toolchain_required).toBe(true)
    expect(inventory.quality_gates.llvm_tool_invoked_by_tool).toBe(false)
    expect(inventory.quality_gates.compiled_by_tool).toBe(false)
    expect(inventory.recommended_next_tools).toEqual(expect.arrayContaining(['workflow.search']))
  })

  test('builds BTF inventory without invoking libbpf, bpftool, or kernel verifier', () => {
    const inventory = buildBtfInventoryFromBuffer(btfFixture(), {
      filename: 'vmlinux.btf',
    })

    expect(inventory.format).toBe('btf')
    expect(inventory.btf).toEqual(
      expect.objectContaining({
        decode_status: 'parsed',
        type_count: 2,
        kind_counts: expect.objectContaining({ INT: 1, STRUCT: 1 }),
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_libbpf: true,
        no_bpftool: true,
        no_kernel_verifier_run: true,
        no_program_load: true,
      })
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['ebpf.bytecode.inventory', 'analysis.evidence.graph'])
    )
  })

  test('builds native debug type inventory without invoking dumpers or symbol servers', () => {
    const inventory = buildNativeDebugTypesInventoryFromBuffer(ctfDictionaryFixture(), {
      filename: 'types.ctf',
    })

    expect(inventory.format).toBe('ctf')
    expect(inventory.ctf).toEqual(
      expect.objectContaining({
        present: true,
        format: 'ctf-dictionary',
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_external_tool: true,
        no_symbol_server_download: true,
        no_source_fetch: true,
      })
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['native.object.inventory', 'workflow.search'])
    )
  })

  test('builds ML model inventory without deserializing or loading frameworks', () => {
    const inventory = buildMlModelInventoryFromBuffer(mlSafeTensorsFixture(), {
      filename: 'model.safetensors',
    })

    expect(inventory.format).toBe('safetensors')
    expect(inventory.inventory).toEqual(
      expect.objectContaining({
        tensor_count: 1,
        dtype_counts: expect.objectContaining({ F32: 1 }),
      })
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_deserialize: true,
        no_model_load: true,
        no_inference: true,
        no_ml_framework_load: true,
      })
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['strings.extract', 'analysis.evidence.graph', 'workflow.search'])
    )
  })

  test('builds shader IR inventory without compiler, validator, disassembler, or GPU access', () => {
    const inventory = buildShaderIrInventoryFromBuffer(shaderSpirvFixture(), {
      filename: 'shader.spv',
    })

    expect(inventory.format).toBe('spir-v')
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_gpu_driver: true,
        no_gpu_access: true,
        no_shader_compiler: true,
        no_validator: true,
        no_disassembler: true,
      })
    )
    expect(inventory.entry_points).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'main', stage: 'GLCompute' })])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['culifter.gpu.plan', 'analysis.evidence.graph'])
    )
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
      'demo.component.wasm',
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
          path: 'demo.component.wasm',
          recommended_tools: expect.arrayContaining(['wasm.component.inventory']),
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
    expect(docker.recommended_next_tools).toContain('container.image.security.profile')
    expect(oci.container_format).toBe('oci-image')
    expect(oci.policy.no_mount).toBe(true)
    expect(oci.recommended_next_tools).toContain('container.image.security.profile')
  })

  test('builds Docker image security profile without registry, daemon, mount, or entrypoint execution', () => {
    const layer = tarDataFixture([{ name: 'usr/bin/helper', mode: 0o4755 }])
    const image = tarDataFixture([
      {
        name: 'manifest.json',
        data: jsonFixture([
          { Config: 'config.json', RepoTags: ['demo:latest'], Layers: ['layer.tar'] },
        ]),
      },
      {
        name: 'config.json',
        data: jsonFixture({
          architecture: 'amd64',
          os: 'linux',
          config: {
            Env: ['PATH=/usr/bin'],
            Entrypoint: ['/bin/sh', '-c', 'run'],
            ExposedPorts: { '80/tcp': {} },
          },
          rootfs: { type: 'layers', diff_ids: ['sha256:diff'] },
        }),
      },
      { name: 'layer.tar', data: layer },
    ])

    const profile = buildContainerImageSecurityProfileFromBuffer(image, { filename: 'image.tar' })

    expect(profile.image_format).toBe('docker-image')
    expect(profile.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_registry_network: true,
        no_docker_daemon: true,
        no_layer_extract: true,
        no_mount: true,
        no_entrypoint_run: true,
      })
    )
    expect(profile.risk_flags).toEqual(
      expect.arrayContaining(['root-user-default', 'shell-entrypoint', 'suid-files'])
    )
    expect(profile.recommended_next_tools).toEqual(
      expect.arrayContaining(['container.structure.analyze', 'sbom.provenance.graph'])
    )
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

describe('passive C++ ABI layout inventory', () => {
  test('extracts cross-platform ABI class layout seeds without demanglers or loaders', () => {
    const inventory = buildCppAbiLayoutInventoryFromBuffer(
      Buffer.from(
        [
          '_ZTVN4demo6WidgetE',
          '_ZTIN4demo6WidgetE',
          '??_7Widget@@6B@',
          '??_R0?AVWidget@@@8',
          '__gxx_personality_v0',
          '__CxxFrameHandler3',
        ].join('\0'),
        'utf8'
      ),
      { filename: 'mixed.o' }
    )

    expect(inventory.format).toBe('mixed-cpp-abi')
    expect(inventory.class_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ abi: 'itanium', class_name: 'demo::Widget' }),
        expect.objectContaining({ abi: 'msvc', class_name: 'Widget' }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['native.debug.types.inventory', 'code.xrefs.analyze'])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_external_demangler: true,
        no_native_load: true,
        no_link: true,
      })
    )
  })
})

describe('passive compiler codegen fingerprint inventory', () => {
  test('extracts toolchain provenance hints without invoking compilers or loaders', () => {
    const inventory = buildCompilerCodegenFingerprintFromBuffer(
      Buffer.from(
        [
          'RSDS',
          'C:\\build\\sample.pdb',
          'GCC: (GNU) 13.2.1',
          'clang version 18.1.8',
          'thinlto',
          '__llvm_prf_cnts',
          'runtime.goexit',
          'rustc 1.78.0',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'sample.o' }
    )

    expect(inventory.compiler_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ family: 'msvc' }),
        expect.objectContaining({ family: 'gcc' }),
        expect.objectContaining({ family: 'clang' }),
      ])
    )
    expect(inventory.language_runtime_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ family: 'go' }),
        expect.objectContaining({ family: 'rust' }),
      ])
    )
    expect(inventory.optimization_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'lto' }),
        expect.objectContaining({ kind: 'pgo' }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['native.debug.types.inventory', 'sbom.provenance.graph'])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_compiler_invocation: true,
        no_linker_invocation: true,
        no_external_tool: true,
      })
    )
  })
})

describe('passive Rust binary inventory', () => {
  test('extracts Rust runtime, mangling, Cargo, and target hints without demanglers', () => {
    const inventory = buildRustBinaryInventoryFromBuffer(
      Buffer.from(
        [
          'rustc 1.84.1',
          'x86_64-unknown-linux-gnu',
          '_RNvCs1234567890abcdef_7mycrate4main',
          '_ZN4core3fmt5write17h0123456789abcdefE',
          '/home/build/.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.217/src/lib.rs',
          'std::rt::lang_start',
          'core::panicking::panic_fmt',
          'rust_eh_personality',
          '__rust_alloc',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'agent.rlib' }
    )

    expect(inventory.format).toBe('rust-rlib-inventory')
    expect(inventory.rustc_candidates).toEqual(
      expect.arrayContaining([expect.objectContaining({ version: '1.84.1' })])
    )
    expect(inventory.symbol_mangling).toEqual(
      expect.objectContaining({ v0_count: 1, legacy_count: 1, demangling_performed: false })
    )
    expect(inventory.crate_candidates).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'serde', version: '1.0.217' })])
    )
    expect(inventory.target_triples).toEqual(
      expect.arrayContaining([expect.objectContaining({ triple: 'x86_64-unknown-linux-gnu' })])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_rustc_invocation: true,
        no_cargo_invocation: true,
        no_external_demangler: true,
      })
    )
  })
})

describe('passive binary hardening inventory', () => {
  test('extracts mitigation posture without loaders, exploit tests, or external tools', () => {
    const inventory = buildBinaryHardeningInventoryFromBuffer(
      Buffer.from(
        [
          '__stack_chk_fail',
          '__memcpy_chk',
          'GNU_PROPERTY_X86_FEATURE_1_IBT',
          'GNU_PROPERTY_X86_FEATURE_1_SHSTK',
          'PACIASP',
          'BTI',
          'memtag',
          'CHERI purecap',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'hardened.bin' }
    )

    expect(inventory.mitigations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'stack.canary', status: 'present' }),
        expect.objectContaining({ id: 'fortify', status: 'present' }),
        expect.objectContaining({ id: 'cet.ibt', status: 'candidate' }),
        expect.objectContaining({ id: 'cet.shstk', status: 'candidate' }),
        expect.objectContaining({ id: 'aarch64.pac', status: 'candidate' }),
        expect.objectContaining({ id: 'aarch64.bti', status: 'candidate' }),
        expect.objectContaining({ id: 'aarch64.mte', status: 'candidate' }),
        expect.objectContaining({ id: 'cheri.purecap', status: 'candidate' }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['pe.security.profile', 'compiler.codegen.fingerprint'])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_loader_invocation: true,
        no_exploit_test: true,
        no_external_tool: true,
      })
    )
  })
})

describe('passive TEE enclave inventory', () => {
  test('extracts enclave and attestation hints without loading enclaves or requesting quotes', () => {
    const inventory = buildTeeEnclaveInventoryFromBuffer(
      Buffer.from(
        [
          'SIGSTRUCT',
          'MRENCLAVE',
          'g_ecall_table',
          'OP-TEE',
          'TA_InvokeCommandEntryPoint',
          'TDREPORT',
          'SEV-SNP',
          'SNP_REPORT',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'enclave.bin' }
    )

    expect(inventory.enclave_families).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ family: 'sgx' }),
        expect.objectContaining({ family: 'optee' }),
        expect.objectContaining({ family: 'tdx' }),
        expect.objectContaining({ family: 'sev-snp' }),
      ])
    )
    expect(inventory.attestation_hints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'sgx.sigstruct' }),
        expect.objectContaining({ id: 'tdx.report' }),
        expect.objectContaining({ id: 'sev.snp-report' }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['native.object.inventory', 'analysis.evidence.graph'])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_enclave_load: true,
        no_attestation_request: true,
        no_quote_generation: true,
        no_external_tool: true,
      })
    )
  })
})

describe('passive kernel driver surface inventory', () => {
  test('extracts IOCTL and module surface hints without loading drivers or modules', () => {
    const ioctl = Buffer.alloc(4)
    ioctl.writeUInt32LE((0x22 << 16) | (0x801 << 2) | 3, 0)
    const inventory = buildKernelDriverSurfaceInventoryFromBuffer(
      Buffer.concat([
        Buffer.from(
          [
            'MZ',
            'DriverEntry',
            'IRP_MJ_DEVICE_CONTROL',
            'IoCreateDevice',
            'METHOD_NEITHER',
            'FILE_ANY_ACCESS',
            'MmMapIoSpace',
            '\\\\.\\SurfaceDrv',
          ].join('\0'),
          'ascii'
        ),
        ioctl,
      ]),
      { filename: 'surfacedrv.sys' }
    )

    expect(inventory.format).toBe('windows-kernel-driver-surface')
    expect(inventory.ioctl_candidates).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          method: 'METHOD_NEITHER',
          access: 'FILE_ANY_ACCESS',
          risk_flags: expect.arrayContaining(['method_neither', 'file_any_access']),
        }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['code.xrefs.analyze', 'vuln.pattern.scan'])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_driver_load: true,
        no_kernel_module_load: true,
        no_device_open: true,
        no_ioctl_send: true,
      })
    )
  })
})

describe('passive UEFI/SMM surface inventory', () => {
  test('extracts trust-boundary hints without booting firmware or touching hardware', () => {
    const inventory = buildUefiSmmSurfaceInventoryFromBuffer(
      Buffer.from(
        [
          'MZ',
          '_FVH',
          'SmiHandlerRegister',
          'EFI_SMM_COMMUNICATION_PROTOCOL',
          'CommBuffer',
          'BootServices',
          'SetVariable',
          'SecureBoot',
          'MmioWrite32',
          'UpdateCapsule',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'SmmSurface.efi' }
    )

    expect(inventory.format).toBe('uefi-firmware-volume-smm-surface')
    expect((inventory.smm_surface as any).present).toBe(true)
    expect((inventory.variable_surface as any).secure_boot_variable_hint).toBe(true)
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'smm.communication-buffer' }),
        expect.objectContaining({ id: 'uefi.variable-write' }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['firmware.scan', 'code.xrefs.analyze', 'analysis.evidence.graph'])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_smi_trigger: true,
        no_smm_execution: true,
        no_efi_variable_write: true,
        no_mmio_or_msr_access: true,
      })
    )
  })
})

describe('passive syscall ABI surface inventory', () => {
  test('extracts direct syscall hints without invoking syscalls or tracing', () => {
    const inventory = buildSyscallAbiSurfaceInventoryFromBuffer(
      Buffer.concat([
        Buffer.from([0x4d, 0x5a, 0x4c, 0x8b, 0xd1, 0xb8, 0x3a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc3]),
        Buffer.from(
          ['SysWhispers', 'HellsGate', 'ntdll.dll', 'NtAllocateVirtualMemory'].join('\0'),
          'ascii'
        ),
      ]),
      { filename: 'direct.syscall' }
    )

    expect(inventory.format).toBe('pe-windows-direct-syscall-surface')
    expect((inventory.windows_nt_surface as any).direct_stub_count).toBe(1)
    expect((inventory.windows_nt_surface as any).syscall_numbers).toContain('0x3a')
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'windows.direct-syscall-stub' }),
        expect.objectContaining({ id: 'direct-syscall.named-evasion-framework' }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['code.xrefs.analyze', 'analysis.evidence.graph'])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_syscall: true,
        no_ptrace: true,
        no_debugger: true,
        no_emulation: true,
      })
    )
  })
})

describe('passive Windows interface surface inventory', () => {
  test('extracts COM/RPC/IPC/WMI/service hints without activating interfaces', () => {
    const inventory = buildWindowsInterfaceSurfaceInventoryFromBuffer(
      Buffer.from(
        [
          'MZ',
          'CLSID',
          '{11111111-2222-3333-4444-555555555555}',
          'CoCreateInstance',
          'DllRegisterServer',
          'RpcServerRegisterIf',
          'ncacn_ip_tcp',
          '\\\\.\\pipe\\svcctl',
          'ImpersonateNamedPipeClient',
          'IWbemServices',
          'root\\subscription',
          '__EventFilter',
          'OpenSCManagerW',
          'CreateServiceW',
        ].join('\0'),
        'ascii'
      ),
      { filename: 'broker.dll' }
    )

    expect(inventory.format).toBe('windows-rpc-interface-surface')
    expect((inventory.com_surface as any).present).toBe(true)
    expect((inventory.rpc_surface as any).has_remote_protocol_hint).toBe(true)
    expect((inventory.ipc_surface as any).impersonation_hint).toBe(true)
    expect((inventory.wmi_surface as any).persistence_hint).toBe(true)
    expect((inventory.service_surface as any).present).toBe(true)
    expect(inventory.risk_flags).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: 'windows.rpc-remote-protocol' }),
        expect.objectContaining({ id: 'windows.ipc-impersonation-surface' }),
        expect.objectContaining({ id: 'windows.wmi-persistence-surface' }),
      ])
    )
    expect(inventory.recommended_next_tools).toEqual(
      expect.arrayContaining(['pe.imports.extract', 'static.resource.graph', 'workflow.search'])
    )
    expect(inventory.policy).toEqual(
      expect.objectContaining({
        passive: true,
        no_execute: true,
        no_com_activation: true,
        no_rpc_call: true,
        no_named_pipe_connect: true,
        no_wmi_query: true,
        no_service_start: true,
      })
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
    const wasmComponent = plugins.find((plugin) => plugin.id === 'wasm-component')
    const bytecode = plugins.find((plugin) => plugin.id === 'bytecode')
    const binaryHardening = plugins.find((plugin) => plugin.id === 'binary-hardening')
    const btf = plugins.find((plugin) => plugin.id === 'btf')
    const compilerCodegen = plugins.find((plugin) => plugin.id === 'compiler-codegen')
    const cppAbiLayout = plugins.find((plugin) => plugin.id === 'cpp-abi-layout')
    const ebpfBytecode = plugins.find((plugin) => plugin.id === 'ebpf-bytecode')
    const kernelDriverSurface = plugins.find((plugin) => plugin.id === 'kernel-driver-surface')
    const llvmBitcode = plugins.find((plugin) => plugin.id === 'llvm-bitcode')
    const mlModel = plugins.find((plugin) => plugin.id === 'ml-model')
    const shaderIr = plugins.find((plugin) => plugin.id === 'shader-ir')
    const syscallAbiSurface = plugins.find((plugin) => plugin.id === 'syscall-abi-surface')
    const teeEnclave = plugins.find((plugin) => plugin.id === 'tee-enclave')
    const uefiSmmSurface = plugins.find((plugin) => plugin.id === 'uefi-smm-surface')
    const windowsInterfaceSurface = plugins.find(
      (plugin) => plugin.id === 'windows-interface-surface'
    )
    const windowsInstaller = plugins.find((plugin) => plugin.id === 'windows-installer')
    const windowsDebugSymbols = plugins.find((plugin) => plugin.id === 'windows-debug-symbols')
    const dotnetManaged = plugins.find((plugin) => plugin.id === 'dotnet-managed')
    const unityManaged = plugins.find((plugin) => plugin.id === 'unity-managed')
    const containerAnalysis = plugins.find((plugin) => plugin.id === 'container-analysis')
    const nativeObject = plugins.find((plugin) => plugin.id === 'native-object')
    const nativeDebugTypes = plugins.find((plugin) => plugin.id === 'native-debug-types')
    const rustBinary = plugins.find((plugin) => plugin.id === 'rust-binary')
    const androidPackage = plugins.find((plugin) => plugin.id === 'android-package')
    const appleSigning = plugins.find((plugin) => plugin.id === 'apple-signing')
    const appleObjcSwift = plugins.find((plugin) => plugin.id === 'apple-objc-swift')
    const linuxBinary = plugins.find((plugin) => plugin.id === 'linux-binary')
    const cudaBinary = plugins.find((plugin) => plugin.id === 'cuda-binary')

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
    expect(wasmComponent?.aspects?.formats).toEqual(
      expect.arrayContaining([
        'wasm-component',
        'component-model',
        'wit-component',
        'wasi-preview2',
      ])
    )
    expect(wasmComponent?.tools?.map((tool) => tool.definition.name)).toContain(
      'wasm.component.inventory'
    )
    expect(bytecode?.aspects?.formats).toEqual(
      expect.arrayContaining(['pyc', 'lua-bytecode', 'v8-cache'])
    )
    expect(bytecode?.tools?.map((tool) => tool.definition.name)).toContain(
      'bytecode.metadata.inspect'
    )
    expect(binaryHardening?.aspects?.formats).toEqual(
      expect.arrayContaining([
        'binary-hardening',
        'exploit-mitigation',
        'elf-hardening',
        'pe-hardening',
        'checksec',
      ])
    )
    expect(binaryHardening?.tools?.map((tool) => tool.definition.name)).toContain(
      'binary.hardening.inventory'
    )
    expect(btf?.aspects?.formats).toEqual(
      expect.arrayContaining(['btf', 'btf-ext', 'btf-elf', 'core-relocations'])
    )
    expect(btf?.tools?.map((tool) => tool.definition.name)).toContain('btf.type.inventory')
    expect(compilerCodegen?.aspects?.formats).toEqual(
      expect.arrayContaining(['compiler-codegen', 'compiler-provenance', 'rich-header', 'codeview'])
    )
    expect(compilerCodegen?.tools?.map((tool) => tool.definition.name)).toContain(
      'compiler.codegen.fingerprint'
    )
    expect(rustBinary?.aspects?.formats).toEqual(
      expect.arrayContaining([
        'rust-binary',
        'rust',
        'rustc',
        'cargo-crate',
        'rust-v0-mangled',
        'rust-legacy-mangled',
      ])
    )
    expect(rustBinary?.tools?.map((tool) => tool.definition.name)).toContain(
      'rust.binary.inventory'
    )
    expect(teeEnclave?.aspects?.formats).toEqual(
      expect.arrayContaining(['tee-enclave', 'sgx-enclave', 'optee-ta', 'tdx', 'sev-snp'])
    )
    expect(teeEnclave?.tools?.map((tool) => tool.definition.name)).toContain(
      'tee.enclave.inventory'
    )
    expect(cppAbiLayout?.aspects?.formats).toEqual(
      expect.arrayContaining(['cpp-abi', 'itanium-abi', 'msvc-abi', 'rtti', 'vtable'])
    )
    expect(cppAbiLayout?.tools?.map((tool) => tool.definition.name)).toContain(
      'cpp.abi.layout.inventory'
    )
    expect(kernelDriverSurface?.aspects?.formats).toEqual(
      expect.arrayContaining(['kernel-driver', 'windows-driver', 'linux-kernel-module', 'ioctl'])
    )
    expect(kernelDriverSurface?.tools?.map((tool) => tool.definition.name)).toContain(
      'kernel.driver.surface.inventory'
    )
    expect(uefiSmmSurface?.aspects?.formats).toEqual(
      expect.arrayContaining(['uefi', 'efi', 'uefi-smm', 'firmware-volume', 'uefi-capsule'])
    )
    expect(uefiSmmSurface?.tools?.map((tool) => tool.definition.name)).toContain(
      'uefi.smm.surface.inventory'
    )
    expect(syscallAbiSurface?.aspects?.formats).toEqual(
      expect.arrayContaining(['syscall', 'direct-syscall', 'raw-shellcode', 'ntdll-stub'])
    )
    expect(syscallAbiSurface?.tools?.map((tool) => tool.definition.name)).toContain(
      'syscall.abi.surface.inventory'
    )
    expect(windowsInterfaceSurface?.aspects?.formats).toEqual(
      expect.arrayContaining(['windows-interface', 'com', 'rpc', 'alpc', 'etw', 'wmi'])
    )
    expect(windowsInterfaceSurface?.tools?.map((tool) => tool.definition.name)).toContain(
      'windows.interface.surface.inventory'
    )
    expect(ebpfBytecode?.aspects?.formats).toEqual(
      expect.arrayContaining(['ebpf', 'bpf', 'raw-ebpf', 'ebpf-elf'])
    )
    expect(ebpfBytecode?.tools?.map((tool) => tool.definition.name)).toContain(
      'ebpf.bytecode.inventory'
    )
    expect(llvmBitcode?.aspects?.formats).toEqual(
      expect.arrayContaining(['llvm-bitcode', 'llvm-bc', 'llvm-ir'])
    )
    expect(llvmBitcode?.tools?.map((tool) => tool.definition.name)).toContain(
      'llvm.bitcode.inventory'
    )
    expect(mlModel?.aspects?.formats).toEqual(
      expect.arrayContaining(['ml-model', 'safetensors', 'gguf', 'onnx', 'tflite'])
    )
    expect(mlModel?.tools?.map((tool) => tool.definition.name)).toContain('ml.model.inventory')
    expect(shaderIr?.aspects?.formats).toEqual(
      expect.arrayContaining(['shader-ir', 'spir-v', 'dxil', 'dxbc', 'wgsl'])
    )
    expect(shaderIr?.tools?.map((tool) => tool.definition.name)).toContain('shader.ir.inventory')
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
    expect(containerAnalysis?.tools?.map((tool) => tool.definition.name)).toEqual(
      expect.arrayContaining(['container.structure.analyze', 'container.image.security.profile'])
    )
    expect(nativeObject?.aspects?.formats).toEqual(
      expect.arrayContaining(['object', 'ar-static-lib', 'elf-object', 'linux-kernel-module'])
    )
    expect(nativeObject?.tools?.map((tool) => tool.definition.name)).toContain(
      'native.object.inventory'
    )
    expect(nativeDebugTypes?.aspects?.formats).toEqual(
      expect.arrayContaining(['dwarf', 'split-dwarf', 'dwo', 'dwp', 'ctf'])
    )
    expect(nativeDebugTypes?.tools?.map((tool) => tool.definition.name)).toContain(
      'native.debug.types.inventory'
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
    expect(appleObjcSwift?.aspects?.formats).toEqual(
      expect.arrayContaining(['objc-metadata', 'swift-metadata', 'swiftmodule', 'macho'])
    )
    expect(appleObjcSwift?.tools?.map((tool) => tool.definition.name)).toContain(
      'apple.objc_swift.metadata.inspect'
    )
    expect(linuxBinary?.aspects?.formats).toEqual(
      expect.arrayContaining(['elf-executable', 'elf-so', 'elf-core', 'linux-kernel-module'])
    )
    expect(linuxBinary?.tools?.map((tool) => tool.definition.name)).toContain(
      'linux.binary.inventory'
    )
    expect(cudaBinary?.aspects?.formats).toEqual(
      expect.arrayContaining(['cuda', 'ptx', 'cubin', 'fatbin', 'sass'])
    )
    expect(cudaBinary?.tools?.map((tool) => tool.definition.name)).toContain(
      'cuda.binary.inventory'
    )
  }, 30_000)

  test('discovers native reverse engineering adapters with tool-level metadata', async () => {
    const plugins = await discoverBuiltInPlugins()
    const ghidra = requirePlugin(plugins, 'ghidra')
    const rizin = requirePlugin(plugins, 'rizin')
    const retdec = requirePlugin(plugins, 'retdec')
    const capstone = requirePlugin(plugins, 'capstone')
    const elfMacho = requirePlugin(plugins, 'elf-macho')
    const apkSmali = requirePlugin(plugins, 'apk-smali')
    const firmware = requirePlugin(plugins, 'firmware')
    const binaryHardening = requirePlugin(plugins, 'binary-hardening')
    const nativeObject = requirePlugin(plugins, 'native-object')
    const nativeDebugTypes = requirePlugin(plugins, 'native-debug-types')
    const compilerCodegen = requirePlugin(plugins, 'compiler-codegen')
    const rustBinary = requirePlugin(plugins, 'rust-binary')
    const cppAbiLayout = requirePlugin(plugins, 'cpp-abi-layout')
    const kernelDriverSurface = requirePlugin(plugins, 'kernel-driver-surface')
    const btf = requirePlugin(plugins, 'btf')
    const ebpfBytecode = requirePlugin(plugins, 'ebpf-bytecode')
    const llvmBitcode = requirePlugin(plugins, 'llvm-bitcode')
    const mlModel = requirePlugin(plugins, 'ml-model')
    const shaderIr = requirePlugin(plugins, 'shader-ir')
    const syscallAbiSurface = requirePlugin(plugins, 'syscall-abi-surface')
    const teeEnclave = requirePlugin(plugins, 'tee-enclave')
    const uefiSmmSurface = requirePlugin(plugins, 'uefi-smm-surface')
    const windowsInterfaceSurface = requirePlugin(plugins, 'windows-interface-surface')
    const wasmComponent = requirePlugin(plugins, 'wasm-component')
    const androidPackage = requirePlugin(plugins, 'android-package')
    const appleSigning = requirePlugin(plugins, 'apple-signing')
    const appleObjcSwift = requirePlugin(plugins, 'apple-objc-swift')
    const linuxBinary = requirePlugin(plugins, 'linux-binary')
    const codeAnalysis = requirePlugin(plugins, 'code-analysis')
    const apiHash = requirePlugin(plugins, 'api-hash')
    const cudaBinary = requirePlugin(plugins, 'cuda-binary')
    const peAnalysis = requirePlugin(plugins, 'pe-analysis')

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
    expect(nativeDebugTypes.aspects?.capabilities).toEqual(
      expect.arrayContaining(['dwarf-unit-summary', 'ctf-type-metadata', 'type-graph-seeds'])
    )
    expect(binaryHardening.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'binary-hardening-inventory',
        'checksec-style-profile',
        'exploit-mitigation-posture',
        'cet-ibt-shstk-hints',
        'pac-bti-mte-hints',
        'cheri-purecap-hints',
      ])
    )
    expect(compilerCodegen.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'compiler-codegen-fingerprint',
        'toolchain-provenance-inventory',
        'optimization-lto-pgo-hints',
      ])
    )
    expect(rustBinary.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'rust-binary-inventory',
        'rust-v0-mangled-symbol-inventory',
        'rust-legacy-mangled-symbol-inventory',
        'rustc-cargo-provenance-hints',
        'rust-panic-unwind-profile',
      ])
    )
    expect(teeEnclave.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'tee-enclave-inventory',
        'sgx-enclave-metadata-hints',
        'optee-ta-metadata-hints',
        'tdx-attestation-hints',
        'sev-snp-attestation-hints',
      ])
    )
    expect(cppAbiLayout.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'itanium-vtable-inventory',
        'msvc-rtti-inventory',
        'class-layout-seeds',
      ])
    )
    expect(btf.aspects?.capabilities).toEqual(
      expect.arrayContaining(['btf-type-inventory', 'core-relocation-inventory'])
    )
    expect(androidPackage.aspects?.formats).toEqual(
      expect.arrayContaining(['android-package', 'apk', 'dex', 'apk-signature'])
    )
    expect(appleSigning.aspects?.formats).toEqual(
      expect.arrayContaining(['apple-signing', 'macho', 'mobileprovision'])
    )
    expect(appleObjcSwift.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'objc-runtime-metadata-inventory',
        'swift-abi-metadata-inventory',
        'selector-inventory',
      ])
    )
    expect(linuxBinary.aspects?.formats).toEqual(
      expect.arrayContaining(['linux-binary', 'elf-executable', 'elf-core'])
    )
    expect(llvmBitcode.aspects?.capabilities).toEqual(
      expect.arrayContaining(['bitstream-summary', 'wrapper-inventory', 'workflow-routing'])
    )
    expect(codeAnalysis.aspects?.capabilities).toEqual(
      expect.arrayContaining(['cross-decompiler-consensus', 'ir-comparison'])
    )
    expect(cudaBinary.aspects?.capabilities).toEqual(
      expect.arrayContaining(['cuda-artifact-inventory', 'culifter-handoff'])
    )
    expect(shaderIr.aspects?.capabilities).toEqual(
      expect.arrayContaining(['shader-ir-inventory', 'spirv-entrypoint-reflection'])
    )
    expect(uefiSmmSurface.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'uefi-smm-surface-inventory',
        'smi-handler-hints',
        'smm-communication-buffer-hints',
      ])
    )
    expect(syscallAbiSurface.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'syscall-abi-surface-inventory',
        'direct-syscall-stub-detection',
        'nt-api-boundary-hints',
      ])
    )
    expect(windowsInterfaceSurface.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'windows-interface-surface-inventory',
        'com-clsid-iid-inventory',
        'rpc-interface-endpoint-hints',
        'alpc-named-pipe-ipc-hints',
      ])
    )
    expect(wasmComponent.aspects?.capabilities).toEqual(
      expect.arrayContaining([
        'component-model-inventory',
        'wit-interface-hints',
        'canonical-abi-summary',
      ])
    )
    expect(peAnalysis.aspects?.capabilities).toEqual(
      expect.arrayContaining(['security-profile', 'mitigation-profile', 'loader-security'])
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
    expectToolMetadata(nativeDebugTypes, 'native.debug.types.inventory', {
      formats: ['dwarf', 'split-dwarf', 'dwo', 'dwp', 'ctf'],
      artifacts: ['native_debug_type_inventory'],
      evidence: ['structure', 'debug-metadata', 'types', 'source-map', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'native-debug-types',
      toolName: 'native.debug.types.inventory',
      recipeId: 'native.debug-types-static-inventory',
      startsWith: ['native.debug.types.inventory'],
      nextTools: ['native.object.inventory', 'artifact.read', 'analysis.evidence.graph'],
      producesArtifacts: ['native_debug_type_inventory'],
      evidence: ['debug-metadata', 'types', 'source-map', 'workflow'],
      safety: ['passive', 'no_external_tool', 'no_symbol_server_download', 'no_source_fetch'],
    })
    expectToolMetadata(binaryHardening, 'binary.hardening.inventory', {
      formats: ['binary-hardening', 'exploit-mitigation', 'elf-hardening', 'pe-hardening'],
      artifacts: ['binary_hardening_inventory'],
      evidence: ['mitigations', 'hardware-features', 'sections', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'binary-hardening',
      toolName: 'binary.hardening.inventory',
      recipeId: 'binary.hardening-static-inventory',
      startsWith: ['binary.hardening.inventory'],
      nextTools: ['pe.security.profile', 'compiler.codegen.fingerprint', 'analysis.evidence.graph'],
      producesArtifacts: ['binary_hardening_inventory'],
      evidence: ['mitigations', 'hardware-features', 'sections', 'workflow'],
      safety: ['passive', 'no_loader_invocation', 'no_exploit_test', 'no_external_tool'],
    })
    expectToolMetadata(compilerCodegen, 'compiler.codegen.fingerprint', {
      formats: ['compiler-codegen', 'compiler-provenance', 'rich-header', 'codeview'],
      artifacts: ['compiler_codegen_fingerprint'],
      evidence: ['provenance', 'compiler', 'linker', 'optimization', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'compiler-codegen',
      toolName: 'compiler.codegen.fingerprint',
      recipeId: 'compiler.codegen-fingerprint-static-inventory',
      startsWith: ['compiler.codegen.fingerprint'],
      nextTools: [
        'native.debug.types.inventory',
        'windows.debug.metadata.inspect',
        'sbom.provenance.graph',
      ],
      producesArtifacts: ['compiler_codegen_fingerprint'],
      evidence: ['provenance', 'compiler', 'linker', 'optimization', 'workflow'],
      safety: ['passive', 'no_compiler_invocation', 'no_linker_invocation', 'no_external_tool'],
    })
    expectToolMetadata(rustBinary, 'rust.binary.inventory', {
      formats: ['rust-binary', 'rust', 'rustc', 'cargo-crate', 'rust-v0-mangled'],
      artifacts: ['rust_binary_inventory'],
      evidence: ['symbols', 'language-runtime', 'provenance', 'panic', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'rust-binary',
      toolName: 'rust.binary.inventory',
      recipeId: 'rust.binary-static-inventory',
      startsWith: ['rust.binary.inventory'],
      nextTools: [
        'compiler.codegen.fingerprint',
        'native.debug.types.inventory',
        'sbom.provenance.graph',
      ],
      producesArtifacts: ['rust_binary_inventory'],
      evidence: ['symbols', 'language-runtime', 'provenance', 'panic', 'workflow'],
      safety: ['passive', 'no_rustc_invocation', 'no_cargo_invocation', 'no_external_demangler'],
    })
    expectToolMetadata(teeEnclave, 'tee.enclave.inventory', {
      formats: ['tee-enclave', 'sgx-enclave', 'optee-ta', 'tdx', 'sev-snp'],
      artifacts: ['tee_enclave_inventory'],
      evidence: ['manifest', 'attestation', 'measurement', 'boundary', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'tee-enclave',
      toolName: 'tee.enclave.inventory',
      recipeId: 'tee.enclave-static-inventory',
      startsWith: ['tee.enclave.inventory'],
      nextTools: [
        'native.object.inventory',
        'compiler.codegen.fingerprint',
        'sbom.provenance.graph',
      ],
      producesArtifacts: ['tee_enclave_inventory'],
      evidence: ['manifest', 'attestation', 'measurement', 'boundary', 'workflow'],
      safety: ['passive', 'no_enclave_load', 'no_attestation_request', 'no_external_tool'],
    })
    expectToolMetadata(cppAbiLayout, 'cpp.abi.layout.inventory', {
      formats: ['cpp-abi', 'itanium-abi', 'msvc-abi', 'rtti'],
      artifacts: ['cpp_abi_layout_inventory'],
      evidence: ['classes', 'rtti', 'vtable', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'cpp-abi-layout',
      toolName: 'cpp.abi.layout.inventory',
      recipeId: 'cpp.abi-layout-static-inventory',
      startsWith: ['cpp.abi.layout.inventory'],
      nextTools: ['native.object.inventory', 'native.debug.types.inventory', 'code.xrefs.analyze'],
      producesArtifacts: ['cpp_abi_layout_inventory'],
      evidence: ['classes', 'rtti', 'vtable', 'layout-seeds', 'workflow'],
      safety: ['passive', 'no_external_demangler', 'no_native_load', 'no_source_fetch'],
    })
    expectToolMetadata(kernelDriverSurface, 'kernel.driver.surface.inventory', {
      formats: ['kernel-driver', 'windows-driver', 'linux-kernel-module', 'ioctl'],
      artifacts: ['kernel_driver_surface_inventory'],
      evidence: ['device-interfaces', 'ioctl', 'dispatch', 'module-metadata', 'risk', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'kernel-driver-surface',
      toolName: 'kernel.driver.surface.inventory',
      recipeId: 'kernel.driver-surface-static-inventory',
      startsWith: ['kernel.driver.surface.inventory'],
      nextTools: ['pe.structure.analyze', 'linux.binary.inventory', 'code.xrefs.analyze'],
      producesArtifacts: ['kernel_driver_surface_inventory'],
      evidence: ['ioctl', 'dispatch', 'module-metadata', 'risk', 'workflow'],
      safety: ['passive', 'no_driver_load', 'no_kernel_module_load', 'no_ioctl_send'],
    })
    expectToolMetadata(uefiSmmSurface, 'uefi.smm.surface.inventory', {
      formats: ['uefi', 'efi', 'uefi-smm', 'firmware-volume'],
      artifacts: ['uefi_smm_surface_inventory'],
      evidence: ['smm', 'protocols', 'variables', 'risk', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'uefi-smm-surface',
      toolName: 'uefi.smm.surface.inventory',
      recipeId: 'uefi.smm-surface-static-inventory',
      startsWith: ['uefi.smm.surface.inventory'],
      nextTools: ['firmware.scan', 'pe.structure.analyze', 'code.xrefs.analyze'],
      producesArtifacts: ['uefi_smm_surface_inventory'],
      evidence: ['smm', 'variables', 'low-level-primitives', 'risk', 'workflow'],
      safety: ['passive', 'no_smi_trigger', 'no_smm_execution', 'no_efi_variable_write'],
    })
    expectToolMetadata(syscallAbiSurface, 'syscall.abi.surface.inventory', {
      formats: ['syscall', 'direct-syscall', 'raw-shellcode', 'ntdll-stub'],
      artifacts: ['syscall_abi_surface_inventory'],
      evidence: ['syscalls', 'abi', 'evasion', 'risk', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'syscall-abi-surface',
      toolName: 'syscall.abi.surface.inventory',
      recipeId: 'syscall.abi-surface-static-inventory',
      startsWith: ['syscall.abi.surface.inventory'],
      nextTools: ['artifact.read', 'pe.imports.extract', 'code.xrefs.analyze'],
      producesArtifacts: ['syscall_abi_surface_inventory'],
      evidence: ['syscalls', 'abi', 'evasion', 'risk', 'workflow'],
      safety: ['passive', 'no_syscall', 'no_ptrace', 'no_debugger', 'no_emulation'],
    })
    expectToolMetadata(windowsInterfaceSurface, 'windows.interface.surface.inventory', {
      formats: ['windows-interface', 'com', 'rpc', 'alpc', 'etw', 'wmi'],
      artifacts: ['windows_interface_surface_inventory'],
      evidence: ['interfaces', 'guid', 'com', 'rpc', 'ipc', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'windows-interface-surface',
      toolName: 'windows.interface.surface.inventory',
      recipeId: 'windows.interface-surface-static-inventory',
      startsWith: ['windows.interface.surface.inventory'],
      nextTools: ['artifact.read', 'pe.imports.extract', 'static.resource.graph'],
      producesArtifacts: ['windows_interface_surface_inventory'],
      evidence: ['interfaces', 'guid', 'com', 'rpc', 'ipc', 'risk', 'workflow'],
      safety: ['passive', 'no_com_activation', 'no_rpc_call', 'no_named_pipe_connect'],
    })
    expectToolMetadata(btf, 'btf.type.inventory', {
      formats: ['btf', 'btf-ext', 'btf-elf', 'core-relocations'],
      artifacts: ['btf_type_inventory'],
      evidence: ['structure', 'types', 'metadata', 'relocations', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'btf',
      toolName: 'btf.type.inventory',
      recipeId: 'btf.type-core-inventory',
      startsWith: ['btf.type.inventory'],
      nextTools: ['ebpf.bytecode.inventory', 'native.object.inventory', 'linux.runtime.plan'],
      producesArtifacts: ['btf_type_inventory'],
      evidence: ['types', 'relocations', 'workflow'],
      safety: ['no_bpf_syscall', 'no_kernel_verifier_run', 'no_program_load', 'no_libbpf'],
      runtimeBackends: ['linux-runtime'],
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
    expectToolMetadata(llvmBitcode, 'llvm.bitcode.inventory', {
      formats: ['llvm-bitcode', 'llvm-bitcode-wrapper', 'llvm-bc', 'llvm-ir'],
      artifacts: ['llvm_bitcode_inventory'],
      evidence: ['structure', 'strings', 'metadata', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'llvm-bitcode',
      toolName: 'llvm.bitcode.inventory',
      recipeId: 'llvm.bitcode-static-inventory',
      startsWith: ['llvm.bitcode.inventory'],
      nextTools: [
        'artifact.read',
        'metadata.extract',
        'strings.extract',
        'analysis.evidence.graph',
      ],
      producesArtifacts: ['llvm_bitcode_inventory'],
      evidence: ['structure', 'strings', 'metadata', 'workflow'],
      safety: ['passive', 'no_llvm_toolchain_required', 'no_compile', 'no_link', 'no_execute'],
    })
    expectToolMetadata(mlModel, 'ml.model.inventory', {
      formats: ['ml-model', 'safetensors', 'gguf', 'onnx', 'tflite'],
      artifacts: ['ml_model_inventory'],
      evidence: ['structure', 'metadata', 'strings', 'workflow', 'provenance'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'ml-model',
      toolName: 'ml.model.inventory',
      recipeId: 'ml.model-static-inventory',
      startsWith: ['ml.model.inventory'],
      nextTools: ['artifact.read', 'strings.extract', 'analysis.evidence.graph'],
      producesArtifacts: ['ml_model_inventory'],
      evidence: ['structure', 'metadata', 'strings', 'workflow', 'provenance'],
      safety: ['passive', 'no_deserialization', 'no_model_load', 'no_inference'],
    })
    expectToolMetadata(shaderIr, 'shader.ir.inventory', {
      formats: ['shader-ir', 'spir-v', 'dxil', 'dxbc', 'wgsl'],
      artifacts: ['shader_ir_inventory'],
      evidence: ['structure', 'metadata', 'strings', 'resources', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'shader-ir',
      toolName: 'shader.ir.inventory',
      recipeId: 'shader.ir-static-inventory',
      startsWith: ['shader.ir.inventory'],
      nextTools: ['artifact.read', 'strings.extract', 'metadata.extract', 'culifter.gpu.plan'],
      producesArtifacts: ['shader_ir_inventory'],
      evidence: ['structure', 'metadata', 'strings', 'resources', 'workflow'],
      safety: ['passive', 'no_gpu_driver', 'no_gpu_access', 'no_shader_compiler'],
    })
    expectToolMetadata(wasmComponent, 'wasm.component.inventory', {
      formats: ['wasm-component', 'component-model', 'wit-component', 'wasi-preview2'],
      artifacts: ['wasm_component_inventory'],
      evidence: [
        'structure',
        'imports',
        'exports',
        'wasi-capability',
        'wit-interface',
        'canonical-abi',
        'workflow',
      ],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'wasm-component',
      toolName: 'wasm.component.inventory',
      recipeId: 'wasm.component-static-inventory',
      startsWith: ['wasm.component.inventory'],
      nextTools: ['wasm.structure.analyze', 'wasm.runtime.plan', 'analysis.evidence.graph'],
      producesArtifacts: ['wasm_component_inventory'],
      evidence: [
        'structure',
        'imports',
        'exports',
        'wasi-capability',
        'wit-interface',
        'canonical-abi',
        'workflow',
      ],
      safety: ['passive', 'no_instantiation', 'no_wasi_grants', 'no_external_tool'],
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
    expectToolMetadata(appleObjcSwift, 'apple.objc_swift.metadata.inspect', {
      formats: ['objc-metadata', 'swift-metadata', 'macho'],
      artifacts: ['apple_objc_swift_metadata_inventory'],
      evidence: ['structure', 'symbols', 'classes', 'selectors', 'swift-metadata', 'workflow'],
    })
    expectWorkflowRecipeMetadata(plugins, {
      pluginId: 'apple-objc-swift',
      toolName: 'apple.objc_swift.metadata.inspect',
      recipeId: 'apple.objc-swift-metadata-static-inventory',
      startsWith: ['apple.objc_swift.metadata.inspect'],
      nextTools: ['macho.structure.analyze', 'apple.signing.inspect', 'analysis.evidence.graph'],
      producesArtifacts: ['apple_objc_swift_metadata_inventory'],
      evidence: ['classes', 'selectors', 'swift-metadata', 'workflow'],
      safety: ['passive', 'no_debug_attach', 'no_app_launch', 'no_external_tool'],
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
    expectToolMetadata(cudaBinary, 'cuda.binary.inventory', {
      formats: ['cuda', 'ptx', 'cubin', 'fatbin'],
      artifacts: ['cuda_binary_inventory', 'cuda_kernel_summary'],
      evidence: ['structure', 'symbols', 'strings', 'workflow', 'provenance'],
    })
    expectToolMetadata(peAnalysis, 'pe.security.profile', {
      formats: ['pe', 'pe-clr', 'dll', 'exe', 'sys', 'efi'],
      artifacts: ['pe_security_profile'],
      evidence: ['structure', 'mitigations', 'sections', 'workflow', 'provenance'],
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
    expect(reportGenerate?.definition.evidence).toBeUndefined()
    expect(workflowSummarize?.definition.evidence).toBeUndefined()
    expect(workflowSummarize?.definition.artifacts?.map((artifact) => artifact.type)).toEqual(
      expect.arrayContaining([
        'summary_triage_digest',
        'summary_static_digest',
        'summary_deep_digest',
        'summary_final_digest',
      ])
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
        pluginId: 'container-analysis',
        toolName: 'container.image.security.profile',
        recipeId: 'container.image-security-profile',
        startsWith: ['container.image.security.profile', 'container.structure.analyze'],
        nextTools: [
          'container.structure.analyze',
          'sbom.provenance.graph',
          'sbom.generate',
          'analysis.evidence.graph',
          'report.generate',
        ],
        producesArtifacts: ['container_image_security_profile'],
        evidence: ['filesystem', 'package-metadata', 'provenance', 'workflow', 'sbom'],
        safety: [
          'passive',
          'no_network_by_default',
          'no_installer_execution',
          'no_auto_mount',
          'no_live_sample_by_default',
          'no_mutation',
        ],
      },
      {
        pluginId: 'ml-model',
        toolName: 'ml.model.inventory',
        recipeId: 'ml.model-static-inventory',
        startsWith: ['ml.model.inventory'],
        nextTools: [
          'artifact.read',
          'metadata.extract',
          'strings.extract',
          'analysis.evidence.graph',
          'report.generate',
        ],
        producesArtifacts: ['ml_model_inventory'],
        evidence: ['structure', 'metadata', 'strings', 'workflow', 'provenance'],
        safety: [
          'passive',
          'no_deserialization',
          'no_model_load',
          'no_inference',
          'no_ml_framework_load',
          'no_network_by_default',
        ],
      },
      {
        pluginId: 'wasm-component',
        toolName: 'wasm.component.inventory',
        recipeId: 'wasm.component-static-inventory',
        startsWith: ['wasm.component.inventory'],
        nextTools: ['wasm.structure.analyze', 'wasm.runtime.plan', 'analysis.evidence.graph'],
        producesArtifacts: ['wasm_component_inventory'],
        evidence: [
          'structure',
          'imports',
          'exports',
          'wasi-capability',
          'wit-interface',
          'canonical-abi',
          'workflow',
          'provenance',
        ],
        safety: [
          'passive',
          'no_live_sample_by_default',
          'no_runtime_start',
          'no_instantiation',
          'no_wasi_grants',
          'no_external_tool',
          'no_network_by_default',
        ],
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
        pluginId: 'apple-objc-swift',
        toolName: 'apple.objc_swift.metadata.inspect',
        recipeId: 'apple.objc-swift-metadata-static-inventory',
        startsWith: ['apple.objc_swift.metadata.inspect'],
        nextTools: ['macho.structure.analyze', 'apple.signing.inspect', 'analysis.evidence.graph'],
        producesArtifacts: ['apple_objc_swift_metadata_inventory'],
        evidence: [
          'structure',
          'symbols',
          'classes',
          'selectors',
          'swift-metadata',
          'workflow',
          'provenance',
        ],
        safety: [
          'passive',
          'no_debug_attach',
          'no_app_launch',
          'no_external_tool',
          'no_runtime_start',
        ],
      },
      {
        pluginId: 'native-debug-types',
        toolName: 'native.debug.types.inventory',
        recipeId: 'native.debug-types-static-inventory',
        startsWith: ['native.debug.types.inventory'],
        nextTools: ['native.object.inventory', 'windows.debug.metadata.inspect'],
        producesArtifacts: ['native_debug_type_inventory'],
        evidence: ['debug-metadata', 'types', 'source-map', 'source-paths', 'workflow'],
        safety: [
          'passive',
          'no_debugger',
          'no_external_tool',
          'no_symbol_server_download',
          'no_source_fetch',
        ],
      },
      {
        pluginId: 'pe-analysis',
        toolName: 'pe.security.profile',
        recipeId: 'pe.security.hardening-profile',
        startsWith: ['pe.security.profile', 'pe.structure.analyze'],
        nextTools: ['pe.structure.analyze', 'pe.pdata.extract', 'analysis.evidence.graph'],
        producesArtifacts: ['pe_security_profile'],
        evidence: ['structure', 'mitigations', 'sections', 'workflow', 'provenance'],
        safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default', 'no_mutation'],
        runtimeBackends: ['builtin-pe-parser'],
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
      {
        pluginId: 'cuda-binary',
        toolName: 'cuda.binary.inventory',
        recipeId: 'cuda.binary.static-inventory-handoff',
        startsWith: ['cuda.binary.inventory'],
        nextTools: ['culifter.gpu.plan', 'native.object.inventory', 'linux.binary.inventory'],
        producesArtifacts: ['cuda_binary_inventory', 'cuda_kernel_summary'],
        evidence: ['structure', 'symbols', 'strings', 'workflow', 'provenance'],
        safety: ['passive', 'no_cuda_driver', 'no_gpu_access', 'no_external_tool'],
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
