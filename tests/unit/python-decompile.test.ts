import { afterEach, beforeEach, describe, expect, test } from '@jest/globals'
import fs from 'fs'
import fsp from 'fs/promises'
import path from 'path'
import os from 'os'
import { fileURLToPath } from 'url'
import { execFileSync } from 'child_process'
import { WorkspaceManager } from '../../src/workspace-manager.js'
import { DatabaseManager } from '../../src/database.js'
import pythonDecompilePlugin from '../../src/plugins/python-decompile/index.js'
import {
  createPythonDecompileHandler,
  pythonDecompileToolDefinition,
} from '../../src/plugins/python-decompile/tools/python-decompile.js'
import { getToolSurfaceManager } from '../../src/core/tool-surface-manager.js'

const __filename = fileURLToPath(import.meta.url)
const PROJECT_ROOT = path.resolve(path.dirname(__filename), '..', '..')

function resetSurfaceForTest(): void {
  const surface = getToolSurfaceManager() as any
  surface.entries = new Map()
  surface.coreTools = new Set()
  surface.visibleCoreTools = new Set()
}

/** Compile a .py source file to a .pyc next to it using the host interpreter. */
function compilePyc(sourcePath: string): string {
  // py_compile writes to __pycache__/<name>.cpython-XY.pyc
  execFileSync('python3', ['-c', `import py_compile; py_compile.compile(r'${sourcePath}', doraise=True)`], {
    stdio: 'pipe',
  })
  const dir = path.dirname(sourcePath)
  const base = path.basename(sourcePath, '.py')
  const cacheDir = path.join(dir, '__pycache__')
  const candidates = fs.readdirSync(cacheDir).filter((f) => f.startsWith(`${base}.cpython`) && f.endsWith('.pyc'))
  if (candidates.length === 0) throw new Error('py_compile produced no .pyc')
  return path.join(cacheDir, candidates[0])
}

describe('python-decompile plugin', () => {
  let tempDir: string
  let workspaceManager: WorkspaceManager
  let database: DatabaseManager
  const sampleId = `sha256:${'b'.repeat(64)}`

  beforeEach(async () => {
    resetSurfaceForTest()
    tempDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'python-decompile-test-'))
    workspaceManager = new WorkspaceManager(path.join(tempDir, 'workspaces'))
    database = new DatabaseManager(path.join(tempDir, 'test.db'))
    database.insertSample({
      id: sampleId,
      sha256: 'b'.repeat(64),
      md5: 'b'.repeat(32),
      size: 4096,
      file_type: 'Python bytecode',
      created_at: new Date().toISOString(),
      source: 'unit-test',
    })
    const workspace = await workspaceManager.createWorkspace(sampleId)
    // Compile the .py in a temp dir so only the .pyc lands in workspace/original.
    // (resolvePrimarySamplePath returns the alphabetically-first file there.)
    const compileDir = await fsp.mkdtemp(path.join(os.tmpdir(), 'pyc-compile-'))
    const sourcePath = path.join(compileDir, 'sample.py')
    await fsp.writeFile(
      sourcePath,
      'def greet(name):\n    return f"hello {name}"\n\nprint(greet("world"))\n'
    )
    const pycPath = compilePyc(sourcePath)
    await fsp.copyFile(pycPath, path.join(workspace.original, 'sample.pyc'))
    await fsp.rm(compileDir, { recursive: true, force: true })
  })

  afterEach(async () => {
    database.close()
    await fsp.rm(tempDir, { recursive: true, force: true })
  })

  test('registers python.decompile with passive decompilation aspects', () => {
    expect(pythonDecompilePlugin.id).toBe('python-decompile')
    expect(pythonDecompilePlugin.aspects.capabilities).toEqual(
      expect.arrayContaining([
        'python-decompilation',
        'bytecode-disassembly',
        'code-object-recovery',
        'source-recovery',
      ])
    )
    expect(pythonDecompilePlugin.surfaceRules).toEqual(
      expect.objectContaining({ tier: 2, category: 'reverse-engineering' })
    )

    const registered: string[] = []
    const fakeServer = {
      registerTool: (def: { name: string }) => registered.push(def.name),
    }
    const toolNames = pythonDecompilePlugin.register?.(fakeServer as any, {
      workspaceManager,
      database,
      resolvePackagePath: (...segs: string[]) => path.join(PROJECT_ROOT, ...segs),
    } as any)
    expect(registered).toEqual(['python.decompile'])
    expect(toolNames).toEqual(['python.decompile'])
  })

  test('declares passive read-only runtime policy and never executes bytecode', () => {
    expect(pythonDecompileToolDefinition.runtimePolicy).toEqual(
      expect.objectContaining({
        passiveByDefault: true,
        noNetwork: true,
        noMutation: true,
        noLiveExecution: true,
      })
    )
    expect(pythonDecompileToolDefinition.aspects.formats).toEqual(
      expect.arrayContaining(['pyc', 'python', 'python-bytecode'])
    )
  })

  test('decompiles a real .pyc into disassembly and code object metadata', async () => {
    const handler = createPythonDecompileHandler({
      workspaceManager,
      database,
      config: { workers: { static: { pythonPath: 'python3' } } } as any,
      resolvePackagePath: (...segs: string[]) => path.join(PROJECT_ROOT, ...segs),
    } as any)

    const result = await handler({
      sample_id: sampleId,
      mode: 'disasm',
      persist_artifact: false,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    expect(['disasm_only', 'unsupported_version', 'source_recovered']).toContain(data.status)
    expect(data.disassembly).toBeTruthy()
    expect(typeof data.disassembly).toBe('string')
    expect(data.code_object).toBeTruthy()
    expect(data.code_object.co_name).toBe('<module>')
    expect(data.code_object.co_names).toEqual(expect.arrayContaining(['greet', 'print']))
    expect(data.python_version).toBeTruthy()
    expect(data.recommended_next_tools).toEqual(
      expect.arrayContaining(['bytecode.metadata.inspect', 'strings.extract'])
    )
  }, 30_000)

  test('auto mode on a modern .pyc falls back to disasm without crashing', async () => {
    const handler = createPythonDecompileHandler({
      workspaceManager,
      database,
      config: { workers: { static: { pythonPath: 'python3' } } } as any,
      resolvePackagePath: (...segs: string[]) => path.join(PROJECT_ROOT, ...segs),
    } as any)

    const result = await handler({
      sample_id: sampleId,
      mode: 'auto',
      persist_artifact: true,
    })

    expect(result.ok).toBe(true)
    const data = result.data as any
    // Modern Python (3.12+) has no compatible decompiler; must fall back.
    expect(['disasm_only', 'unsupported_version', 'source_recovered']).toContain(data.status)
    expect(data.disassembly).toBeTruthy()
    expect(result.artifacts?.length).toBeGreaterThan(0)
  }, 30_000)

  test('rejects missing sample_id before worker invocation', async () => {
    const handler = createPythonDecompileHandler({
      workspaceManager,
      database,
      config: { workers: { static: { pythonPath: 'python3' } } } as any,
      resolvePackagePath: (...segs: string[]) => path.join(PROJECT_ROOT, ...segs),
    } as any)

    const result = await handler({ mode: 'disasm' } as any)
    expect(result.ok).toBe(false)
    expect(result.errors?.[0]).toMatch(/sample_id|Invalid arguments|required/i)
  })
})
