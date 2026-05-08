import fs from 'fs'
import path from 'path'

export interface ScriptResourceEntry {
  uri: string
  name: string
  description: string
  mimeType: string
  repoRelativePath: string
  distRelativePath: string
}

export interface ScriptResourceResolveOptions {
  resourceRoot?: string | null
  entrypointDir?: string
  cwd?: string
}

const FRIDA_AND_ANDROID_SCRIPT_RESOURCES: ScriptResourceEntry[] = [
  {
    uri: 'script://frida/anti_debug_bypass',
    name: 'Frida: Anti-Debug Bypass',
    description: 'Bypass common anti-debugging techniques',
    mimeType: 'application/javascript',
    repoRelativePath: 'src/plugins/frida/scripts/anti_debug_bypass.js',
    distRelativePath: 'resources/scripts/frida/anti_debug_bypass.js',
  },
  {
    uri: 'script://frida/api_trace',
    name: 'Frida: API Trace',
    description: 'Trace Windows API calls at runtime',
    mimeType: 'application/javascript',
    repoRelativePath: 'src/plugins/frida/scripts/api_trace.js',
    distRelativePath: 'resources/scripts/frida/api_trace.js',
  },
  {
    uri: 'script://frida/crypto_finder',
    name: 'Frida: Crypto Finder',
    description: 'Detect cryptographic operations at runtime',
    mimeType: 'application/javascript',
    repoRelativePath: 'src/plugins/frida/scripts/crypto_finder.js',
    distRelativePath: 'resources/scripts/frida/crypto_finder.js',
  },
  {
    uri: 'script://frida/file_registry_monitor',
    name: 'Frida: File/Registry Monitor',
    description: 'Monitor file and registry access',
    mimeType: 'application/javascript',
    repoRelativePath: 'src/plugins/frida/scripts/file_registry_monitor.js',
    distRelativePath: 'resources/scripts/frida/file_registry_monitor.js',
  },
  {
    uri: 'script://frida/string_decoder',
    name: 'Frida: String Decoder',
    description: 'Decode obfuscated strings at runtime',
    mimeType: 'application/javascript',
    repoRelativePath: 'src/plugins/frida/scripts/string_decoder.js',
    distRelativePath: 'resources/scripts/frida/string_decoder.js',
  },
  {
    uri: 'script://frida/android_crypto_trace',
    name: 'Frida: Android Crypto Trace',
    description: 'Trace Android crypto API calls',
    mimeType: 'application/javascript',
    repoRelativePath: 'src/plugins/android/scripts/android_crypto_trace.js',
    distRelativePath: 'resources/scripts/android/android_crypto_trace.js',
  },
  {
    uri: 'script://frida/android_root_bypass',
    name: 'Frida: Android Root Bypass',
    description: 'Bypass Android root detection',
    mimeType: 'application/javascript',
    repoRelativePath: 'src/plugins/android/scripts/android_root_bypass.js',
    distRelativePath: 'resources/scripts/android/android_root_bypass.js',
  },
  {
    uri: 'script://frida/android_ssl_bypass',
    name: 'Frida: Android SSL Bypass',
    description: 'Bypass Android SSL pinning',
    mimeType: 'application/javascript',
    repoRelativePath: 'src/plugins/android/scripts/android_ssl_bypass.js',
    distRelativePath: 'resources/scripts/android/android_ssl_bypass.js',
  },
]

const GHIDRA_SCRIPT_RESOURCES: ScriptResourceEntry[] = [
  {
    uri: 'script://ghidra/AnalyzeCrossReferences',
    name: 'Ghidra: Analyze Cross References',
    description: 'Extract cross-reference data from Ghidra project',
    mimeType: 'text/x-java-source',
    repoRelativePath: 'src/plugins/ghidra/scripts/AnalyzeCrossReferences.java',
    distRelativePath: 'resources/scripts/ghidra/AnalyzeCrossReferences.java',
  },
  {
    uri: 'script://ghidra/DecompileFunction',
    name: 'Ghidra: Decompile Function (Java)',
    description: 'Decompile specific function via Ghidra headless',
    mimeType: 'text/x-java-source',
    repoRelativePath: 'src/plugins/ghidra/scripts/DecompileFunction.java',
    distRelativePath: 'resources/scripts/ghidra/DecompileFunction.java',
  },
  {
    uri: 'script://ghidra/ExtractCFG',
    name: 'Ghidra: Extract CFG (Java)',
    description: 'Extract control flow graph from Ghidra',
    mimeType: 'text/x-java-source',
    repoRelativePath: 'src/plugins/ghidra/scripts/ExtractCFG.java',
    distRelativePath: 'resources/scripts/ghidra/ExtractCFG.java',
  },
  {
    uri: 'script://ghidra/ExtractFunctions',
    name: 'Ghidra: Extract Functions (Java)',
    description: 'List all functions from Ghidra project',
    mimeType: 'text/x-java-source',
    repoRelativePath: 'src/plugins/ghidra/scripts/ExtractFunctions.java',
    distRelativePath: 'resources/scripts/ghidra/ExtractFunctions.java',
  },
  {
    uri: 'script://ghidra/SearchFunctionReferences',
    name: 'Ghidra: Search Function References',
    description: 'Search for function references in Ghidra',
    mimeType: 'text/x-java-source',
    repoRelativePath: 'src/plugins/ghidra/scripts/SearchFunctionReferences.java',
    distRelativePath: 'resources/scripts/ghidra/SearchFunctionReferences.java',
  },
  {
    uri: 'script://ghidra/DecompileFunction_py',
    name: 'Ghidra: Decompile Function (Python)',
    description: 'Decompile function via Ghidra Python',
    mimeType: 'text/x-python',
    repoRelativePath: 'src/plugins/ghidra/scripts/DecompileFunction.py',
    distRelativePath: 'resources/scripts/ghidra/DecompileFunction.py',
  },
  {
    uri: 'script://ghidra/ExtractCFG_py',
    name: 'Ghidra: Extract CFG (Python)',
    description: 'Extract CFG via Ghidra Python',
    mimeType: 'text/x-python',
    repoRelativePath: 'src/plugins/ghidra/scripts/ExtractCFG.py',
    distRelativePath: 'resources/scripts/ghidra/ExtractCFG.py',
  },
  {
    uri: 'script://ghidra/ExtractFunctions_py',
    name: 'Ghidra: Extract Functions (Python)',
    description: 'List functions via Ghidra Python',
    mimeType: 'text/x-python',
    repoRelativePath: 'src/plugins/ghidra/scripts/ExtractFunctions.py',
    distRelativePath: 'resources/scripts/ghidra/ExtractFunctions.py',
  },
]

export const SCRIPT_RESOURCE_ENTRIES: ScriptResourceEntry[] = [
  ...FRIDA_AND_ANDROID_SCRIPT_RESOURCES,
  ...GHIDRA_SCRIPT_RESOURCES,
]

const DEFAULT_ENTRYPOINT_DIR = process.argv[1]
  ? path.dirname(path.resolve(process.argv[1]))
  : process.cwd()

function normalizeRoot(root: string | null | undefined): string | null {
  if (!root) {
    return null
  }
  const resolved = path.resolve(root)
  return fs.existsSync(resolved) ? resolved : null
}

function findProjectRoot(startDir: string): string | null {
  let current = path.resolve(startDir)
  while (true) {
    if (
      fs.existsSync(path.join(current, 'package.json')) &&
      (fs.existsSync(path.join(current, 'src', 'plugins')) ||
        fs.existsSync(path.join(current, 'dist', 'resources', 'scripts')))
    ) {
      return current
    }

    const parent = path.dirname(current)
    if (parent === current) {
      return null
    }
    current = parent
  }
}

export function listScriptResourceEntries(): ScriptResourceEntry[] {
  return [...SCRIPT_RESOURCE_ENTRIES]
}

export function resolveScriptResourcePath(
  entry: ScriptResourceEntry,
  options: ScriptResourceResolveOptions = {}
): string | null {
  const entrypointDir = path.resolve(options.entrypointDir ?? DEFAULT_ENTRYPOINT_DIR)
  const cwd = path.resolve(options.cwd ?? process.cwd())
  const explicitRoot = normalizeRoot(options.resourceRoot ?? process.env.RIKUNE_RESOURCE_ROOT)
  const packageRoot =
    normalizeRoot(findProjectRoot(entrypointDir)) ??
    normalizeRoot(findProjectRoot(cwd)) ??
    normalizeRoot(path.resolve(entrypointDir, '..'))

  const roots = [
    explicitRoot,
    packageRoot,
    normalizeRoot(entrypointDir),
    normalizeRoot(path.resolve(entrypointDir, '..')),
  ].filter((root): root is string => Boolean(root))

  const candidates = roots.flatMap((root) => [
    path.join(root, entry.repoRelativePath),
    path.join(root, entry.distRelativePath),
  ])

  for (const candidate of new Set(candidates)) {
    if (fs.existsSync(candidate)) {
      return candidate
    }
  }

  return null
}
