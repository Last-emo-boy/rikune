import fs from 'fs/promises'
import path from 'path'
import { fileURLToPath } from 'url'
import type { ResourceRegistrar } from '../registrar.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const PROJECT_ROOT = path.resolve(__dirname, '../..')

interface ScriptEntry {
  uri: string
  name: string
  description: string
  mimeType: string
  filePath: string
}

const FRIDA_SCRIPTS: ScriptEntry[] = [
  { uri: 'script://frida/anti_debug_bypass', name: 'Frida: Anti-Debug Bypass', description: 'Bypass common anti-debugging techniques', mimeType: 'application/javascript', filePath: 'src/plugins/frida/scripts/anti_debug_bypass.js' },
  { uri: 'script://frida/api_trace', name: 'Frida: API Trace', description: 'Trace Windows API calls at runtime', mimeType: 'application/javascript', filePath: 'src/plugins/frida/scripts/api_trace.js' },
  { uri: 'script://frida/crypto_finder', name: 'Frida: Crypto Finder', description: 'Detect cryptographic operations at runtime', mimeType: 'application/javascript', filePath: 'src/plugins/frida/scripts/crypto_finder.js' },
  { uri: 'script://frida/file_registry_monitor', name: 'Frida: File/Registry Monitor', description: 'Monitor file and registry access', mimeType: 'application/javascript', filePath: 'src/plugins/frida/scripts/file_registry_monitor.js' },
  { uri: 'script://frida/string_decoder', name: 'Frida: String Decoder', description: 'Decode obfuscated strings at runtime', mimeType: 'application/javascript', filePath: 'src/plugins/frida/scripts/string_decoder.js' },
  { uri: 'script://frida/android_crypto_trace', name: 'Frida: Android Crypto Trace', description: 'Trace Android crypto API calls', mimeType: 'application/javascript', filePath: 'src/plugins/android/scripts/android_crypto_trace.js' },
  { uri: 'script://frida/android_root_bypass', name: 'Frida: Android Root Bypass', description: 'Bypass Android root detection', mimeType: 'application/javascript', filePath: 'src/plugins/android/scripts/android_root_bypass.js' },
  { uri: 'script://frida/android_ssl_bypass', name: 'Frida: Android SSL Bypass', description: 'Bypass Android SSL pinning', mimeType: 'application/javascript', filePath: 'src/plugins/android/scripts/android_ssl_bypass.js' },
]

const GHIDRA_SCRIPTS: ScriptEntry[] = [
  { uri: 'script://ghidra/AnalyzeCrossReferences', name: 'Ghidra: Analyze Cross References', description: 'Extract cross-reference data from Ghidra project', mimeType: 'text/x-java-source', filePath: 'src/plugins/ghidra/scripts/AnalyzeCrossReferences.java' },
  { uri: 'script://ghidra/DecompileFunction', name: 'Ghidra: Decompile Function (Java)', description: 'Decompile specific function via Ghidra headless', mimeType: 'text/x-java-source', filePath: 'src/plugins/ghidra/scripts/DecompileFunction.java' },
  { uri: 'script://ghidra/ExtractCFG', name: 'Ghidra: Extract CFG (Java)', description: 'Extract control flow graph from Ghidra', mimeType: 'text/x-java-source', filePath: 'src/plugins/ghidra/scripts/ExtractCFG.java' },
  { uri: 'script://ghidra/ExtractFunctions', name: 'Ghidra: Extract Functions (Java)', description: 'List all functions from Ghidra project', mimeType: 'text/x-java-source', filePath: 'src/plugins/ghidra/scripts/ExtractFunctions.java' },
  { uri: 'script://ghidra/SearchFunctionReferences', name: 'Ghidra: Search Function References', description: 'Search for function references in Ghidra', mimeType: 'text/x-java-source', filePath: 'src/plugins/ghidra/scripts/SearchFunctionReferences.java' },
  { uri: 'script://ghidra/DecompileFunction_py', name: 'Ghidra: Decompile Function (Python)', description: 'Decompile function via Ghidra Python', mimeType: 'text/x-python', filePath: 'src/plugins/ghidra/scripts/DecompileFunction.py' },
  { uri: 'script://ghidra/ExtractCFG_py', name: 'Ghidra: Extract CFG (Python)', description: 'Extract CFG via Ghidra Python', mimeType: 'text/x-python', filePath: 'src/plugins/ghidra/scripts/ExtractCFG.py' },
  { uri: 'script://ghidra/ExtractFunctions_py', name: 'Ghidra: Extract Functions (Python)', description: 'List functions via Ghidra Python', mimeType: 'text/x-python', filePath: 'src/plugins/ghidra/scripts/ExtractFunctions.py' },
]

export function registerScriptResources(server: ResourceRegistrar): void {
  for (const entry of [...FRIDA_SCRIPTS, ...GHIDRA_SCRIPTS]) {
    const absPath = path.join(PROJECT_ROOT, entry.filePath)
    server.registerResource(
      { uri: entry.uri, name: entry.name, description: entry.description, mimeType: entry.mimeType },
      async () => {
        const text = await fs.readFile(absPath, 'utf8')
        return { uri: entry.uri, mimeType: entry.mimeType, text }
      },
    )
  }
}
