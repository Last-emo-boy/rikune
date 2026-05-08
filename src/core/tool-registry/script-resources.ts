import fs from 'fs/promises'
import type { ResourceRegistrar } from '../registrar.js'
import {
  listScriptResourceEntries,
  resolveScriptResourcePath,
  type ScriptResourceResolveOptions,
} from './script-resource-manifest.js'

export function registerScriptResources(
  server: ResourceRegistrar,
  options: ScriptResourceResolveOptions = {}
): void {
  for (const entry of listScriptResourceEntries()) {
    const absPath = resolveScriptResourcePath(entry, options)
    if (!absPath) continue

    server.registerResource(
      {
        uri: entry.uri,
        name: entry.name,
        description: entry.description,
        mimeType: entry.mimeType,
      },
      async () => {
        const text = await fs.readFile(absPath, 'utf8')
        return { uri: entry.uri, mimeType: entry.mimeType, text }
      }
    )
  }
}
