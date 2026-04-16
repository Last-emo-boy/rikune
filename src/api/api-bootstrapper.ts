import type { MCPServer } from '../core/server.js'
import type { DatabaseManager } from '../database.js'
import type { WorkspaceManager } from '../workspace-manager.js'
import type { StorageManager } from '../storage/storage-manager.js'
import type { FileServer } from './file-server.js'

export interface ApiBootstrapper {
  bootstrap(context: {
    server: MCPServer
    database: DatabaseManager
    workspaceManager: WorkspaceManager
    storageManager: StorageManager
    fileServer: FileServer
  }): Promise<void> | void
}
