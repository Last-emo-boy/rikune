/**
 * Workspace Manager
 * Manages sample storage with SHA256-based bucketed directories
 * Implements path normalization and security boundary checks
 * Optimized for file I/O performance
 */

import fs from 'fs'
import fsPromises from 'fs/promises'
import path from 'path'
import type { WorkspacePath } from './types.js'

/**
 * WorkspaceManager handles creation and management of sample workspaces
 * Each workspace is organized in a bucketed directory structure based on SHA256
 * 
 * Performance optimizations (Requirement 26.3):
 * - Async file operations where possible
 * - Cached workspace path lookups
 * - Batch directory creation
 */
export class WorkspaceManager {
  private workspaceRoot: string
  private workspacePathCache: Map<string, WorkspacePath> = new Map()
  private readonly CACHE_SIZE_LIMIT = 1000

  constructor(workspaceRoot: string) {
    this.workspaceRoot = path.resolve(workspaceRoot)
    this.ensureWorkspaceRoot()
  }

  /**
   * Ensure workspace root directory exists
   */
  private ensureWorkspaceRoot(): void {
    if (!fs.existsSync(this.workspaceRoot)) {
      fs.mkdirSync(this.workspaceRoot, { recursive: true })
    }
  }

  /**
   * Create workspace directory structure for a sample
   * Uses SHA256-based bucketing: workspaces/ab/cd/<sha256>/
   * 
   * Requirements: 19.1, 19.2, 26.3 (file I/O optimization)
   * 
   * Optimizations:
   * - Async directory creation
   * - Cached workspace paths
   * - Batch subdirectory creation
   * 
   * @param sampleId - Sample ID in format "sha256:<hex>"
   * @returns WorkspacePath with all subdirectory paths
   */
  public async createWorkspace(sampleId: string): Promise<WorkspacePath> {
    const sha256 = this.extractSha256(sampleId)
    
    // Check cache first (Requirement 26.3)
    const cachedPath = this.workspacePathCache.get(sha256)
    if (cachedPath && fs.existsSync(cachedPath.root)) {
      return cachedPath
    }

    const workspacePath = this.generateWorkspacePath(sha256)

    // Create directory structure asynchronously
    const subdirs = ['original', 'cache', 'ghidra', 'dotnet', 'reports']
    
    // Create root workspace directory
    await fsPromises.mkdir(workspacePath.root, { recursive: true })

    // Create all subdirectories in parallel (Requirement 26.3)
    await Promise.all(
      subdirs.map(subdir => 
        fsPromises.mkdir(path.join(workspacePath.root, subdir), { recursive: true })
      )
    )

    // Cache the workspace path
    this.cacheWorkspacePath(sha256, workspacePath)

    return workspacePath
  }

  /**
   * Get workspace path for an existing sample
   * 
   * Requirements: 26.3 (file I/O optimization - cached lookups)
   * 
   * @param sampleId - Sample ID in format "sha256:<hex>"
   * @returns WorkspacePath with all subdirectory paths
   */
  public async getWorkspace(sampleId: string): Promise<WorkspacePath> {
    const sha256 = this.extractSha256(sampleId)
    
    // Check cache first (Requirement 26.3)
    const cachedPath = this.workspacePathCache.get(sha256)
    if (cachedPath) {
      return cachedPath
    }

    const workspacePath = this.generateWorkspacePath(sha256)

    // Verify workspace exists
    if (!fs.existsSync(workspacePath.root)) {
      throw new Error(`Workspace not found for sample: ${sampleId}`)
    }

    // Cache the workspace path
    this.cacheWorkspacePath(sha256, workspacePath)

    return workspacePath
  }

  /**
   * Cache workspace path for faster lookups
   * Implements LRU eviction when cache size limit is reached
   * 
   * Requirements: 26.3 (file I/O optimization)
   * 
   * @param sha256 - SHA256 hash
   * @param workspacePath - Workspace path to cache
   */
  private cacheWorkspacePath(sha256: string, workspacePath: WorkspacePath): void {
    // Evict oldest entry if cache is full
    if (this.workspacePathCache.size >= this.CACHE_SIZE_LIMIT) {
      const firstKey = this.workspacePathCache.keys().next().value
      if (firstKey) {
        this.workspacePathCache.delete(firstKey)
      }
    }

    this.workspacePathCache.set(sha256, workspacePath)
  }

  /**
   * Clear workspace path cache
   * Useful after cleanup operations
   */
  public clearWorkspaceCache(): void {
    this.workspacePathCache.clear()
  }

  /**
   * Extract SHA256 hash from sample ID
   * 
   * @param sampleId - Sample ID in format "sha256:<hex>"
   * @returns SHA256 hash string
   */
  private extractSha256(sampleId: string): string {
    if (!sampleId.startsWith('sha256:')) {
      throw new Error(`Invalid sample ID format: ${sampleId}`)
    }

    const sha256 = sampleId.substring(7)
    
    // Validate SHA256 format (64 hex characters)
    if (!/^[a-f0-9]{64}$/i.test(sha256)) {
      throw new Error(`Invalid SHA256 hash: ${sha256}`)
    }

    return sha256.toLowerCase()
  }

  /**
   * Generate bucketed workspace path from SHA256
   * Structure: workspaces/ab/cd/<sha256>/
   * 
   * @param sha256 - SHA256 hash string
   * @returns WorkspacePath object with all subdirectory paths
   */
  private generateWorkspacePath(sha256: string): WorkspacePath {
    // Use first 2 and next 2 characters for bucketing
    const bucket1 = sha256.substring(0, 2)
    const bucket2 = sha256.substring(2, 4)

    const root = path.join(this.workspaceRoot, bucket1, bucket2, sha256)

    return {
      root,
      original: path.join(root, 'original'),
      cache: path.join(root, 'cache'),
      ghidra: path.join(root, 'ghidra'),
      reports: path.join(root, 'reports'),
    }
  }

  /**
   * Normalize and validate a path is within workspace boundaries
   * Prevents path traversal attacks
   * 
   * Requirement: 29.5
   * 
   * @param workspacePath - Base workspace path
   * @param relativePath - Relative path to validate
   * @returns Normalized absolute path
   * @throws Error if path is outside workspace boundaries
   */
  public normalizePath(workspacePath: string, relativePath: string): string {
    // Resolve to absolute path
    const absolutePath = path.resolve(workspacePath, relativePath)
    const normalizedPath = path.normalize(absolutePath)

    // Check if path is within workspace boundaries
    const workspaceAbsolute = path.resolve(workspacePath)
    
    if (!normalizedPath.startsWith(workspaceAbsolute + path.sep) && 
        normalizedPath !== workspaceAbsolute) {
      throw new Error(
        `Path traversal detected: ${relativePath} is outside workspace boundaries`
      )
    }

    return normalizedPath
  }

  /**
   * Check if a path is within workspace boundaries
   * 
   * Requirement: 29.5
   * 
   * @param workspacePath - Base workspace path
   * @param targetPath - Path to check
   * @returns true if path is within boundaries
   */
  public isWithinBoundaries(workspacePath: string, targetPath: string): boolean {
    try {
      this.normalizePath(workspacePath, targetPath)
      return true
    } catch {
      return false
    }
  }

  /**
   * Get workspace root directory
   */
  public getWorkspaceRoot(): string {
    return this.workspaceRoot
  }

  /**
   * Clean up workspace for a sample
   * Deletes all subdirectories and files
   * 
   * Requirements: 19.6, 26.3 (file I/O optimization)
   * 
   * @param sampleId - Sample ID in format "sha256:<hex>"
   */
  public async cleanup(sampleId: string): Promise<void> {
    const sha256 = this.extractSha256(sampleId)
    const workspacePath = this.generateWorkspacePath(sha256)

    // Remove from cache
    this.workspacePathCache.delete(sha256)

    // Check if workspace exists
    if (!fs.existsSync(workspacePath.root)) {
      // Workspace doesn't exist, nothing to clean up
      return
    }

    // Delete the entire workspace directory recursively (async)
    await fsPromises.rm(workspacePath.root, { recursive: true, force: true })
  }

  /**
   * Clean up old workspaces based on retention policy
   * Deletes workspaces older than the specified number of days
   * 
   * Requirements: 操作约束 6 (30-day retention policy), 26.3 (file I/O optimization)
   * 
   * Optimizations:
   * - Async file operations
   * - Parallel directory scanning
   * - Batch deletion
   * 
   * @param retentionDays - Number of days to retain workspaces (default: 30)
   * @returns Number of workspaces cleaned up
   */
  public async cleanupOldWorkspaces(retentionDays: number = 30): Promise<number> {
    const cutoffTime = Date.now() - (retentionDays * 24 * 60 * 60 * 1000)
    let cleanedCount = 0

    // Traverse the bucketed directory structure
    if (!fs.existsSync(this.workspaceRoot)) {
      return 0
    }

    const bucket1Dirs = await fsPromises.readdir(this.workspaceRoot)
    
    // Process bucket1 directories in parallel (Requirement 26.3)
    const cleanupPromises: Promise<number>[] = []

    for (const bucket1 of bucket1Dirs) {
      const bucket1Path = path.join(this.workspaceRoot, bucket1)
      
      cleanupPromises.push(
        (async () => {
          let localCleanedCount = 0

          try {
            // Skip if not a directory
            const bucket1Stats = await fsPromises.stat(bucket1Path)
            if (!bucket1Stats.isDirectory()) {
              return 0
            }

            const bucket2Dirs = await fsPromises.readdir(bucket1Path)
            
            for (const bucket2 of bucket2Dirs) {
              const bucket2Path = path.join(bucket1Path, bucket2)
              
              try {
                // Skip if not a directory
                const bucket2Stats = await fsPromises.stat(bucket2Path)
                if (!bucket2Stats.isDirectory()) {
                  continue
                }

                const workspaceDirs = await fsPromises.readdir(bucket2Path)
                
                for (const workspaceDir of workspaceDirs) {
                  const workspacePath = path.join(bucket2Path, workspaceDir)
                  
                  try {
                    // Skip if not a directory
                    const workspaceStats = await fsPromises.stat(workspacePath)
                    if (!workspaceStats.isDirectory()) {
                      continue
                    }

                    // Check modification time
                    if (workspaceStats.mtimeMs < cutoffTime) {
                      // Delete old workspace
                      await fsPromises.rm(workspacePath, { recursive: true, force: true })
                      localCleanedCount++
                      
                      // Remove from cache if present
                      this.workspacePathCache.delete(workspaceDir)
                    }
                  } catch {
                    // Skip workspace on error
                    continue
                  }
                }

                // Clean up empty bucket2 directories
                const remainingFiles = await fsPromises.readdir(bucket2Path)
                if (remainingFiles.length === 0) {
                  await fsPromises.rmdir(bucket2Path)
                }
              } catch {
                // Skip bucket2 on error
                continue
              }
            }

            // Clean up empty bucket1 directories
            const remainingFiles = await fsPromises.readdir(bucket1Path)
            if (remainingFiles.length === 0) {
              await fsPromises.rmdir(bucket1Path)
            }
          } catch {
            // Skip bucket1 on error
          }

          return localCleanedCount
        })()
      )
    }

    // Wait for all cleanup operations to complete
    const results = await Promise.all(cleanupPromises)
    cleanedCount = results.reduce((sum, count) => sum + count, 0)

    return cleanedCount
  }

  /**
   * Get workspace statistics for monitoring
   * Requirements: 26.3 (file I/O optimization)
   * 
   * @returns Object with workspace statistics
   */
  public async getWorkspaceStats(): Promise<{
    totalWorkspaces: number;
    totalSizeBytes: number;
    oldestWorkspaceAge: number;
  }> {
    let totalWorkspaces = 0
    let totalSizeBytes = 0
    let oldestMtime = Date.now()

    if (!fs.existsSync(this.workspaceRoot)) {
      return { totalWorkspaces: 0, totalSizeBytes: 0, oldestWorkspaceAge: 0 }
    }

    const bucket1Dirs = await fsPromises.readdir(this.workspaceRoot)

    for (const bucket1 of bucket1Dirs) {
      const bucket1Path = path.join(this.workspaceRoot, bucket1)
      
      try {
        const bucket1Stats = await fsPromises.stat(bucket1Path)
        if (!bucket1Stats.isDirectory()) {
          continue
        }

        const bucket2Dirs = await fsPromises.readdir(bucket1Path)
        
        for (const bucket2 of bucket2Dirs) {
          const bucket2Path = path.join(bucket1Path, bucket2)
          
          try {
            const bucket2Stats = await fsPromises.stat(bucket2Path)
            if (!bucket2Stats.isDirectory()) {
              continue
            }

            const workspaceDirs = await fsPromises.readdir(bucket2Path)
            
            for (const workspaceDir of workspaceDirs) {
              const workspacePath = path.join(bucket2Path, workspaceDir)
              
              try {
                const workspaceStats = await fsPromises.stat(workspacePath)
                if (!workspaceStats.isDirectory()) {
                  continue
                }

                totalWorkspaces++
                
                // Get directory size (approximate)
                const size = await this.getDirectorySize(workspacePath)
                totalSizeBytes += size

                // Track oldest workspace
                if (workspaceStats.mtimeMs < oldestMtime) {
                  oldestMtime = workspaceStats.mtimeMs
                }
              } catch {
                continue
              }
            }
          } catch {
            continue
          }
        }
      } catch {
        continue
      }
    }

    const oldestWorkspaceAge = Math.floor((Date.now() - oldestMtime) / (24 * 60 * 60 * 1000))

    return {
      totalWorkspaces,
      totalSizeBytes,
      oldestWorkspaceAge
    }
  }

  /**
   * Get approximate size of a directory
   * Requirements: 26.3 (file I/O optimization)
   * 
   * @param dirPath - Directory path
   * @returns Size in bytes
   */
  private async getDirectorySize(dirPath: string): Promise<number> {
    let totalSize = 0

    try {
      const entries = await fsPromises.readdir(dirPath, { withFileTypes: true })

      for (const entry of entries) {
        const entryPath = path.join(dirPath, entry.name)

        if (entry.isDirectory()) {
          totalSize += await this.getDirectorySize(entryPath)
        } else if (entry.isFile()) {
          const stats = await fsPromises.stat(entryPath)
          totalSize += stats.size
        }
      }
    } catch {
      // Ignore errors
    }

    return totalSize
  }
}
