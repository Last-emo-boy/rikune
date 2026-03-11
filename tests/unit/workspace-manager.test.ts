/**
 * Unit tests for WorkspaceManager
 * Tests directory creation, path generation, and security boundary checks
 */

import { WorkspaceManager } from '../../src/workspace-manager'
import fs from 'fs'
import path from 'path'
import os from 'os'

describe('WorkspaceManager', () => {
  let workspaceManager: WorkspaceManager
  let testRoot: string

  beforeEach(() => {
    // Create a temporary directory for testing
    testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'workspace-test-'))
    workspaceManager = new WorkspaceManager(testRoot)
  })

  afterEach(() => {
    // Clean up test directory
    if (fs.existsSync(testRoot)) {
      fs.rmSync(testRoot, { recursive: true, force: true })
    }
  })

  describe('createWorkspace', () => {
    it('should create workspace with correct bucketed structure', async () => {
      const sampleId = 'sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
      const workspace = await workspaceManager.createWorkspace(sampleId)

      // Check root path structure (ab/cd/<sha256>)
      expect(workspace.root).toMatch(/ab[/\\]cd[/\\]abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890$/)
      
      // Verify all directories exist
      expect(fs.existsSync(workspace.root)).toBe(true)
      expect(fs.existsSync(workspace.original)).toBe(true)
      expect(fs.existsSync(workspace.cache)).toBe(true)
      expect(fs.existsSync(workspace.ghidra)).toBe(true)
      expect(fs.existsSync(workspace.reports)).toBe(true)
    })

    it('should create all required subdirectories', async () => {
      const sampleId = 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
      const workspace = await workspaceManager.createWorkspace(sampleId)

      const subdirs = ['original', 'cache', 'ghidra', 'dotnet', 'reports']
      for (const subdir of subdirs) {
        const subdirPath = path.join(workspace.root, subdir)
        expect(fs.existsSync(subdirPath)).toBe(true)
        expect(fs.statSync(subdirPath).isDirectory()).toBe(true)
      }
    })

    it('should handle uppercase SHA256 in sample ID', async () => {
      const sampleId = 'sha256:ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890'
      const workspace = await workspaceManager.createWorkspace(sampleId)

      // Should normalize to lowercase
      expect(workspace.root).toMatch(/ab[/\\]cd[/\\]abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890$/)
      expect(fs.existsSync(workspace.root)).toBe(true)
    })

    it('should be idempotent - creating same workspace twice should succeed', async () => {
      const sampleId = 'sha256:fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321'
      
      const workspace1 = await workspaceManager.createWorkspace(sampleId)
      const workspace2 = await workspaceManager.createWorkspace(sampleId)

      expect(workspace1.root).toBe(workspace2.root)
      expect(fs.existsSync(workspace1.root)).toBe(true)
    })

    it('should reject invalid sample ID format', async () => {
      const invalidIds = [
        'invalid-format',
        'sha256:',
        'sha256:short',
        'md5:abcdef1234567890abcdef1234567890',
      ]

      for (const invalidId of invalidIds) {
        await expect(workspaceManager.createWorkspace(invalidId)).rejects.toThrow()
      }
    })

    it('should reject invalid SHA256 hash', async () => {
      const invalidHashes = [
        'sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg', // invalid hex
        'sha256:abcdef', // too short
        'sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890extra', // too long
      ]

      for (const invalidHash of invalidHashes) {
        await expect(workspaceManager.createWorkspace(invalidHash)).rejects.toThrow()
      }
    })
  })

  describe('getWorkspace', () => {
    it('should return workspace path for existing workspace', async () => {
      const sampleId = 'sha256:1111111111111111111111111111111111111111111111111111111111111111'
      
      // Create workspace first
      const created = await workspaceManager.createWorkspace(sampleId)
      
      // Get workspace
      const retrieved = await workspaceManager.getWorkspace(sampleId)

      expect(retrieved.root).toBe(created.root)
      expect(retrieved.original).toBe(created.original)
      expect(retrieved.cache).toBe(created.cache)
      expect(retrieved.ghidra).toBe(created.ghidra)
      expect(retrieved.reports).toBe(created.reports)
    })

    it('should throw error for non-existent workspace', async () => {
      const sampleId = 'sha256:9999999999999999999999999999999999999999999999999999999999999999'
      
      await expect(workspaceManager.getWorkspace(sampleId)).rejects.toThrow(
        /Workspace not found/
      )
    })

    it('should reject invalid sample ID format', async () => {
      await expect(workspaceManager.getWorkspace('invalid')).rejects.toThrow()
    })
  })

  describe('normalizePath', () => {
    it('should normalize valid relative paths', () => {
      const workspacePath = path.join(testRoot, 'test-workspace')
      fs.mkdirSync(workspacePath, { recursive: true })

      const normalized = workspaceManager.normalizePath(workspacePath, 'subdir/file.txt')
      
      expect(normalized).toBe(path.join(workspacePath, 'subdir', 'file.txt'))
    })

    it('should allow paths within workspace boundaries', () => {
      const workspacePath = path.join(testRoot, 'test-workspace')
      fs.mkdirSync(workspacePath, { recursive: true })

      const validPaths = [
        'file.txt',
        'subdir/file.txt',
        './file.txt',
        'subdir/../file.txt',
      ]

      for (const validPath of validPaths) {
        expect(() => {
          workspaceManager.normalizePath(workspacePath, validPath)
        }).not.toThrow()
      }
    })

    it('should prevent path traversal attacks', () => {
      const workspacePath = path.join(testRoot, 'test-workspace')
      fs.mkdirSync(workspacePath, { recursive: true })

      const maliciousPaths = [
        '../../../etc/passwd',
        '../../outside.txt',
        '../outside/file.txt',
      ]

      for (const maliciousPath of maliciousPaths) {
        expect(() => {
          workspaceManager.normalizePath(workspacePath, maliciousPath)
        }).toThrow(/Path traversal detected/)
      }
    })

    it('should handle absolute paths that are within boundaries', () => {
      const workspacePath = path.join(testRoot, 'test-workspace')
      fs.mkdirSync(workspacePath, { recursive: true })

      const absolutePath = path.join(workspacePath, 'file.txt')
      const normalized = workspaceManager.normalizePath(workspacePath, absolutePath)

      expect(normalized).toBe(absolutePath)
    })

    it('should reject absolute paths outside boundaries', () => {
      const workspacePath = path.join(testRoot, 'test-workspace')
      fs.mkdirSync(workspacePath, { recursive: true })

      const outsidePath = path.join(testRoot, 'outside', 'file.txt')

      expect(() => {
        workspaceManager.normalizePath(workspacePath, outsidePath)
      }).toThrow(/Path traversal detected/)
    })

    it('should handle complex path traversal attempts', () => {
      const workspacePath = path.join(testRoot, 'test-workspace')
      fs.mkdirSync(workspacePath, { recursive: true })

      const complexPaths = [
        'subdir/../../outside.txt',
        './subdir/../../../etc/passwd',
        'subdir/./../../../etc/passwd',
      ]

      for (const complexPath of complexPaths) {
        expect(() => {
          workspaceManager.normalizePath(workspacePath, complexPath)
        }).toThrow(/Path traversal detected/)
      }
    })
  })

  describe('isWithinBoundaries', () => {
    it('should return true for paths within boundaries', () => {
      const workspacePath = path.join(testRoot, 'test-workspace')
      fs.mkdirSync(workspacePath, { recursive: true })

      const validPaths = [
        'file.txt',
        'subdir/file.txt',
        './file.txt',
      ]

      for (const validPath of validPaths) {
        expect(workspaceManager.isWithinBoundaries(workspacePath, validPath)).toBe(true)
      }
    })

    it('should return false for paths outside boundaries', () => {
      const workspacePath = path.join(testRoot, 'test-workspace')
      fs.mkdirSync(workspacePath, { recursive: true })

      const invalidPaths = [
        '../outside.txt',
        '../../etc/passwd',
        '../../../etc/passwd',
      ]

      for (const invalidPath of invalidPaths) {
        expect(workspaceManager.isWithinBoundaries(workspacePath, invalidPath)).toBe(false)
      }
    })
  })

  describe('getWorkspaceRoot', () => {
    it('should return the workspace root directory', () => {
      const root = workspaceManager.getWorkspaceRoot()
      expect(root).toBe(path.resolve(testRoot))
    })
  })

  describe('bucketing algorithm', () => {
    it('should create different buckets for different SHA256 prefixes', async () => {
      const samples = [
        'sha256:aa00000000000000000000000000000000000000000000000000000000000000',
        'sha256:bb00000000000000000000000000000000000000000000000000000000000000',
        'sha256:cc00000000000000000000000000000000000000000000000000000000000000',
      ]

      const workspaces = await Promise.all(
        samples.map(id => workspaceManager.createWorkspace(id))
      )

      // Verify different bucket directories
      expect(workspaces[0].root).toMatch(/aa[/\\]00/)
      expect(workspaces[1].root).toMatch(/bb[/\\]00/)
      expect(workspaces[2].root).toMatch(/cc[/\\]00/)

      // Verify all exist
      for (const workspace of workspaces) {
        expect(fs.existsSync(workspace.root)).toBe(true)
      }
    })

    it('should use first 4 characters for bucketing', async () => {
      const sampleId = 'sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab'
      const workspace = await workspaceManager.createWorkspace(sampleId)

      // Should create ab/cd/ bucket structure
      expect(workspace.root).toMatch(/ab[/\\]cd[/\\]/)
    })
  })

  describe('workspace root initialization', () => {
    it('should create workspace root if it does not exist', () => {
      const newRoot = path.join(testRoot, 'new-workspace-root')
      expect(fs.existsSync(newRoot)).toBe(false)

      new WorkspaceManager(newRoot)

      expect(fs.existsSync(newRoot)).toBe(true)
    })

    it('should not fail if workspace root already exists', () => {
      const existingRoot = path.join(testRoot, 'existing-root')
      fs.mkdirSync(existingRoot, { recursive: true })

      expect(() => {
        new WorkspaceManager(existingRoot)
      }).not.toThrow()
    })
  })

  describe('cleanup', () => {
    it('should delete workspace directory and all contents', async () => {
      const sampleId = 'sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
      
      // Create workspace with some files
      const workspace = await workspaceManager.createWorkspace(sampleId)
      fs.writeFileSync(path.join(workspace.original, 'sample.exe'), 'test data')
      fs.writeFileSync(path.join(workspace.cache, 'result.json'), '{}')
      
      // Verify workspace exists
      expect(fs.existsSync(workspace.root)).toBe(true)
      expect(fs.existsSync(path.join(workspace.original, 'sample.exe'))).toBe(true)
      
      // Clean up
      await workspaceManager.cleanup(sampleId)
      
      // Verify workspace is deleted
      expect(fs.existsSync(workspace.root)).toBe(false)
    })

    it('should not throw error if workspace does not exist', async () => {
      const sampleId = 'sha256:9999999999999999999999999999999999999999999999999999999999999999'
      
      // Should not throw
      await expect(workspaceManager.cleanup(sampleId)).resolves.not.toThrow()
    })

    it('should handle cleanup of multiple workspaces', async () => {
      const sampleIds = [
        'sha256:1111111111111111111111111111111111111111111111111111111111111111',
        'sha256:2222222222222222222222222222222222222222222222222222222222222222',
        'sha256:3333333333333333333333333333333333333333333333333333333333333333',
      ]
      
      // Create workspaces
      const workspaces = await Promise.all(
        sampleIds.map(id => workspaceManager.createWorkspace(id))
      )
      
      // Verify all exist
      for (const workspace of workspaces) {
        expect(fs.existsSync(workspace.root)).toBe(true)
      }
      
      // Clean up all
      await Promise.all(sampleIds.map(id => workspaceManager.cleanup(id)))
      
      // Verify all deleted
      for (const workspace of workspaces) {
        expect(fs.existsSync(workspace.root)).toBe(false)
      }
    })
  })

  describe('cleanupOldWorkspaces', () => {
    it('should delete workspaces older than retention period', async () => {
      const sampleId = 'sha256:aaaa000000000000000000000000000000000000000000000000000000000000'
      const workspace = await workspaceManager.createWorkspace(sampleId)
      
      // Modify the workspace timestamp to be old (35 days ago)
      const oldTime = Date.now() - (35 * 24 * 60 * 60 * 1000)
      fs.utimesSync(workspace.root, new Date(oldTime), new Date(oldTime))
      
      // Clean up with 30-day retention
      const cleanedCount = await workspaceManager.cleanupOldWorkspaces(30)
      
      expect(cleanedCount).toBe(1)
      expect(fs.existsSync(workspace.root)).toBe(false)
    })

    it('should not delete workspaces within retention period', async () => {
      const sampleId = 'sha256:bbbb000000000000000000000000000000000000000000000000000000000000'
      const workspace = await workspaceManager.createWorkspace(sampleId)
      
      // Workspace is fresh (just created)
      const cleanedCount = await workspaceManager.cleanupOldWorkspaces(30)
      
      expect(cleanedCount).toBe(0)
      expect(fs.existsSync(workspace.root)).toBe(true)
    })

    it('should handle mixed old and new workspaces', async () => {
      // Create old workspace
      const oldSampleId = 'sha256:cccc000000000000000000000000000000000000000000000000000000000000'
      const oldWorkspace = await workspaceManager.createWorkspace(oldSampleId)
      const oldTime = Date.now() - (35 * 24 * 60 * 60 * 1000)
      fs.utimesSync(oldWorkspace.root, new Date(oldTime), new Date(oldTime))
      
      // Create new workspace
      const newSampleId = 'sha256:dddd000000000000000000000000000000000000000000000000000000000000'
      const newWorkspace = await workspaceManager.createWorkspace(newSampleId)
      
      // Clean up
      const cleanedCount = await workspaceManager.cleanupOldWorkspaces(30)
      
      expect(cleanedCount).toBe(1)
      expect(fs.existsSync(oldWorkspace.root)).toBe(false)
      expect(fs.existsSync(newWorkspace.root)).toBe(true)
    })

    it('should clean up empty bucket directories', async () => {
      const sampleId = 'sha256:eeee000000000000000000000000000000000000000000000000000000000000'
      const workspace = await workspaceManager.createWorkspace(sampleId)
      
      // Make workspace old
      const oldTime = Date.now() - (35 * 24 * 60 * 60 * 1000)
      fs.utimesSync(workspace.root, new Date(oldTime), new Date(oldTime))
      
      // Get bucket paths
      const bucket1Path = path.join(testRoot, 'ee')
      const bucket2Path = path.join(bucket1Path, 'ee')
      
      // Verify buckets exist
      expect(fs.existsSync(bucket1Path)).toBe(true)
      expect(fs.existsSync(bucket2Path)).toBe(true)
      
      // Clean up
      await workspaceManager.cleanupOldWorkspaces(30)
      
      // Verify empty buckets are removed
      expect(fs.existsSync(bucket2Path)).toBe(false)
      expect(fs.existsSync(bucket1Path)).toBe(false)
    })

    it('should return 0 if workspace root does not exist', async () => {
      const emptyRoot = path.join(testRoot, 'non-existent')
      const emptyManager = new WorkspaceManager(emptyRoot)
      
      // Delete the root that was auto-created
      fs.rmSync(emptyRoot, { recursive: true, force: true })
      
      const cleanedCount = await emptyManager.cleanupOldWorkspaces(30)
      
      expect(cleanedCount).toBe(0)
    })

    it('should use custom retention period', async () => {
      const sampleId = 'sha256:ffff000000000000000000000000000000000000000000000000000000000000'
      const workspace = await workspaceManager.createWorkspace(sampleId)
      
      // Make workspace 10 days old
      const oldTime = Date.now() - (10 * 24 * 60 * 60 * 1000)
      fs.utimesSync(workspace.root, new Date(oldTime), new Date(oldTime))
      
      // Clean up with 7-day retention (should delete)
      const cleanedCount = await workspaceManager.cleanupOldWorkspaces(7)
      
      expect(cleanedCount).toBe(1)
      expect(fs.existsSync(workspace.root)).toBe(false)
    })

    it('should handle multiple old workspaces in different buckets', async () => {
      const oldSamples = [
        'sha256:1100000000000000000000000000000000000000000000000000000000000000',
        'sha256:2200000000000000000000000000000000000000000000000000000000000000',
        'sha256:3300000000000000000000000000000000000000000000000000000000000000',
      ]
      
      const workspaces = await Promise.all(
        oldSamples.map(id => workspaceManager.createWorkspace(id))
      )
      
      // Make all workspaces old
      const oldTime = Date.now() - (35 * 24 * 60 * 60 * 1000)
      for (const workspace of workspaces) {
        fs.utimesSync(workspace.root, new Date(oldTime), new Date(oldTime))
      }
      
      // Clean up
      const cleanedCount = await workspaceManager.cleanupOldWorkspaces(30)
      
      expect(cleanedCount).toBe(3)
      for (const workspace of workspaces) {
        expect(fs.existsSync(workspace.root)).toBe(false)
      }
    })
  })
})
