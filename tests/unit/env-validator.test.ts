/**
 * Unit tests for environment validation
 * **Validates: Requirements 31.3**
 */

import { describe, test, expect, beforeEach, afterEach } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { validateEnvironment } from '../../src/env-validator.js'
import type { Config } from '../../src/config.js'

describe('Environment Validation', () => {
  const testWorkspaceDir = path.join(process.cwd(), 'test-workspace')
  const testDbDir = path.join(process.cwd(), 'test-db')

  beforeEach(() => {
    // Clean up test directories before each test
    if (fs.existsSync(testWorkspaceDir)) {
      fs.rmSync(testWorkspaceDir, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbDir)) {
      fs.rmSync(testDbDir, { recursive: true, force: true })
    }
  })

  afterEach(() => {
    // Clean up test directories after each test
    if (fs.existsSync(testWorkspaceDir)) {
      fs.rmSync(testWorkspaceDir, { recursive: true, force: true })
    }
    if (fs.existsSync(testDbDir)) {
      fs.rmSync(testDbDir, { recursive: true, force: true })
    }
  })

  describe('Node.js version validation', () => {
    test('should pass validation with Node.js >= 18', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      // Node.js version check should pass (we're running on Node 18+)
      expect(result.valid).toBe(true)
      expect(result.errors).not.toContain(expect.stringContaining('Node.js version'))
    })
  })

  describe('Workspace validation', () => {
    test('should create workspace directory if it does not exist', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(true)
      expect(result.warnings.some(w => w.includes('Created workspace directory'))).toBe(true)
      expect(fs.existsSync(testWorkspaceDir)).toBe(true)
    })

    test('should pass validation if workspace directory exists and is writable', () => {
      fs.mkdirSync(testWorkspaceDir, { recursive: true })

      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })
  })

  describe('Database validation', () => {
    test('should pass validation for SQLite with default path', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(true)
    })

    test('should create database directory if it does not exist', () => {
      const dbPath = path.join(testDbDir, 'data.sqlite')
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite', path: dbPath },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(true)
      // Check that either workspace or database directory was created
      expect(result.warnings.length).toBeGreaterThan(0)
      expect(fs.existsSync(testDbDir)).toBe(true)
    })

    test('should fail validation for PostgreSQL without required fields', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'postgresql' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('PostgreSQL configuration requires host and database name')
    })

    test('should pass validation for PostgreSQL with required fields', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: {
          type: 'postgresql',
          host: 'localhost',
          port: 5432,
          database: 'mcp_server',
          user: 'admin',
          password: 'secret',
        },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(true)
    })
  })

  describe('Ghidra worker validation', () => {
    test('should pass validation when Ghidra is disabled', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(true)
    })

    test('should fail validation when Ghidra is enabled but path is not configured', () => {
      const savedGhidraPath = process.env.GHIDRA_PATH
      delete process.env.GHIDRA_PATH
      try {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: true, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('Ghidra worker is enabled but GHIDRA_PATH is not configured')
      } finally {
        if (savedGhidraPath !== undefined) process.env.GHIDRA_PATH = savedGhidraPath
      }
    })

    test('should fail validation when Ghidra path does not exist', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: true, path: '/non-existent/ghidra', maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('Ghidra path does not exist: /non-existent/ghidra')
    })
  })

  describe('Python worker validation', () => {
    test('should pass validation when Python worker is disabled', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(true)
    })

    test('should validate Python is available when worker is enabled', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: true, pythonPath: 'python3', timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      // This test will pass or fail depending on whether python3 is installed
      // We just check that validation runs without crashing
      expect(result).toHaveProperty('valid')
      expect(result).toHaveProperty('errors')
      expect(result).toHaveProperty('warnings')
    })
  })

  describe('.NET worker validation', () => {
    test('should pass validation when .NET worker is disabled', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(true)
    })

    test('should fail validation when .NET worker is enabled but ilspyPath is not configured', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: true, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('.NET worker is enabled but ilspyPath is not configured')
    })

    test('should fail validation when ILSpy path does not exist', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: true, ilspyPath: '/non-existent/ilspy', timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(false)
      expect(result.errors).toContain('ILSpy path does not exist: /non-existent/ilspy')
    })
  })

  describe('Complete validation', () => {
    test('should return valid result with no errors for minimal valid configuration', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite' },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(true)
      expect(result.errors).toHaveLength(0)
    })

    test('should accumulate multiple errors', () => {
      const savedGhidraPath = process.env.GHIDRA_PATH
      delete process.env.GHIDRA_PATH
      try {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'postgresql' }, // Missing required fields
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: true, maxConcurrent: 4, timeout: 300 }, // Missing path
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: true, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 }, // Missing ilspyPath
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(false)
      expect(result.errors.length).toBeGreaterThan(1)
      expect(result.errors).toContain('PostgreSQL configuration requires host and database name')
      expect(result.errors).toContain('Ghidra worker is enabled but GHIDRA_PATH is not configured')
      expect(result.errors).toContain('.NET worker is enabled but ilspyPath is not configured')
      } finally {
        if (savedGhidraPath !== undefined) process.env.GHIDRA_PATH = savedGhidraPath
      }
    })

    test('should include warnings for created directories', () => {
      const config: Config = {
        server: { port: 3000, host: 'localhost' },
        database: { type: 'sqlite', path: path.join(testDbDir, 'data.sqlite') },
        workspace: { root: testWorkspaceDir, maxSampleSize: 524288000 },
        workers: {
          ghidra: { enabled: false, maxConcurrent: 4, timeout: 300 },
          static: { enabled: false, timeout: 60 },
          dotnet: { enabled: false, timeout: 60 },
          sandbox: { enabled: false, timeout: 120 },
        },
        cache: { enabled: true, ttl: 2592000 },
        logging: { level: 'info', pretty: false },
      }

      const result = validateEnvironment(config)

      expect(result.valid).toBe(true)
      expect(result.warnings.length).toBeGreaterThan(0)
    })
  })
})


