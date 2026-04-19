/**
 * Unit tests for Policy Guard
 * Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 31.3
 */

import { describe, test, expect, beforeEach, afterEach, jest } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import PolicyGuard, {
  Operation,
  PolicyContext,
  AuditEvent,
  POLICY_RULES,
  DangerousOperation,
} from '../../src/policy-guard'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

describe('PolicyGuard', () => {
  let policyGuard: PolicyGuard
  let testAuditLogPath: string

  beforeEach(() => {
    // Create temporary audit log path for testing
    testAuditLogPath = path.join(__dirname, '../temp', `audit-${Date.now()}.log`)
    policyGuard = new PolicyGuard(testAuditLogPath)
  })

  afterEach(() => {
    // Clean up test audit log
    if (fs.existsSync(testAuditLogPath)) {
      fs.unlinkSync(testAuditLogPath)
    }
    const tempDir = path.dirname(testAuditLogPath)
    if (fs.existsSync(tempDir) && fs.readdirSync(tempDir).length === 0) {
      fs.rmSync(tempDir, { recursive: true, force: true })
    }
  })

  describe('POLICY_RULES configuration', () => {
    test('should define dynamic_execution rule', () => {
      expect(POLICY_RULES.dynamic_execution).toBeDefined()
      expect(POLICY_RULES.dynamic_execution.defaultAllow).toBe(false)
      expect(POLICY_RULES.dynamic_execution.requiresApproval).toBe(true)
      expect(POLICY_RULES.dynamic_execution.requiresIsolation).toBe(true)
      expect(POLICY_RULES.dynamic_execution.auditLevel).toBe('critical')
    })

    test('should define external_upload rule', () => {
      expect(POLICY_RULES.external_upload).toBeDefined()
      expect(POLICY_RULES.external_upload.defaultAllow).toBe(false)
      expect(POLICY_RULES.external_upload.requiresApproval).toBe(true)
      expect(POLICY_RULES.external_upload.auditLevel).toBe('critical')
    })

    test('should define bulk_decompile rule', () => {
      expect(POLICY_RULES.bulk_decompile).toBeDefined()
      expect(POLICY_RULES.bulk_decompile.defaultAllow).toBe(false)
      expect(POLICY_RULES.bulk_decompile.requiresApproval).toBe(true)
      expect(POLICY_RULES.bulk_decompile.maxLimit).toBe(100)
      expect(POLICY_RULES.bulk_decompile.auditLevel).toBe('warning')
    })

    test('should allow static_analysis by default', () => {
      expect(POLICY_RULES.static_analysis).toBeDefined()
      expect(POLICY_RULES.static_analysis.defaultAllow).toBe(true)
      expect(POLICY_RULES.static_analysis.requiresApproval).toBe(false)
    })
  })

  describe('checkPermission', () => {
    describe('dynamic execution', () => {
      test('should deny dynamic execution without approval (Requirement 18.1)', async () => {
        const operation: Operation = {
          type: 'dynamic_execution',
          tool: 'sandbox.execute',
          args: {
            sample_id: 'sha256:test',
            require_user_approval: false,
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(false)
        expect(decision.reason).toContain('requires explicit approval')
        expect(decision.requiresApproval).toBe(true)
      })

      test('should allow dynamic execution with approval token after explicit approval', async () => {
        const operation: Operation = {
          type: 'dynamic_execution',
          tool: 'sandbox.execute',
          args: {
            sample_id: 'sha256:test',
          },
        }

        const firstDecision = await policyGuard.checkPermission(operation, {
          user: 'analyst@example.com',
          sampleId: 'sha256:test',
        })

        expect(firstDecision.allowed).toBe(false)
        expect(firstDecision.approvalToken).toBeTruthy()
        expect(firstDecision.approvalStatus).toBe('pending')

        await policyGuard.approveOperation(firstDecision.approvalToken!, {
          decidedBy: 'reviewer@example.com',
          reason: 'Sandbox execution approved for malware triage',
        })

        const approvedDecision = await policyGuard.checkPermission(
          {
            ...operation,
            args: {
              ...operation.args,
              approval_token: firstDecision.approvalToken,
            },
          },
          {
            user: 'analyst@example.com',
            sampleId: 'sha256:test',
          }
        )

        expect(approvedDecision.allowed).toBe(true)
        expect(approvedDecision.reason).toBe('Approved by user')
        expect(approvedDecision.approvalToken).toBe(firstDecision.approvalToken)
        expect(approvedDecision.approvalStatus).toBe('approved')
      })

      test('should detect sandbox.execute as dynamic execution', async () => {
        const operation: Operation = {
          type: 'static_analysis', // Wrong type, but tool indicates dynamic
          tool: 'sandbox.execute',
          args: {
            sample_id: 'sha256:test',
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(false)
        expect(decision.requiresApproval).toBe(true)
      })
    })

    describe('external upload', () => {
      test('should deny external upload without approval (Requirement 18.3)', async () => {
        const operation: Operation = {
          type: 'dynamic_execution',
          tool: 'sandbox.execute',
          args: {
            sample_id: 'sha256:test',
            backend: 'online_sandbox',
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(false)
        expect(decision.requiresApproval).toBe(true)
      })

      test('should deny operations with external flag', async () => {
        const operation: Operation = {
          type: 'static_analysis',
          tool: 'yara.scan',
          args: {
            sample_id: 'sha256:test',
            external: true,
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(false)
        expect(decision.requiresApproval).toBe(true)
      })

      test('should allow external upload with approval', async () => {
        const operation: Operation = {
          type: 'static_analysis',
          tool: 'upload_to_virustotal',
          args: {
            sample_id: 'sha256:test',
            approved: true,
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(true)
      })
    })

    describe('bulk decompilation', () => {
      test('should deny bulk decompilation exceeding limit (Requirement 18.4)', async () => {
        const operation: Operation = {
          type: 'decompile',
          tool: 'code.function.decompile',
          args: {
            sample_id: 'sha256:test',
            count: 150,
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(false)
        expect(decision.reason).toContain('exceeds maximum limit of 100')
        expect(decision.requiresApproval).toBe(true)
      })

      test('should allow decompilation within limit', async () => {
        const operation: Operation = {
          type: 'decompile',
          tool: 'code.function.decompile',
          args: {
            sample_id: 'sha256:test',
            count: 50,
            approved: true,
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(true)
      })

      test('should check topk parameter for bulk operations', async () => {
        const operation: Operation = {
          type: 'decompile',
          tool: 'code.functions.rank',
          args: {
            sample_id: 'sha256:test',
            topk: 150,
            approved: false, // Explicitly not approved
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(false)
        expect(decision.requiresApproval).toBe(true)
      })

      test('should check addresses array length', async () => {
        const operation: Operation = {
          type: 'decompile',
          tool: 'code.function.decompile',
          args: {
            sample_id: 'sha256:test',
            addresses: new Array(150).fill('0x1000'),
            approved: false, // Explicitly not approved
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(false)
        expect(decision.requiresApproval).toBe(true)
      })
    })

    describe('network access', () => {
      test('should deny network access without approval', async () => {
        const operation: Operation = {
          type: 'dynamic_execution',
          tool: 'sandbox.execute',
          args: {
            sample_id: 'sha256:test',
            network: 'enabled',
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(false)
        expect(decision.requiresApproval).toBe(true)
      })

      test('should deny fake network without approval', async () => {
        const operation: Operation = {
          type: 'dynamic_execution',
          tool: 'sandbox.execute',
          args: {
            sample_id: 'sha256:test',
            network: 'fake',
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(false)
        expect(decision.requiresApproval).toBe(true)
      })
    })

    describe('allowed operations', () => {
      test('should allow static analysis without approval', async () => {
        const operation: Operation = {
          type: 'static_analysis',
          tool: 'pe.fingerprint',
          args: {
            sample_id: 'sha256:test',
            fast: true,
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(true)
        expect(decision.requiresApproval).toBeFalsy()
      })

      test('should allow regular decompilation without approval', async () => {
        const operation: Operation = {
          type: 'decompile',
          tool: 'code.function.decompile',
          args: {
            sample_id: 'sha256:test',
            address: '0x1000',
          },
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(true)
      })
    })

    describe('unknown operations', () => {
      test('should deny unknown operation types', async () => {
        const operation: Operation = {
          type: 'unknown_operation' as any,
          tool: 'unknown.tool',
          args: {},
        }

        const decision = await policyGuard.checkPermission(operation, {})

        expect(decision.allowed).toBe(false)
        expect(decision.reason).toContain('Unknown operation type')
      })
    })
  })

  describe('auditLog', () => {
    test('should write audit log to file (Requirement 18.5, 23.1)', async () => {
      const event: AuditEvent = {
        timestamp: new Date().toISOString(),
        operation: 'sample.ingest',
        sampleId: 'sha256:test123',
        decision: 'allow',
        user: 'test-user',
      }

      await policyGuard.auditLog(event)

      expect(fs.existsSync(testAuditLogPath)).toBe(true)
      const content = fs.readFileSync(testAuditLogPath, 'utf-8')
      expect(content).toContain('sample.ingest')
      expect(content).toContain('sha256:test123')
      expect(content).toContain('allow')
    })

    test('should format audit log as JSON Lines (Requirement 23.4)', async () => {
      const event1: AuditEvent = {
        timestamp: new Date().toISOString(),
        operation: 'pe.fingerprint',
        sampleId: 'sha256:abc',
        decision: 'allow',
      }

      const event2: AuditEvent = {
        timestamp: new Date().toISOString(),
        operation: 'sandbox.execute',
        sampleId: 'sha256:def',
        decision: 'deny',
        reason: 'No approval',
      }

      await policyGuard.auditLog(event1)
      await policyGuard.auditLog(event2)

      const content = fs.readFileSync(testAuditLogPath, 'utf-8')
      const lines = content.trim().split('\n')

      expect(lines).toHaveLength(2)

      const parsed1 = JSON.parse(lines[0])
      expect(parsed1.operation).toBe('pe.fingerprint')
      expect(parsed1.decision).toBe('allow')

      const parsed2 = JSON.parse(lines[1])
      expect(parsed2.operation).toBe('sandbox.execute')
      expect(parsed2.decision).toBe('deny')
      expect(parsed2.reason).toBe('No approval')
    })

    test('should add timestamp if not provided', async () => {
      const event: AuditEvent = {
        timestamp: '', // Empty timestamp
        operation: 'test.operation',
        sampleId: 'sha256:test',
        decision: 'allow',
      }

      await policyGuard.auditLog(event)

      const content = fs.readFileSync(testAuditLogPath, 'utf-8')
      const parsed = JSON.parse(content.trim())

      expect(parsed.timestamp).toBeTruthy()
      expect(new Date(parsed.timestamp).getTime()).toBeGreaterThan(0)
    })

    test('should include metadata in audit log', async () => {
      const event: AuditEvent = {
        timestamp: new Date().toISOString(),
        operation: 'ghidra.analyze',
        sampleId: 'sha256:test',
        decision: 'allow',
        metadata: {
          duration: 120000,
          functionCount: 500,
        },
      }

      await policyGuard.auditLog(event)

      const content = fs.readFileSync(testAuditLogPath, 'utf-8')
      const parsed = JSON.parse(content.trim())

      expect(parsed.metadata).toBeDefined()
      expect(parsed.metadata.duration).toBe(120000)
      expect(parsed.metadata.functionCount).toBe(500)
    })

    test('should handle file write errors gracefully', async () => {
      // Test that audit log doesn't throw even if write fails
      // We'll mock fs.appendFileSync to simulate a write error
      const originalAppendFileSync = fs.appendFileSync
      
      const consoleSpy = jest.spyOn(console, 'error').mockImplementation(() => {})
      
      // Mock appendFileSync to throw an error
      fs.appendFileSync = jest.fn(() => {
        throw new Error('Simulated write error')
      }) as any

      const event: AuditEvent = {
        timestamp: new Date().toISOString(),
        operation: 'test',
        sampleId: 'sha256:test',
        decision: 'allow',
      }

      // Should not throw even if write fails
      await expect(policyGuard.auditLog(event)).resolves.not.toThrow()

      // Error is logged via pino logger (not console.error)

      // Restore mocks
      fs.appendFileSync = originalAppendFileSync
      consoleSpy.mockRestore()
    })
  })

  describe('requireUserApproval', () => {
    test('should create a pending approval request when no approval token is supplied', async () => {
      const operation: DangerousOperation = {
        type: 'dynamic_execution',
        description: 'Execute sample in sandbox',
        risks: ['Malware execution', 'Network access'],
        sampleId: 'sha256:test',
        tool: 'sandbox.execute',
        requestedBy: 'analyst@example.com',
      }

      const result = await policyGuard.requireUserApproval(operation)

      expect(result).toBe(false)

      const pendingRequests = policyGuard.listApprovalRequests('pending')
      expect(pendingRequests).toHaveLength(1)
      expect(pendingRequests[0].operation.sampleId).toBe('sha256:test')
      expect(pendingRequests[0].operation.tool).toBe('sandbox.execute')
    })

    test('should return true when an existing approval token has been approved', async () => {
      const operation: DangerousOperation = {
        type: 'dynamic_execution',
        description: 'Execute sample in sandbox',
        risks: ['Malware execution', 'Network access'],
        sampleId: 'sha256:test',
        tool: 'sandbox.execute',
        requestedBy: 'analyst@example.com',
      }

      const request = await policyGuard.createApprovalRequest(operation)
      await policyGuard.approveOperation(request.token, {
        decidedBy: 'reviewer@example.com',
        reason: 'Approved for investigation',
      })

      const result = await policyGuard.requireUserApproval({
        ...operation,
        approvalToken: request.token,
      })

      expect(result).toBe(true)
    })

    test('should expose approval status for created approvals', async () => {
      const request = await policyGuard.createApprovalRequest({
        type: 'external_upload',
        description: 'Upload sample to remote sandbox',
        risks: ['Transfers sample material to external systems'],
        sampleId: 'sha256:test',
        tool: 'upload_to_virustotal',
        requestedBy: 'analyst@example.com',
      })

      const status = policyGuard.getApprovalStatus(request.token)

      expect(status).toBeDefined()
      expect(status?.token).toBe(request.token)
      expect(status?.status).toBe('pending')
    })
  })

  describe('getAuditLogPath', () => {
    test('should return audit log path', () => {
      const path = policyGuard.getAuditLogPath()
      expect(path).toBe(testAuditLogPath)
    })
  })

  describe('audit log file creation', () => {
    test('should create audit log directory if not exists', () => {
      const newPath = path.join(__dirname, '../temp/nested/dir', `audit-${Date.now()}.log`)
      new PolicyGuard(newPath)

      expect(fs.existsSync(path.dirname(newPath))).toBe(true)

      // Cleanup
      fs.unlinkSync(newPath)
      fs.rmSync(path.dirname(newPath), { recursive: true, force: true })
    })

    test('should create audit log file if not exists', () => {
      expect(fs.existsSync(testAuditLogPath)).toBe(true)
    })
  })

  describe('integration scenarios', () => {
    test('should handle complete workflow: check permission and audit log', async () => {
      const operation: Operation = {
        type: 'dynamic_execution',
        tool: 'sandbox.execute',
        args: {
          sample_id: 'sha256:malware123',
          require_user_approval: false,
        },
      }

      const context: PolicyContext = {
        user: 'analyst@example.com',
        sampleId: 'sha256:malware123',
      }

      // Check permission
      const decision = await policyGuard.checkPermission(operation, context)

      // Log the decision
      await policyGuard.auditLog({
        timestamp: new Date().toISOString(),
        operation: operation.tool,
        user: context.user,
        sampleId: context.sampleId!,
        decision: decision.allowed ? 'allow' : 'deny',
        reason: decision.reason,
      })

      // Verify decision
      expect(decision.allowed).toBe(false)

      // Verify audit log
      const content = fs.readFileSync(testAuditLogPath, 'utf-8')
      const entries = content
        .trim()
        .split('\n')
        .filter(Boolean)
        .map((line) => JSON.parse(line))

      const parsed = entries[entries.length - 1]

      expect(entries.length).toBeGreaterThanOrEqual(2)
      expect(parsed.operation).toBe('sandbox.execute')
      expect(parsed.decision).toBe('deny')
      expect(parsed.user).toBe('analyst@example.com')
      expect(parsed.sampleId).toBe('sha256:malware123')
    })
  })
})
