/**
 * Policy Guard Component
 * Enforces authorization rules for dangerous operations
 * Requirements: 18.1, 18.2, 18.3, 18.4
 */

import { randomUUID } from 'crypto'
import fs from 'fs'
import { logger } from '../logger.js'
import path from 'path'

// ============================================================================
// Types
// ============================================================================

/**
 * Operation types that can be checked by Policy Guard
 */
export type OperationType =
  | 'static_analysis'
  | 'decompile'
  | 'dynamic_execution'
  | 'network_access'
  | 'external_upload'
  | 'bulk_decompile'

/**
 * Operation to be checked
 */
export interface Operation {
  type: OperationType
  tool: string
  args: Record<string, unknown>
}

/**
 * Context for policy decision
 */
export interface PolicyContext {
  user?: string
  sampleId?: string
  timestamp?: string
}

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired'

/**
 * Policy decision result
 */
export interface PolicyDecision {
  allowed: boolean
  reason?: string
  requiresApproval?: boolean
  approvalToken?: string
  approvalStatus?: ApprovalStatus
}

/**
 * Dangerous operation requiring approval
 */
export interface DangerousOperation {
  type: string
  description: string
  risks: string[]
  sampleId: string
  tool?: string
  requestedBy?: string
  approvalToken?: string
}

export interface ApprovalRecord {
  token: string
  status: ApprovalStatus
  operation: DangerousOperation
  requestedAt: string
  expiresAt: string
  decidedAt?: string
  decidedBy?: string
  reason?: string
  operationKey: string
}

export interface ApprovalDecisionOptions {
  decidedBy?: string
  reason?: string
}

export interface PolicyGuardOptions {
  approvalTtlMs?: number
}

/**
 * Audit event for logging
 */
export interface AuditEvent {
  timestamp: string
  operation: string
  user?: string
  sampleId: string
  decision: 'allow' | 'deny'
  reason?: string
  metadata?: Record<string, unknown>
}

/**
 * Policy rule configuration
 */
export interface PolicyRule {
  defaultAllow: boolean
  requiresApproval: boolean
  requiresIsolation?: boolean
  auditLevel: 'info' | 'warning' | 'critical'
  maxLimit?: number
}

// ============================================================================
// Policy Rules Configuration
// ============================================================================

/**
 * Policy rules for different operation types
 * Requirements: 18.1, 18.2, 18.3, 18.4
 */
export const POLICY_RULES: Record<string, PolicyRule> = {
  // Requirement 18.1: Dynamic execution requires approval
  dynamic_execution: {
    defaultAllow: false,
    requiresApproval: true,
    requiresIsolation: true,
    auditLevel: 'critical',
  },

  // Requirement 18.3: External upload requires approval
  external_upload: {
    defaultAllow: false,
    requiresApproval: true,
    auditLevel: 'critical',
  },

  // Requirement 18.4: Bulk decompilation requires approval
  bulk_decompile: {
    defaultAllow: false,
    requiresApproval: true,
    auditLevel: 'warning',
    maxLimit: 100,
  },

  // Static analysis is generally allowed
  static_analysis: {
    defaultAllow: true,
    requiresApproval: false,
    auditLevel: 'info',
  },

  // Regular decompilation is allowed
  decompile: {
    defaultAllow: true,
    requiresApproval: false,
    auditLevel: 'info',
  },

  // Network access requires approval
  network_access: {
    defaultAllow: false,
    requiresApproval: true,
    requiresIsolation: true,
    auditLevel: 'critical',
  },
}

const DEFAULT_APPROVAL_TTL_MS = 15 * 60 * 1000

// ============================================================================
// Policy Guard Implementation
// ============================================================================

/**
 * Policy Guard class for enforcing authorization rules
 */
export class PolicyGuard {
  private auditLogPath: string
  private readonly approvalTtlMs: number
  private readonly approvals = new Map<string, ApprovalRecord>()

  constructor(auditLogPath: string = './audit.log', options: PolicyGuardOptions = {}) {
    this.auditLogPath = auditLogPath
    this.approvalTtlMs = options.approvalTtlMs ?? DEFAULT_APPROVAL_TTL_MS
    this.ensureAuditLogExists()
  }

  /**
   * Ensure audit log file exists
   */
  private ensureAuditLogExists(): void {
    const dir = path.dirname(this.auditLogPath)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }
    if (!fs.existsSync(this.auditLogPath)) {
      fs.writeFileSync(this.auditLogPath, '', 'utf-8')
    }
  }

  /**
   * Check permission for an operation
   * Requirements: 18.1, 18.2
   */
  async checkPermission(
    operation: Operation,
    context: PolicyContext
  ): Promise<PolicyDecision> {
    this.pruneExpiredApprovals()

    // Detect dangerous operations
    const dangerousType = this.detectDangerousOperation(operation)

    // Get policy rule for the operation type
    const rule = POLICY_RULES[dangerousType] || POLICY_RULES[operation.type]

    if (!rule) {
      // Unknown operation type - deny by default
      return {
        allowed: false,
        reason: `Unknown operation type: ${operation.type}`,
      }
    }

    // Check specific limits FIRST (e.g., bulk decompile limit)
    if (rule.maxLimit !== undefined) {
      const limitExceeded = this.checkLimitExceeded(operation, rule.maxLimit)
      if (limitExceeded) {
        return {
          allowed: false,
          reason: `Operation exceeds maximum limit of ${rule.maxLimit}`,
          requiresApproval: true,
        }
      }
    }

    // Check if operation requires approval
    if (rule.requiresApproval) {
      const directApproval = this.checkApprovalProvided(operation)
      const dangerousOperation = this.toDangerousOperation(operation, context, dangerousType)
      const resolvedApproval = this.resolveApproval(operation, dangerousOperation)

      if (directApproval || resolvedApproval.status === 'approved') {
        return {
          allowed: true,
          reason: 'Approved by user',
          approvalToken: resolvedApproval.token,
          approvalStatus: directApproval ? 'approved' : resolvedApproval.status,
        }
      }

      const approvalRequest =
        resolvedApproval.token && resolvedApproval.status === 'pending'
          ? this.approvals.get(resolvedApproval.token)!
          : await this.createApprovalRequest(dangerousOperation)

      return {
        allowed: false,
        reason: `Operation '${dangerousType}' requires explicit approval (approval_token=${approvalRequest.token})`,
        requiresApproval: true,
        approvalToken: approvalRequest.token,
        approvalStatus: approvalRequest.status,
      }
    }

    // Operation is allowed
    return {
      allowed: rule.defaultAllow,
      reason: rule.defaultAllow ? undefined : 'Approved by user',
    }
  }

  /**
   * Detect if operation is dangerous based on tool and arguments
   * Requirements: 18.1, 18.3, 18.4
   */
  private detectDangerousOperation(operation: Operation): string {
    // Check for dynamic execution
    if (
      operation.tool === 'sandbox.execute' ||
      operation.type === 'dynamic_execution'
    ) {
      return 'dynamic_execution'
    }

    // Check for external upload
    if (
      operation.tool.includes('upload') ||
      operation.args.backend === 'online_sandbox' ||
      operation.args.external === true
    ) {
      return 'external_upload'
    }

    // Check for bulk decompilation - check multiple parameters
    if (operation.type === 'decompile') {
      // Check count parameter
      if (typeof operation.args.count === 'number' && operation.args.count > 100) {
        return 'bulk_decompile'
      }

      // Check topk parameter
      if (typeof operation.args.topk === 'number' && operation.args.topk > 100) {
        return 'bulk_decompile'
      }

      // Check addresses array
      if (Array.isArray(operation.args.addresses) && operation.args.addresses.length > 100) {
        return 'bulk_decompile'
      }

      // Check functions array
      if (Array.isArray(operation.args.functions) && operation.args.functions.length > 100) {
        return 'bulk_decompile'
      }
    }

    // Check for network access
    if (
      operation.args.network === 'enabled' ||
      operation.args.network === 'fake'
    ) {
      return 'network_access'
    }

    return operation.type
  }

  /**
   * Check if approval was provided in operation arguments
   */
  private checkApprovalProvided(operation: Operation): boolean {
    // Check for explicit approval flag
    if (operation.args.require_user_approval === true) {
      return true
    }

    if (operation.args.approved === true) {
      return true
    }

    return false
  }

  private getApprovalTokenFromArgs(operation: Operation): string | null {
    const token = operation.args.approval_token ?? operation.args.approvalToken
    return typeof token === 'string' && token.trim().length > 0 ? token.trim() : null
  }

  private resolveApproval(
    operation: Operation,
    dangerousOperation: DangerousOperation
  ): { token?: string; status?: ApprovalStatus } {
    const token = this.getApprovalTokenFromArgs(operation)
    if (!token) {
      return {}
    }

    const approval = this.approvals.get(token)
    if (!approval) {
      return { token, status: 'denied' }
    }

    if (approval.status === 'expired') {
      return { token, status: 'expired' }
    }

    const requestedKey = this.buildOperationKey(dangerousOperation)
    if (approval.operationKey !== requestedKey) {
      return { token, status: 'denied' }
    }

    return { token, status: approval.status }
  }

  private toDangerousOperation(
    operation: Operation,
    context: PolicyContext,
    dangerousType: string
  ): DangerousOperation {
    const sampleId =
      (typeof operation.args.sample_id === 'string' && operation.args.sample_id) ||
      context.sampleId ||
      'unknown'

    return {
      type: dangerousType,
      description: `${operation.tool} requested for sample ${sampleId}`,
      risks: this.inferRisks(dangerousType, operation),
      sampleId,
      tool: operation.tool,
      requestedBy: context.user,
      approvalToken: this.getApprovalTokenFromArgs(operation) ?? undefined,
    }
  }

  private inferRisks(dangerousType: string, operation: Operation): string[] {
    const risks = new Set<string>()

    switch (dangerousType) {
      case 'dynamic_execution':
        risks.add('Executes untrusted sample code')
        risks.add('May modify filesystem or processes inside isolated runtime')
        break
      case 'external_upload':
        risks.add('Transfers sample material to external systems')
        risks.add('May disclose sensitive binary or telemetry data')
        break
      case 'bulk_decompile':
        risks.add('High resource consumption')
        risks.add('May generate large volumes of derived code artifacts')
        break
      case 'network_access':
        risks.add('Permits outbound communication during execution')
        risks.add('May contact attacker-controlled infrastructure')
        break
      default:
        risks.add(`Operation '${dangerousType}' requires elevated review`)
        break
    }

    if (operation.args.network === 'enabled' || operation.args.network === 'fake') {
      risks.add('Network behavior requested')
    }
    if (operation.args.external === true || operation.args.backend === 'online_sandbox') {
      risks.add('External service interaction requested')
    }

    return [...risks]
  }

  private buildOperationKey(operation: DangerousOperation): string {
    return JSON.stringify({
      type: operation.type,
      sampleId: operation.sampleId,
      tool: operation.tool || '',
      description: operation.description,
      risks: [...operation.risks].sort(),
      requestedBy: operation.requestedBy || '',
    })
  }

  private pruneExpiredApprovals(nowMs: number = Date.now()): void {
    for (const approval of this.approvals.values()) {
      if (approval.status === 'pending' && Date.parse(approval.expiresAt) <= nowMs) {
        approval.status = 'expired'
        approval.reason = approval.reason || 'Approval request expired'
        approval.decidedAt = new Date(nowMs).toISOString()
      }
    }
  }

  async createApprovalRequest(operation: DangerousOperation): Promise<ApprovalRecord> {
    this.pruneExpiredApprovals()

    const now = new Date()
    const record: ApprovalRecord = {
      token: randomUUID(),
      status: 'pending',
      operation,
      requestedAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + this.approvalTtlMs).toISOString(),
      operationKey: this.buildOperationKey(operation),
    }

    this.approvals.set(record.token, record)

    await this.auditLog({
      timestamp: record.requestedAt,
      operation: operation.tool || operation.type,
      user: operation.requestedBy,
      sampleId: operation.sampleId,
      decision: 'deny',
      reason: `Approval required (token=${record.token})`,
      metadata: {
        approval_status: record.status,
        approval_token: record.token,
        approval_expires_at: record.expiresAt,
        risks: operation.risks,
      },
    })

    return record
  }

  async approveOperation(
    approvalToken: string,
    options: ApprovalDecisionOptions = {}
  ): Promise<ApprovalRecord> {
    this.pruneExpiredApprovals()
    const record = this.approvals.get(approvalToken)
    if (!record) {
      throw new Error(`Approval token not found: ${approvalToken}`)
    }
    if (record.status === 'expired') {
      throw new Error(`Approval token expired: ${approvalToken}`)
    }

    record.status = 'approved'
    record.decidedAt = new Date().toISOString()
    record.decidedBy = options.decidedBy
    record.reason = options.reason || 'Approved by user'

    await this.auditLog({
      timestamp: record.decidedAt,
      operation: record.operation.tool || record.operation.type,
      user: options.decidedBy,
      sampleId: record.operation.sampleId,
      decision: 'allow',
      reason: record.reason,
      metadata: {
        approval_status: record.status,
        approval_token: record.token,
        requested_at: record.requestedAt,
      },
    })

    return record
  }

  async denyOperation(
    approvalToken: string,
    options: ApprovalDecisionOptions = {}
  ): Promise<ApprovalRecord> {
    this.pruneExpiredApprovals()
    const record = this.approvals.get(approvalToken)
    if (!record) {
      throw new Error(`Approval token not found: ${approvalToken}`)
    }
    if (record.status === 'expired') {
      throw new Error(`Approval token expired: ${approvalToken}`)
    }

    record.status = 'denied'
    record.decidedAt = new Date().toISOString()
    record.decidedBy = options.decidedBy
    record.reason = options.reason || 'Denied by user'

    await this.auditLog({
      timestamp: record.decidedAt,
      operation: record.operation.tool || record.operation.type,
      user: options.decidedBy,
      sampleId: record.operation.sampleId,
      decision: 'deny',
      reason: record.reason,
      metadata: {
        approval_status: record.status,
        approval_token: record.token,
        requested_at: record.requestedAt,
      },
    })

    return record
  }

  getApprovalStatus(approvalToken: string): ApprovalRecord | undefined {
    this.pruneExpiredApprovals()
    const record = this.approvals.get(approvalToken)
    return record ? { ...record, operation: { ...record.operation, risks: [...record.operation.risks] } } : undefined
  }

  listApprovalRequests(status?: ApprovalStatus): ApprovalRecord[] {
    this.pruneExpiredApprovals()
    return [...this.approvals.values()]
      .filter((record) => !status || record.status === status)
      .map((record) => ({
        ...record,
        operation: {
          ...record.operation,
          risks: [...record.operation.risks],
        },
      }))
  }

  /**
   * Require user approval for dangerous operation
   * Requirements: 18.1
   */
  async requireUserApproval(
    operation: DangerousOperation
  ): Promise<boolean> {
    this.pruneExpiredApprovals()

    const approvalToken = operation.approvalToken?.trim()
    if (approvalToken) {
      const record = this.approvals.get(approvalToken)
      if (record && record.operationKey === this.buildOperationKey({ ...operation, approvalToken: undefined })) {
        return record.status === 'approved'
      }
    }

    await this.createApprovalRequest({
      ...operation,
      approvalToken: undefined,
    })
    return false
  }

  /**
   * Check if operation exceeds limit
   */
  private checkLimitExceeded(operation: Operation, maxLimit: number): boolean {
    // Check count parameter
    if (typeof operation.args.count === 'number') {
      return operation.args.count > maxLimit
    }

    // Check topk parameter (for bulk operations)
    if (typeof operation.args.topk === 'number') {
      return operation.args.topk > maxLimit
    }

    // Check array length parameters
    if (Array.isArray(operation.args.addresses)) {
      return operation.args.addresses.length > maxLimit
    }

    if (Array.isArray(operation.args.functions)) {
      return operation.args.functions.length > maxLimit
    }

    return false
  }

  /**
   * Record audit log event
   * Requirements: 18.5, 18.6, 23.1, 23.2, 23.4, 23.5
   */
  async auditLog(event: AuditEvent): Promise<void> {
    // Ensure timestamp is set
    if (!event.timestamp) {
      event.timestamp = new Date().toISOString()
    }

    // Format as JSON Lines (one JSON object per line)
    const logLine = JSON.stringify(event) + '\n'

    // Append to audit log file
    try {
      fs.appendFileSync(this.auditLogPath, logLine, 'utf-8')
    } catch (error) {
      // Log to stderr if file write fails
      logger.error({ err: error, event }, 'Failed to write audit log')
    }
  }

  /**
   * Get audit log path
   */
  getAuditLogPath(): string {
    return this.auditLogPath
  }
}

// ============================================================================
// Exports
// ============================================================================

export default PolicyGuard
