/**
 * Type definitions for the MCP Server
 */

import { z } from 'zod'
import {
  RuntimeArtifactControlPlaneMetadataSchema,
  RuntimeBackendCapabilitySchema,
  RuntimeConnectedEventDataSchema,
  RuntimeDynamicArtifactFamilySchema,
  RuntimeDynamicArtifactTypeSchema,
  RuntimeDelegationFailureCategorySchema,
  RuntimeDelegationFailureDataSchema,
  RuntimeDelegationFailureResultSchema,
  RuntimeSseEventSchema,
  RuntimeSnapshotEventDataSchema,
  RuntimeTaskArtifactRefSchema,
  RuntimeTaskEventSchema,
  RuntimeTaskResultSchema,
  RuntimeTaskSnapshotSchema,
  RuntimeTaskStatusSchema,
  ToolRuntimeContractSchema,
  type ArtifactRef,
  type DynamicRuntimePolicy,
  type RuntimeArtifactControlPlaneMetadata,
  type RuntimeBackendType,
  type RuntimeConnectedEventData,
  type RuntimeControlPlaneEvent,
  type RuntimeDynamicArtifactFamily,
  type RuntimeDynamicArtifactType,
  type RuntimeDelegationFailureCategory,
  type RuntimeExecutionMode,
  type RuntimeExecutionSemantics,
  type RuntimeFallbackRule,
  type RuntimeSseEvent,
  type RuntimeSnapshotEventData,
  type RuntimeTaskArtifactRef,
  type RuntimeTaskEvent,
  type RuntimeTaskResult,
  type RuntimeTaskSnapshot,
  type RuntimeTaskStatus,
  type ToolRuntimeContract,
  type WorkerResult,
  PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPES,
  buildRuntimeArtifactControlPlaneMetadata,
  extractRuntimeTaskStatusFromEvent,
  inferRuntimeArtifactFamily,
  inferRuntimeArtifactType,
} from '@rikune/shared'

export {
  RuntimeArtifactControlPlaneMetadataSchema,
  RuntimeBackendCapabilitySchema,
  RuntimeConnectedEventDataSchema,
  RuntimeDynamicArtifactFamilySchema,
  RuntimeDynamicArtifactTypeSchema,
  RuntimeDelegationFailureCategorySchema,
  RuntimeDelegationFailureDataSchema,
  RuntimeDelegationFailureResultSchema,
  RuntimeSseEventSchema,
  RuntimeSnapshotEventDataSchema,
  RuntimeTaskArtifactRefSchema,
  RuntimeTaskEventSchema,
  RuntimeTaskResultSchema,
  RuntimeTaskSnapshotSchema,
  RuntimeTaskStatusSchema,
  ToolRuntimeContractSchema,
  PRIMARY_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  SANDBOX_RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPE,
  RUNTIME_DYNAMIC_TRACE_ARTIFACT_TYPES,
  buildRuntimeArtifactControlPlaneMetadata,
  extractRuntimeTaskStatusFromEvent,
  inferRuntimeArtifactFamily,
  inferRuntimeArtifactType,
}
export type {
  ArtifactRef,
  DynamicRuntimePolicy,
  RuntimeArtifactControlPlaneMetadata,
  RuntimeBackendType,
  RuntimeConnectedEventData,
  RuntimeControlPlaneEvent,
  RuntimeDynamicArtifactFamily,
  RuntimeDynamicArtifactType,
  RuntimeDelegationFailureCategory,
  RuntimeExecutionMode,
  RuntimeExecutionSemantics,
  RuntimeFallbackRule,
  RuntimeSseEvent,
  RuntimeTaskArtifactRef,
  RuntimeTaskEvent,
  RuntimeTaskResult,
  RuntimeTaskSnapshot,
  RuntimeTaskStatus,
  RuntimeSnapshotEventData,
  ToolRuntimeContract,
  WorkerResult,
}

// ============================================================================
// MCP Protocol Types
// ============================================================================

/**
 * JSON Schema type for tool input/output validation
 */
export type JSONSchema = z.ZodTypeAny

/**
 * Plugin aspect metadata used for sample routing, discovery, and readiness.
 * This mirrors the public SDK taxonomy while staying permissive for future
 * plugin-defined aspect groups.
 */
export interface PluginAspects {
  formats?: string[]
  platforms?: string[]
  architectures?: string[]
  execution?: string[]
  runtimes?: string[]
  safety?: string[]
  capabilities?: string[]
  evidence?: string[]
  [group: string]: string[] | undefined
}

/** Declaration of artifact families a tool may produce. */
export interface ToolArtifactSpec {
  type: string
  description?: string
  mimeTypes?: string[]
  required?: boolean
  [key: string]: unknown
}

/** Declaration of evidence families a tool may produce. */
export interface ToolEvidenceSpec {
  category: string
  description?: string
  artifactTypes?: string[]
  required?: boolean
  [key: string]: unknown
}

/** Declaration of a cross-plugin workflow a tool starts, advances, or completes. */
export interface WorkflowRecipeSpec {
  id: string
  title: string
  description?: string
  startsWith?: string[]
  nextTools?: string[]
  requiredArtifacts?: string[]
  producesArtifacts?: string[]
  evidence?: string[]
  safety?: string[]
  runtimeBackends?: string[]
  [key: string]: unknown
}

/** Policy envelope for bounded backend worker tools. */
export interface BackendWorkerPolicy {
  passiveByDefault?: boolean
  requiresUserOptIn?: boolean
  requiresIsolation?: boolean
  noNetwork?: boolean
  noMutation?: boolean
  noLiveExecution?: boolean
  maxInputBytes?: number
  maxOutputBytes?: number
  defaultTimeoutMs?: number
  allowedRoots?: string[]
  notes?: string[]
  [key: string]: unknown
}

/** Declaration of an optional worker backend used by a tool. */
export interface BackendWorkerContract {
  version?: 'backend-worker.v1'
  backendName: string
  backendKind: 'builtin' | 'external' | 'delegated-runtime'
  adapter: string
  availability?: 'builtin' | 'optional' | 'required'
  envVar?: string
  commandHint?: string
  versionHint?: string
  supportedModes?: string[]
  defaultMode?: string
  inputArtifactTypes?: string[]
  outputArtifactTypes?: string[]
  policy?: BackendWorkerPolicy
  readiness?: {
    doesNotStartBackend?: boolean
    setupActions?: string[]
    missingBackendBehavior?: string
    [key: string]: unknown
  }
  packaging?: {
    installRoute?: 'installed' | 'profile-gated' | 'byo' | 'sidecar' | 'validation-only'
    installProfile?:
      | 'default'
      | 'optional'
      | 'heavy'
      | 'research'
      | 'runtime'
      | 'gpu'
      | 'license-gated'
    dockerFeature?: string
    envVar?: string
    dockerDefault?: string
    notes?: string[]
    [key: string]: unknown
  }
  [key: string]: unknown
}

/**
 * MCP tool annotations — behavioral hints surfaced to clients.
 * All hints are advisory; clients treat them as untrusted metadata.
 */
export interface ToolAnnotations {
  /** Human-readable display name for the tool. */
  title?: string
  /** If true, the tool does not modify its environment. */
  readOnlyHint?: boolean
  /** If true, the tool may perform destructive side effects. */
  destructiveHint?: boolean
  /** If true, repeated calls with the same arguments yield the same result. */
  idempotentHint?: boolean
  /** If true, the tool interacts with an open-world external system. */
  openWorldHint?: boolean
}

/**
 * Tool definition following MCP protocol
 */
export interface ToolDefinition {
  name: string
  canonicalName?: string
  description: string
  inputSchema: JSONSchema
  outputSchema?: JSONSchema
  /**
   * MCP tool annotations surfaced to clients as hints about tool behavior.
   * When omitted, annotations are derived from runtimePolicy/workerBackend.
   */
  annotations?: ToolAnnotations
  /** Aspect metadata used by sample profiling and progressive discovery. */
  aspects?: PluginAspects
  /** Artifact families this tool may write. */
  artifacts?: ToolArtifactSpec[]
  /** Evidence families this tool may produce. */
  evidence?: ToolEvidenceSpec[]
  /** Cross-plugin workflow recipes surfaced by discovery, help, and readiness tools. */
  workflowRecipes?: WorkflowRecipeSpec[]
  /** Dynamic execution policy surfaced by readiness and scaffold templates. */
  runtimePolicy?: DynamicRuntimePolicy
  /** Runtime execution contract for tools delegated to a runtime node. */
  runtime?: ToolRuntimeContract
  /** Bounded backend worker contract for optional worker-backed tools. */
  workerBackend?: BackendWorkerContract
}

/**
 * Prompt argument definition following MCP protocol
 */
export interface PromptArgumentDefinition {
  name: string
  description?: string
  required?: boolean
}

/**
 * Prompt definition following MCP protocol
 */
export interface PromptDefinition {
  name: string
  title?: string
  description?: string
  arguments?: PromptArgumentDefinition[]
}

/**
 * Prompt arguments (generic string map)
 */
export type PromptArgs = Record<string, string>

/**
 * Prompt message content
 */
export interface PromptMessageContent {
  type: 'text'
  text: string
}

/**
 * Prompt message item
 */
export interface PromptMessage {
  role: 'user' | 'assistant'
  content: PromptMessageContent
}

/**
 * Prompt handler result
 */
export interface PromptResult {
  description?: string
  messages: PromptMessage[]
}

/**
 * Content types for MCP responses
 */
export type ContentType = 'text' | 'resource' | 'structuredContent'

/**
 * Resource content structure
 */
export interface ResourceContent {
  uri: string
  mimeType?: string
  text?: string
}

/**
 * Structured content with schema
 */
export interface StructuredContent {
  type: string
  data: unknown
  schema?: JSONSchema
}

/**
 * Content item in tool result
 */
export interface Content {
  type: ContentType
  text?: string
  resource?: ResourceContent
  structuredContent?: StructuredContent
}

/**
 * Tool execution result
 */
export interface ToolResult {
  content: Content[]
  isError?: boolean
  structuredContent?: Record<string, unknown>
}

/**
 * Tool arguments (generic)
 */
export type ToolArgs = Record<string, unknown>

/**
 * Tool handler function type
 */
export type ToolHandler = (args: unknown) => Promise<ToolResult>

// ============================================================================
// Domain Types
// ============================================================================

export interface SampleInfo {
  sampleId: string
  sha256: string
  md5: string
  size: number
  path: string
}

export interface WorkspacePath {
  root: string
  original: string
  cache: string
  ghidra: string
  reports: string
}

// ============================================================================
// Cache Types
// ============================================================================

/**
 * Parameters for cache key generation
 * Requirements: 20.1, 20.2
 */
export interface CacheKeyParams {
  sampleSha256: string
  toolName: string
  toolVersion: string
  args: Record<string, unknown>
  rulesetVersion?: string
}

/**
 * Cached result structure
 * Requirements: 20.3, 20.4, 20.5
 */
export interface CachedResult {
  key: string
  data: unknown
  createdAt: string
  expiresAt?: string
  sampleSha256?: string
}

// ============================================================================
// Error Handling Types
// ============================================================================

/**
 * Error categories for classification
 * Requirements: 22.1, 22.2, 22.3
 */
export enum ErrorCategory {
  // Retryable errors
  TIMEOUT = 'E_TIMEOUT',
  RESOURCE_EXHAUSTED = 'E_RESOURCE_EXHAUSTED',
  WORKER_UNAVAILABLE = 'E_WORKER_UNAVAILABLE',

  // Non-retryable errors
  INVALID_INPUT = 'E_INVALID_INPUT',
  PARSE_ERROR = 'E_PARSE_PE',
  POLICY_DENIED = 'E_POLICY_DENY',
  NOT_FOUND = 'E_NOT_FOUND',

  // Partial failures
  PARTIAL_SUCCESS = 'E_PARTIAL_SUCCESS',

  // Unknown errors
  UNKNOWN = 'E_UNKNOWN',
}

/**
 * Context for error handling
 * Requirements: 22.4
 */
export interface ErrorContext {
  tool: string
  sampleId: string
  attempt: number
  maxRetries: number
}

/**
 * Result of error handling
 * Requirements: 22.4, 22.5, 22.6
 */
export interface ErrorResult {
  shouldRetry: boolean
  backoffMs?: number
  fallbackAction?: string
}

// ============================================================================
// Job Queue Types
// ============================================================================

/**
 * Job priority levels (higher number = higher priority)
 * Requirements: 21.2
 */
export enum JobPriority {
  LOW = 1,
  NORMAL = 5,
  HIGH = 10,
  CRITICAL = 20,
}

/**
 * Job execution status
 * Requirements: 21.1, 21.2
 */
export type JobStatusType =
  | 'queued'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'interrupted'

/**
 * Retry policy for failed jobs
 * Requirements: 21.5
 */
export interface RetryPolicy {
  maxRetries: number
  backoffMs: number
  retryableErrors: string[]
}

/**
 * Job definition
 * Requirements: 21.1
 */
export interface Job {
  id: string
  type: 'static' | 'decompile' | 'dotnet' | 'sandbox'
  tool: string
  sampleId: string
  args: Record<string, unknown>
  priority: number
  timeout: number
  retryPolicy: RetryPolicy
  createdAt: string
  attempts: number
  estimatedDurationMs?: number // Estimated duration for async job pattern
}

/**
 * Job status information
 * Requirements: 21.1, 21.2
 */
export interface JobStatus {
  id: string
  status: JobStatusType
  progress?: number
  progressStage?: string
  startedAt?: string
  finishedAt?: string
  error?: string
}

/**
 * Job execution metrics
 * Requirements: 30.1, 30.2
 */
export interface JobMetrics {
  elapsedMs: number
  peakRssMb: number
  cpuPercent?: number
}

/**
 * Job execution result
 * Requirements: 21.4
 */
export interface JobResult {
  jobId: string
  ok: boolean
  data?: unknown
  errors: string[]
  warnings: string[]
  artifacts: ArtifactRef[]
  metrics: JobMetrics
}
