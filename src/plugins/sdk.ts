/**
 * Plugin SDK — The public contract for all plugins.
 *
 * Every plugin imports types ONLY from this file (+ npm packages).
 * No server internals, no cross-plugin imports.
 *
 * This file defines:
 *   - Plugin interface — the contract every plugin implements
 *   - PluginToolDeps — injected dependencies (server provides implementations)
 *   - ToolDefinition / WorkerResult / ArtifactRef — standard return types
 *   - PluginServerInterface — what the server exposes to plugins
 */

// ═══════════════════════════════════════════════════════════════════════════
// Result Types
// ═══════════════════════════════════════════════════════════════════════════

/** Reference to a persisted analysis artifact. */
export interface ArtifactRef {
  id: string
  type: string
  path: string
  sha256: string
  mime?: string
  metadata?: Record<string, unknown>
}

/** Standard tool result (MCP protocol). */
export interface ToolResult {
  content: Array<{ type: string; text: string }>
  isError?: boolean
  structuredContent?: Record<string, unknown>
}

/** Worker-style result used by most analysis tools. */
export interface WorkerResult {
  ok: boolean
  data?: unknown
  errors?: string[]
  warnings?: string[]
  setup_actions?: unknown[]
  required_user_inputs?: unknown[]
  artifacts?: ArtifactRef[]
  metrics?: Record<string, unknown>
}

// ═══════════════════════════════════════════════════════════════════════════
// Tool Definition
// ═══════════════════════════════════════════════════════════════════════════

/** Schema for a tool's inputs. */
export interface ToolDefinition {
  name: string
  canonicalName?: string
  description: string
  inputSchema: any
  outputSchema?: any
}

/** Generic tool arguments (for tools that don't use Zod parsing). */
export type ToolArgs = Record<string, unknown>

// ═══════════════════════════════════════════════════════════════════════════
// Server Interface (what plugins see)
// ═══════════════════════════════════════════════════════════════════════════

/** The server facade exposed to plugins during registration. */
export interface PluginServerInterface {
  registerTool(definition: ToolDefinition, handler: (args: any) => Promise<any>): void
  unregisterTool(canonicalName: string): void
}

// ═══════════════════════════════════════════════════════════════════════════
// Plugin Context — scoped runtime context passed to plugins at registration
// ═══════════════════════════════════════════════════════════════════════════

/** Scoped logger interface for plugins. */
export interface PluginLogger {
  info(msg: string, data?: Record<string, unknown>): void
  warn(msg: string, data?: Record<string, unknown>): void
  error(msg: string, data?: Record<string, unknown>): void
  debug(msg: string, data?: Record<string, unknown>): void
}

/**
 * Runtime context provided to each plugin during registration.
 *
 * Gives plugins a scoped logger (prefixed with plugin ID) and a type-safe
 * config reader that validates against the plugin's declared configSchema.
 */
export interface PluginContext {
  /** The plugin's unique ID. */
  pluginId: string
  /** Scoped logger with plugin ID prefix. */
  logger: PluginLogger
  /** Read a config value declared in configSchema (resolved from env vars). */
  getConfig(envVar: string): string | undefined
  /** Read a required config value — throws if missing. */
  getRequiredConfig(envVar: string): string
  /** Data directory path for this plugin (for persistent state). */
  dataDir: string
}

// ═══════════════════════════════════════════════════════════════════════════
// Dependency Injection
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Dependencies injected by the server into plugins.
 *
 * Core services (workspaceManager, database, config, etc.) are always available.
 * Utility functions (resolvePrimarySamplePath, persistStaticAnalysisJsonArtifact, etc.)
 * are provided so plugins never import server internals directly.
 *
 * Plugins should destructure what they need:
 * ```ts
 * register(server, deps) {
 *   const { workspaceManager, database, config } = deps
 * }
 * ```
 */
export interface PluginToolDeps {
  // ── Core services ──────────────────────────────────────────────────────
  workspaceManager: any
  database: any
  config?: any
  policyGuard?: any
  cacheManager?: any
  jobQueue?: any
  storageManager?: any
  server?: any

  // ── Utility functions ──────────────────────────────────────────────────
  /** Resolve a sample_id to its primary file path on disk. */
  resolvePrimarySamplePath?: (wm: any, sampleId: string) => Promise<{ samplePath: string; integrity?: any }>
  /** Write a JSON analysis artifact to the workspace and register in DB. */
  persistStaticAnalysisJsonArtifact?: (wm: any, db: any, sampleId: string, artifactType: string, filePrefix: string, payload: unknown, sessionTag?: string | null) => Promise<ArtifactRef>
  /** Resolve a path relative to the project root (e.g. for Python workers). */
  resolvePackagePath?: (...segments: string[]) => string
  /** Generate a deterministic cache key for a tool invocation. */
  generateCacheKey?: (params: { sampleSha256: string; toolName: string; toolVersion: string; args: Record<string, unknown>; rulesetVersion?: string }) => string

  // ── Logging ────────────────────────────────────────────────────────────
  logger?: any

  // ── Specialized (Ghidra, Frida, etc.) ──────────────────────────────────
  /** DecompilerWorker class constructor (Ghidra plugins). */
  DecompilerWorker?: any
  getGhidraDiagnostics?: any
  normalizeGhidraError?: any
  findBestGhidraAnalysis?: any
  getGhidraReadiness?: any
  parseGhidraAnalysisMetadata?: any
  buildPollingGuidance?: any
  PollingGuidanceSchema?: any
  SetupActionSchema?: any
  RequiredUserInputSchema?: any

  /** Allow additional properties for extensibility. */
  [key: string]: any
}

// ═══════════════════════════════════════════════════════════════════════════
// Plugin Contract
// ═══════════════════════════════════════════════════════════════════════════

/** Declarative description of one config field a plugin needs. */
export interface PluginConfigField {
  envVar: string
  description: string
  required: boolean
  defaultValue?: string
}

// ═══════════════════════════════════════════════════════════════════════════
// System Dependencies — declarative runtime requirement descriptors
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Describes a single runtime dependency a plugin requires.
 *
 * The plugin system uses these to:
 *   1. Auto-generate `check()` when the plugin doesn't provide one
 *   2. Produce a structured health report at startup
 *   3. Validate Docker images include all necessary tools
 *   4. Generate documentation of per-plugin requirements
 *
 * Example:
 * ```ts
 * systemDeps: [
 *   { type: 'binary', name: 'frida', versionFlag: '--version', envVar: 'FRIDA_PATH' },
 *   { type: 'python', name: 'dnfile', importName: 'dnfile' },
 *   { type: 'binary', name: 'gdb', versionFlag: '--version', required: false },
 * ]
 * ```
 */
export interface PluginSystemDep {
  /** Kind of dependency. */
  type: 'binary' | 'python' | 'python-venv' | 'env-var' | 'directory' | 'file'

  /** Human-readable name (e.g. `'frida'`, `'dnfile'`, `'Ghidra'`). */
  name: string

  /**
   * For `binary`: the executable name or absolute path to test.
   * For `python`: the pip package name.
   * For `python-venv`: path to the venv's python binary.
   * For `env-var`: the environment variable name.
   * For `directory` / `file`: the path to check (may reference an env var via `$ENV_VAR`).
   */
  target?: string

  /** For `python`: the importable module name if different from package name. */
  importName?: string

  /** For `binary`: flag to get version output (e.g. `'--version'`). */
  versionFlag?: string

  /** Environment variable that provides / overrides the path to this dependency. */
  envVar?: string

  /** Default path inside the Docker image (used for health reporting). */
  dockerDefault?: string

  /** Whether the dependency is required (true) or optional/nice-to-have (false). */
  required: boolean

  /** Short human-readable description shown in health reports. */
  description?: string

  /** Docker `RUN` instruction or package name that installs this dep. */
  dockerInstall?: string
}

/**
 * Result of validating a single system dependency at runtime.
 */
export interface DepCheckResult {
  dep: PluginSystemDep
  available: boolean
  resolvedPath?: string
  version?: string
  error?: string
}

/** Lifecycle hooks a plugin can implement. */
export interface PluginHooks {
  onBeforeToolCall?: (toolName: string, args: Record<string, unknown>) => void | Promise<void>
  onAfterToolCall?: (toolName: string, args: Record<string, unknown>, elapsedMs: number) => void | Promise<void>
  onToolError?: (toolName: string, error: unknown) => void | Promise<void>
  onActivate?: () => void | Promise<void>
  onDeactivate?: () => void | Promise<void>
}

/** Runtime metadata about a loaded (or skipped) plugin. */
export interface PluginStatus {
  id: string
  name: string
  description?: string
  version?: string
  status: 'loaded' | 'skipped-disabled' | 'skipped-check' | 'skipped-deps' | 'error'
  tools: string[]
  configFields?: PluginConfigField[]
  /** Results of system dependency checks (populated at load time). */
  depChecks?: DepCheckResult[]
  error?: string
}

/**
 * The contract every plugin must implement.
 *
 * A plugin is a self-contained module that lives in its own directory
 * under `src/plugins/<id>/`. It exports a default `Plugin` object.
 */
export interface Plugin {
  /** Unique kebab-case identifier, e.g. `'android'`, `'ghidra'`. */
  id: string
  /** Human-readable display name. */
  name: string
  /** Short description of the plugin's capabilities. */
  description?: string
  /** Semantic version string, e.g. `'1.0.0'`. */
  version?: string
  /** IDs of plugins that must load before this one. */
  dependencies?: string[]
  /** Declarative config fields the plugin expects. */
  configSchema?: PluginConfigField[]
  /**
   * Declarative system dependencies this plugin requires at runtime.
   * Used for auto-check, health reporting, and Docker validation.
   * When provided and no explicit `check()` is defined, the plugin system
   * will auto-generate a check from these declarations.
   */
  systemDeps?: PluginSystemDep[]
  /** Optional lifecycle hooks. */
  hooks?: PluginHooks
  /** If true, hooks fire for ALL tool invocations, not just this plugin's tools. */
  globalHooks?: boolean
  /** Optional prerequisite check; return false to skip loading. */
  check?: () => boolean | Promise<boolean>
  /** Register all tools belonging to this plugin. Return tool names registered. */
  register: (server: PluginServerInterface, deps: PluginToolDeps, ctx?: PluginContext) => string[] | void
  /** Optional cleanup when the plugin is unloaded at runtime. */
  teardown?: () => void | Promise<void>
}
