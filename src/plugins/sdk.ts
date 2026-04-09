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
 *   3. **Drive Docker image generation** — the generator scans all plugins,
 *      collects their systemDeps, and only includes the build stages, apt
 *      packages, env vars, and validation commands that are actually needed.
 *   4. Generate documentation of per-plugin requirements
 *
 * Example:
 * ```ts
 * systemDeps: [
 *   {
 *     type: 'binary', name: 'frida', versionFlag: '--version',
 *     envVar: 'FRIDA_PATH', required: true,
 *     dockerFeature: 'frida',
 *     aptPackages: [],
 *     dockerValidation: ['frida-ps --help >/dev/null 2>&1'],
 *   },
 *   { type: 'python', name: 'dnfile', importName: 'dnfile', required: true },
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

  // ── Docker generation fields (drive Dockerfile output) ───────────────

  /**
   * Docker feature group ID that controls conditional blocks in the
   * Dockerfile template.  Deps with the same `dockerFeature` share a
   * build stage (e.g. `'ghidra'`, `'rizin'`, `'angr'`).
   *
   * When the generator scans plugins, it collects all unique
   * `dockerFeature` values and enables the corresponding `# @if <feature>`
   * blocks in the template.
   *
   * Leave undefined for deps that don't require a dedicated Docker stage
   * (e.g. Python packages already in requirements.txt).
   */
  dockerFeature?: string

  /**
   * apt-get packages to install in the runtime Docker image.
   * Merged across all enabled plugins into a single `apt-get install`.
   */
  aptPackages?: string[]

  /**
   * Shell commands to validate this dependency inside the Docker image.
   * Merged into a single `RUN` validation step at the end of the build.
   */
  dockerValidation?: string[]

  // ── Extended Docker metadata (replaces hardcoded maps in generator) ──

  /**
   * Additional Docker ENV vars beyond the primary `envVar`/`dockerDefault`.
   * Merged across all enabled plugins into the runtime ENV block and
   * docker-compose environment section.
   *
   * Example: `{ JAVA_HOME: '/opt/java/openjdk', GHIDRA_LOG_ROOT: '/ghidra-logs' }`
   */
  extraEnv?: Record<string, string>

  /**
   * Docker build ARG names and their default values.
   * Merged across all plugins into global ARG declarations and
   * docker-compose build args.
   *
   * Example: `{ GHIDRA_VERSION: '12.0.4' }`
   */
  buildArgs?: Record<string, string>

  /**
   * Directories to create and optionally chown in the runtime Docker image.
   * Merged into the `mkdir` + `chown` block near the end of the Dockerfile.
   *
   * Example: `[{ path: '/ghidra-projects', chown: 'appuser:appuser' }]`
   */
  directories?: Array<{ path: string; chown?: string }>

  /**
   * docker-compose volume mounts this dependency requires.
   * Merged into the volumes section of docker-compose.yml.
   *
   * Example: `[{ source: '${RIKUNE_DATA_ROOT:-D:/Docker/rikune}/ghidra-projects', target: '/ghidra-projects', mode: 'rw' }]`
   */
  volumes?: Array<{ source: string; target: string; mode?: 'ro' | 'rw' }>
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
 *
 * ## Standard directory layout
 *
 * ```
 * src/plugins/<id>/
 *   index.ts         — Plugin entry point (required)
 *   tools/            — Co-located tool implementations
 *   workers/          — Python worker scripts (plugin-specific)
 *   scripts/          — Frida/Ghidra scripts (plugin-specific)
 *   data/             — Data files (JSON patterns, rules, etc.)
 * ```
 *
 * Tools, workers, scripts, and data files that are specific to a single
 * plugin MUST live inside that plugin's directory. Only truly shared
 * resources (used by 3+ plugins or by the core) remain in root-level dirs.
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
  /**
   * Declares co-located resource directories relative to the plugin root.
   * Used by the Docker generator and build tooling to discover plugin assets.
   *
   * Convention (all optional):
   * - `workers` — Python worker scripts (default: `'workers'`)
   * - `scripts` — Frida/Ghidra scripts (default: `'scripts'`)
   * - `data`    — Data files (JSON, YARA rules, etc.) (default: `'data'`)
   *
   * Set a key to declare the resource exists. The value is the directory name
   * relative to the plugin root (almost always the default).
   *
   * Example:
   * ```ts
   * resources: { workers: 'workers', scripts: 'scripts', data: 'data' }
   * ```
   */
  resources?: {
    workers?: string
    scripts?: string
    data?: string
  }
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
