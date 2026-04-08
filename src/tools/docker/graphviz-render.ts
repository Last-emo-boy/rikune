/**
 * Graphviz render tool — renders DOT graph text into SVG or PNG artifacts.
 */

import { z } from 'zod'
import type { WorkerResult, ToolDefinition, ToolArgs, ArtifactRef } from '../../types.js'
import type { WorkspaceManager } from '../../workspace-manager.js'
import type { DatabaseManager } from '../../database.js'
import type { SharedBackendDependencies } from './docker-shared.js'
import {
  fs, os, path,
  ArtifactRefSchema, BackendSchema, SharedMetricsSchema,
  ExplanationConfidenceStateSchema, ExplanationSurfaceRoleSchema, ToolSurfaceRoleSchema,
  ensureSampleExists, executeCommand, truncateText, normalizeError,
  persistBackendArtifact, buildMetrics,
  resolveAnalysisBackends,
  mergeSetupActions, buildCoreLinuxToolchainSetupActions, buildHeavyBackendSetupActions,
} from './docker-shared.js'

export const graphvizRenderInputSchema = z.object({
  sample_id: z.string().describe('Sample identifier (sha256:<hex>) used for artifact persistence.'),
  graph_text: z.string().min(1).describe('DOT graph source to render.'),
  format: z.enum(['svg', 'png']).default('svg').describe('Rendered output format.'),
  layout: z
    .enum(['dot', 'neato', 'fdp', 'sfdp', 'circo', 'twopi'])
    .default('dot')
    .describe('Graphviz layout engine.'),
  timeout_sec: z.number().int().min(1).max(120).default(30).describe('Renderer timeout in seconds.'),
  preview_max_chars: z
    .number()
    .int()
    .min(128)
    .max(4000)
    .default(1000)
    .describe('Maximum inline preview characters from the rendered asset text when the format is svg.'),
  persist_artifact: z
    .boolean()
    .default(true)
    .describe('Persist the rendered output as an artifact in reports/backend_tools.'),
  session_tag: z
    .string()
    .optional()
    .describe('Optional artifact session tag for grouping graphviz outputs.'),
})

export const graphvizRenderOutputSchema = z.object({
  ok: z.boolean(),
  data: z
    .object({
      status: z.enum(['ready', 'setup_required']),
      backend: BackendSchema,
      sample_id: z.string().optional(),
      tool_surface_role: ToolSurfaceRoleSchema,
      preferred_primary_tools: z.array(z.string()),
      graph_semantics: z
        .object({
          surface_role: ExplanationSurfaceRoleSchema,
          confidence_state: ExplanationConfidenceStateSchema,
          upstream_surface: z.string(),
          omissions: z.array(z.object({ code: z.string(), reason: z.string() })).optional(),
        })
        .optional(),
      format: z.enum(['svg', 'png']).optional(),
      layout: z.string().optional(),
      preview: z
        .object({
          inline_text: z.string().optional(),
          truncated: z.boolean(),
          char_count: z.number().int().nonnegative(),
        })
        .optional(),
      artifact: ArtifactRefSchema.optional(),
      summary: z.string(),
      recommended_next_tools: z.array(z.string()),
      next_actions: z.array(z.string()),
    })
    .optional(),
  warnings: z.array(z.string()).optional(),
  errors: z.array(z.string()).optional(),
  artifacts: z.array(ArtifactRefSchema).optional(),
  setup_actions: z.array(z.any()).optional(),
  required_user_inputs: z.array(z.any()).optional(),
  metrics: SharedMetricsSchema.optional(),
})

export const graphvizRenderToolDefinition: ToolDefinition = {
  name: 'graphviz.render',
  description:
    'Render DOT graph text with Graphviz into SVG or PNG artifacts. This is a renderer/export helper over an existing graph, not the primary analysis or explanation surface. Use it when you explicitly want Graphviz output beyond code.function.cfg and need artifact-first graph rendering.',
  inputSchema: graphvizRenderInputSchema,
  outputSchema: graphvizRenderOutputSchema,
}

export function createGraphvizRenderHandler(
  workspaceManager: WorkspaceManager,
  database: DatabaseManager,
  dependencies?: SharedBackendDependencies
) {
  return async (args: ToolArgs): Promise<WorkerResult> => {
    const startTime = Date.now()
    try {
      const input = graphvizRenderInputSchema.parse(args)
      ensureSampleExists(database, input.sample_id)
      const backends = (dependencies?.resolveBackends || resolveAnalysisBackends)()
      const backend = backends.graphviz
      if (!backend.available || !backend.path) {
        return {
          ok: true,
          data: {
            status: 'setup_required',
            backend,
            sample_id: input.sample_id,
            tool_surface_role: 'renderer_helper',
            preferred_primary_tools: ['code.function.cfg', 'workflow.summarize', 'report.summarize'],
            graph_semantics: {
              surface_role: 'render_export_helper',
              confidence_state: 'observed',
              upstream_surface: 'code.function.cfg',
              omissions: [
                {
                  code: 'renderer_unavailable',
                  reason:
                    'Graphviz is unavailable, so only upstream text graph exports can currently carry semantics.',
                },
              ],
            },
            summary: backend.error || 'Graphviz renderer is unavailable.',
            recommended_next_tools: ['code.function.cfg', 'system.health', 'system.setup.guide'],
            next_actions: [
              'Use code.function.cfg for the primary graph semantics and artifact-first text exports.',
              'Install Graphviz before retrying this render/export helper.',
            ],
          },
          warnings: [backend.error || 'Backend unavailable'],
          setup_actions: mergeSetupActions(
            buildCoreLinuxToolchainSetupActions(),
            buildHeavyBackendSetupActions()
          ),
          metrics: buildMetrics(startTime, graphvizRenderToolDefinition.name),
        }
      }

      const runner = dependencies?.executeCommand || executeCommand
      const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'graphviz-render-'))
      const inputPath = path.join(tempDir, 'graph.dot')
      const outputPath = path.join(tempDir, `rendered.${input.format}`)
      await fs.writeFile(inputPath, input.graph_text, 'utf8')

      const commandResult = await runner(
        backend.path,
        [`-K${input.layout}`, `-T${input.format}`, inputPath, '-o', outputPath],
        input.timeout_sec * 1000
      )

      if (commandResult.exitCode !== 0) {
        await fs.rm(tempDir, { recursive: true, force: true })
        return {
          ok: false,
          errors: [
            `Graphviz render failed with exit code ${commandResult.exitCode}`,
            commandResult.stderr || commandResult.stdout || 'No backend output was returned.',
          ],
          metrics: buildMetrics(startTime, graphvizRenderToolDefinition.name),
        }
      }

      const rendered = await fs.readFile(outputPath)
      const previewSource = input.format === 'svg' ? rendered.toString('utf8') : ''
      const preview = truncateText(previewSource, input.preview_max_chars)

      const artifacts: ArtifactRef[] = []
      let artifact: ArtifactRef | undefined
      if (input.persist_artifact) {
        artifact = await persistBackendArtifact(
          workspaceManager,
          database,
          input.sample_id,
          'graphviz',
          `render_${input.format}`,
          rendered,
          {
            extension: input.format,
            mime: input.format === 'svg' ? 'image/svg+xml' : 'image/png',
            sessionTag: input.session_tag,
            metadata: {
              layout: input.layout,
            },
          }
        )
        artifacts.push(artifact)
      }

      await fs.rm(tempDir, { recursive: true, force: true })

      return {
        ok: true,
        data: {
          status: 'ready',
          backend,
          sample_id: input.sample_id,
          tool_surface_role: 'renderer_helper',
          preferred_primary_tools: ['code.function.cfg', 'workflow.summarize', 'report.summarize'],
          graph_semantics: {
            surface_role: 'render_export_helper',
            confidence_state: 'observed',
            upstream_surface: 'code.function.cfg',
            omissions: [
              {
                code: 'render_only',
                reason:
                  'graphviz.render only converts an existing DOT graph into SVG or PNG. It does not add deeper analysis semantics on its own.',
              },
            ],
          },
          format: input.format,
          layout: input.layout,
          preview: {
            inline_text: input.format === 'svg' ? preview.text : undefined,
            truncated: preview.truncated,
            char_count: previewSource.length,
          },
          artifact,
          summary: `Rendered DOT input with Graphviz ${backend.version || 'unknown version'} using layout=${input.layout} to ${input.format}.`,
          recommended_next_tools: ['artifact.read', 'code.function.cfg', 'workflow.summarize'],
          next_actions: artifact
            ? [
                'Read the persisted artifact if you need the full rendered payload or share it downstream.',
                'Return to code.function.cfg or workflow.summarize when you need the graph semantics, not just the rendered asset.',
              ]
            : ['Enable persist_artifact to keep the rendered output under reports/backend_tools.'],
        },
        artifacts,
        metrics: buildMetrics(startTime, graphvizRenderToolDefinition.name),
      }
    } catch (error) {
      return {
        ok: false,
        errors: [normalizeError(error)],
        metrics: buildMetrics(startTime, graphvizRenderToolDefinition.name),
      }
    }
  }
}
