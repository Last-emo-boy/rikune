/**
 * report.html.generate MCP tool — Generate a self-contained HTML analysis report
 * for a sample, pulling from all available evidence. Includes sections for
 * static analysis, dynamic behavior, strings, IoCs, and threat scoring.
 */

import { z } from 'zod'
import {
  ArtifactRefSchema,
  createWorkerResultOutputSchema,
  type ToolDefinition,
  type WorkerResult,
  type ArtifactRef,
  type PluginToolDeps,
} from '../../sdk.js'
import path from 'node:path'
import fs from 'node:fs/promises'
import { createHash, randomUUID } from 'node:crypto'

const TOOL_NAME = 'report.html.generate'
const HTML_REPORT_ARTIFACT_TYPE = 'html_report'
const HTML_REPORT_RECOMMENDED_NEXT_TOOLS = ['artifact.read', 'workflow.search']

export const ReportHtmlGenerateInputSchema = z.object({
  sample_id: z.string().describe('Sample ID (format: sha256:<hex>)'),
  title: z.string().optional().describe('Custom report title'),
  sections: z
    .array(z.enum(['overview', 'static', 'dynamic', 'strings', 'iocs', 'threat_score']))
    .optional()
    .default(['overview', 'static', 'dynamic', 'strings', 'iocs', 'threat_score'])
    .describe('Sections to include'),
})

const HtmlReportArtifactReadArgsSchema = z.object({
  sample_id: z.string(),
  artifact_id: z.string().optional(),
  path: z.string().optional(),
  read_mode: z.enum(['profile', 'summary', 'content']),
  include_content: z.boolean().optional(),
})

const HtmlReportArtifactReadSchema = z.object({
  tool: z.literal('artifact.read'),
  args: HtmlReportArtifactReadArgsSchema,
})

const HtmlReportWorkflowHandoffSchema = z
  .object({
    schema: z.literal('rikune.html_report.workflow_handoff.v1'),
    source_tool: z.literal(TOOL_NAME),
    sample_id: z.string(),
    read_args: HtmlReportArtifactReadArgsSchema,
    artifact_contract: z.record(z.string(), z.any()),
    routing: z.array(z.record(z.string(), z.any())),
    dynamic_boundary: z.record(z.string(), z.any()),
  })
  .passthrough()

export const ReportHtmlGenerateOutputSchema = createWorkerResultOutputSchema(
  z.object({
    report_path: z.string(),
    artifact_id: z.string(),
    artifact: ArtifactRefSchema,
    sha256: z.string(),
    artifact_refs: z.array(ArtifactRefSchema),
    artifact_read: HtmlReportArtifactReadSchema,
    sections_included: z.array(
      z.enum(['overview', 'static', 'dynamic', 'strings', 'iocs', 'threat_score'])
    ),
    evidence_used: z.number().int().nonnegative(),
    html_size: z.number().int().nonnegative(),
    recommended_next_tools: z.array(z.string()),
    next_actions: z.array(z.string()),
    workflow_handoff: HtmlReportWorkflowHandoffSchema,
    quality_gates: z.record(z.string(), z.any()),
  })
)

export const reportHtmlGenerateToolDefinition: ToolDefinition = {
  name: TOOL_NAME,
  description:
    'Generate a self-contained HTML report for a sample analysis. Aggregates all ' +
    'available evidence into a professional report with overview, static analysis, ' +
    'dynamic behavior, strings, IoCs, and threat scoring sections.',
  inputSchema: ReportHtmlGenerateInputSchema,
  outputSchema: ReportHtmlGenerateOutputSchema,
  aspects: {
    formats: ['artifact', 'report', 'html-report'],
    platforms: ['all', 'cross-platform'],
    execution: ['static', 'correlation'],
    safety: ['passive'],
    capabilities: ['html-report-generation', 'report-export', 'artifact-handoff'],
    evidence: ['artifact', 'provenance', 'behavior', 'network', 'strings'],
  },
  artifacts: [
    {
      type: HTML_REPORT_ARTIFACT_TYPE,
      description: 'Self-contained HTML analysis report',
      mime: 'text/html',
    },
  ],
  evidence: [{ category: 'artifact', artifactTypes: [HTML_REPORT_ARTIFACT_TYPE] }],
  workflowRecipes: [
    {
      id: 'visualization.html-report-artifact',
      title: 'Generate HTML report artifact',
      description:
        'Aggregate existing analysis evidence into a self-contained HTML report and hand it off to artifact.read without exposing broader visualization tools.',
      startsWith: [TOOL_NAME],
      nextTools: HTML_REPORT_RECOMMENDED_NEXT_TOOLS,
      producesArtifacts: [HTML_REPORT_ARTIFACT_TYPE],
      evidence: ['artifact', 'provenance', 'report'],
      safety: ['passive', 'no_live_sample_by_default', 'no_network_by_default'],
    },
  ],
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

function severityBadge(level: string): string {
  const colors: Record<string, string> = {
    critical: '#dc3545',
    high: '#fd7e14',
    medium: '#ffc107',
    low: '#28a745',
    info: '#17a2b8',
  }
  const color = colors[level] ?? '#6c757d'
  return `<span style="background:${escapeHtml(color)};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">${escapeHtml(level.toUpperCase())}</span>`
}

export function createReportHtmlGenerateHandler(deps: PluginToolDeps) {
  const { workspaceManager, database } = deps

  return async (args: unknown): Promise<WorkerResult> => {
    const t0 = Date.now()
    const warnings: string[] = []

    try {
      const input = ReportHtmlGenerateInputSchema.parse(args || {})
      const sample = database.findSample(input.sample_id)
      if (!sample) return { ok: false, errors: [`Sample not found: ${input.sample_id}`] }

      const fileName = sample.file_type ?? input.sample_id
      const reportTitle = input.title ?? `Analysis Report: ${fileName}`

      const evidence = database.findAnalysisEvidenceBySample(input.sample_id)
      const allEvidence: Array<{ family: string; data: Record<string, unknown> }> = []
      if (Array.isArray(evidence)) {
        for (const entry of evidence) {
          try {
            const data =
              typeof entry.result_json === 'string'
                ? JSON.parse(entry.result_json)
                : entry.result_json
            allEvidence.push({ family: entry.evidence_family ?? 'unknown', data })
          } catch {
            /* skip */
          }
        }
      }

      // Gather data for each section
      const sections: string[] = []

      // --- Overview ---
      if (input.sections.includes('overview')) {
        let overview = `<h2>Overview</h2><table class="info-table">`
        overview += `<tr><td><strong>Sample ID</strong></td><td><code>${escapeHtml(input.sample_id)}</code></td></tr>`
        overview += `<tr><td><strong>Filename</strong></td><td>${escapeHtml(fileName)}</td></tr>`
        overview += `<tr><td><strong>File Size</strong></td><td>${escapeHtml(String(sample.size))} bytes</td></tr>`
        if (sample.file_type)
          overview += `<tr><td><strong>File Type</strong></td><td>${escapeHtml(sample.file_type)}</td></tr>`
        overview += `<tr><td><strong>Evidence Entries</strong></td><td>${allEvidence.length}</td></tr>`
        overview += `</table>`
        sections.push(overview)
      }

      // --- Static Analysis ---
      if (input.sections.includes('static')) {
        let staticSection = `<h2>Static Analysis</h2>`
        const staticFamilies = [
          'pe_fingerprint',
          'pe_imports',
          'pe_exports',
          'pe_structure',
          'elf_structure',
          'macho_structure',
          'capability_triage',
          'packer_detect',
          'compiler_detect',
          'binary_role',
        ]
        const staticEvid = allEvidence.filter((e) => staticFamilies.includes(e.family))
        if (staticEvid.length === 0) {
          staticSection += `<p class="muted">No static analysis evidence available.</p>`
        } else {
          for (const ev of staticEvid) {
            staticSection += `<h3>${escapeHtml(ev.family)}</h3><pre>${escapeHtml(JSON.stringify(ev.data?.data ?? ev.data, null, 2).slice(0, 3000))}</pre>`
          }
        }
        sections.push(staticSection)
      }

      // --- Dynamic Behavior ---
      if (input.sections.includes('dynamic')) {
        let dynSection = `<h2>Dynamic Behavior</h2>`
        const dynFamilies = [
          'dynamic_trace',
          'frida_trace',
          'sandbox_execution',
          'sandbox_report',
          'speakeasy_trace',
          'runtime_trace',
        ]
        const dynEvid = allEvidence.filter((e) => dynFamilies.includes(e.family))
        if (dynEvid.length === 0) {
          dynSection += `<p class="muted">No dynamic analysis evidence available.</p>`
        } else {
          for (const ev of dynEvid) {
            const data = ev.data?.data ?? ev.data
            const threatScore = (data as Record<string, unknown>)?.threat_score
            if (threatScore !== undefined) {
              dynSection += `<p>Threat Score: <strong>${escapeHtml(String(threatScore))}</strong>/100</p>`
            }
            dynSection += `<h3>${escapeHtml(ev.family)}</h3><pre>${escapeHtml(JSON.stringify(data, null, 2).slice(0, 3000))}</pre>`
          }
        }
        sections.push(dynSection)
      }

      // --- Strings ---
      if (input.sections.includes('strings')) {
        let strSection = `<h2>Strings</h2>`
        const strEvid = allEvidence.filter(
          (e) => e.family === 'strings' || e.family === 'floss_strings'
        )
        if (strEvid.length === 0) {
          strSection += `<p class="muted">No string extraction evidence available.</p>`
        } else {
          for (const ev of strEvid) {
            const strs =
              (ev.data?.data as Record<string, unknown>)?.strings ?? ev.data?.strings ?? []
            const strArr = (strs as Array<unknown>).slice(0, 200)
            strSection += `<h3>${escapeHtml(ev.family)} (showing ${strArr.length})</h3><ul>`
            for (const s of strArr) {
              const val =
                typeof s === 'string' ? s : ((s as Record<string, unknown>)?.value ?? String(s))
              strSection += `<li><code>${escapeHtml(String(val).slice(0, 200))}</code></li>`
            }
            strSection += `</ul>`
          }
        }
        sections.push(strSection)
      }

      // --- IoCs ---
      if (input.sections.includes('iocs')) {
        let iocSection = `<h2>Indicators of Compromise</h2>`
        const iocEvid = allEvidence.filter(
          (e) => e.family === 'ioc_export' || e.family === 'c2_extract' || e.family === 'attack_map'
        )
        if (iocEvid.length === 0) {
          iocSection += `<p class="muted">No IoC evidence available.</p>`
        } else {
          for (const ev of iocEvid) {
            iocSection += `<h3>${escapeHtml(ev.family)}</h3><pre>${escapeHtml(JSON.stringify(ev.data?.data ?? ev.data, null, 2).slice(0, 3000))}</pre>`
          }
        }
        sections.push(iocSection)
      }

      // --- Threat Score Summary ---
      if (input.sections.includes('threat_score')) {
        let scoreSection = `<h2>Threat Assessment</h2>`
        const scores: Array<{ source: string; score: number; level: string }> = []
        for (const ev of allEvidence) {
          const data = (ev.data?.data ?? ev.data) as Record<string, unknown>
          if (data?.threat_score !== undefined) {
            scores.push({
              source: ev.family,
              score: data.threat_score as number,
              level: (data.threat_level ?? 'unknown') as string,
            })
          }
        }
        if (scores.length === 0) {
          scoreSection += `<p class="muted">No threat scores available.</p>`
        } else {
          const avg = Math.round(scores.reduce((s, e) => s + e.score, 0) / scores.length)
          const maxScore = scores.reduce((m, e) => Math.max(m, e.score), 0)
          const maxLevel =
            maxScore >= 70
              ? 'critical'
              : maxScore >= 40
                ? 'high'
                : maxScore >= 20
                  ? 'medium'
                  : 'low'
          scoreSection += `<div class="score-box"><span class="score">${avg}</span><span class="label">Average</span></div>`
          scoreSection += `<div class="score-box"><span class="score">${maxScore}</span><span class="label">Maximum</span></div>`
          scoreSection += `<p>Overall Level: ${severityBadge(maxLevel)}</p>`
          scoreSection += `<table class="info-table"><tr><th>Source</th><th>Score</th><th>Level</th></tr>`
          for (const s of scores) {
            scoreSection += `<tr><td>${escapeHtml(s.source)}</td><td>${s.score}</td><td>${severityBadge(s.level)}</td></tr>`
          }
          scoreSection += `</table>`
        }
        sections.push(scoreSection)
      }

      // Assemble HTML
      const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(reportTitle)}</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; color: #333; }
  .container { max-width: 1100px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
  h1 { border-bottom: 3px solid #007bff; padding-bottom: 10px; }
  h2 { color: #007bff; border-bottom: 1px solid #dee2e6; padding-bottom: 8px; margin-top: 30px; }
  h3 { color: #495057; }
  pre { background: #f8f9fa; border: 1px solid #dee2e6; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 12px; max-height: 400px; overflow-y: auto; }
  code { background: #e9ecef; padding: 1px 4px; border-radius: 3px; font-size: 13px; }
  .info-table { width: 100%; border-collapse: collapse; margin: 10px 0; }
  .info-table td, .info-table th { padding: 8px 12px; border: 1px solid #dee2e6; text-align: left; }
  .info-table tr:nth-child(even) { background: #f8f9fa; }
  .muted { color: #6c757d; font-style: italic; }
  .score-box { display: inline-block; text-align: center; margin: 10px 20px 10px 0; padding: 15px 25px; background: #f8f9fa; border-radius: 8px; border: 1px solid #dee2e6; }
  .score-box .score { display: block; font-size: 36px; font-weight: bold; color: #007bff; }
  .score-box .label { display: block; font-size: 12px; color: #6c757d; }
  .footer { margin-top: 30px; padding-top: 15px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 12px; }
  ul { max-height: 300px; overflow-y: auto; }
</style>
</head>
<body>
<div class="container">
<h1>${escapeHtml(reportTitle)}</h1>
<p class="muted">Generated: ${new Date().toISOString()}</p>
${sections.join('\n')}
<div class="footer">
  <p>Generated by Binary Analysis MCP Server &mdash; ${new Date().toISOString()}</p>
</div>
</div>
</body>
</html>`

      // Write to workspace
      const workspace = await workspaceManager.createWorkspace(input.sample_id)
      const outDir = workspace.reports
      await fs.mkdir(outDir, { recursive: true })
      const safeName = input.sample_id.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 80)
      const artifactId = randomUUID()
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
      const outFile = path.join(
        outDir,
        `${safeName}_report_${timestamp}_${artifactId.slice(0, 8)}.html`
      )
      await fs.writeFile(outFile, html, 'utf-8')

      const reportSha256 = createHash('sha256').update(html).digest('hex')
      const relativePath = path.relative(workspace.root, outFile).replace(/\\/g, '/')
      const artifact: ArtifactRef = {
        id: artifactId,
        type: HTML_REPORT_ARTIFACT_TYPE,
        path: relativePath,
        sha256: reportSha256,
        mime: 'text/html',
        metadata: {
          source_tool: TOOL_NAME,
          sample_id: input.sample_id,
          surface_role: 'html_report_export',
          sections_included: input.sections,
          evidence_used: allEvidence.length,
          html_size: Buffer.byteLength(html, 'utf8'),
        },
      }
      let artifactRegistered = false
      if (typeof database.insertArtifact === 'function') {
        database.insertArtifact({
          id: artifact.id,
          sample_id: input.sample_id,
          type: artifact.type,
          path: artifact.path,
          sha256: artifact.sha256,
          mime: artifact.mime,
          created_at: new Date().toISOString(),
        })
        artifactRegistered = true
      } else {
        warnings.push('Database artifact registration unavailable; returning inline artifact ref.')
      }

      const artifactRead = {
        tool: 'artifact.read',
        args: artifactRegistered
          ? {
              sample_id: input.sample_id,
              artifact_id: artifact.id,
              read_mode: 'content' as const,
              include_content: true,
            }
          : {
              sample_id: input.sample_id,
              path: artifact.path,
              read_mode: 'content' as const,
              include_content: true,
            },
      }
      const workflowHandoff = {
        schema: 'rikune.html_report.workflow_handoff.v1',
        source_tool: TOOL_NAME,
        sample_id: input.sample_id,
        read_args: artifactRead.args,
        artifact_contract: {
          produces: [HTML_REPORT_ARTIFACT_TYPE],
          artifact_id: artifact.id,
          artifact_path: artifact.path,
          sha256: artifact.sha256,
          mime: artifact.mime,
          expected_consumers: ['artifact.read'],
        },
        routing: [
          {
            goal: 'read-generated-html-report',
            next_tools: ['artifact.read'],
            artifact_id: artifact.id,
            read_mode: 'content',
            read_args: artifactRead.args,
          },
          {
            goal: 'continue-profile-routing',
            next_tools: ['workflow.search'],
            query: 'html report evidence summary',
          },
        ],
        dynamic_boundary: {
          runtime_started_by_tool: false,
          sample_executed_by_tool: false,
          network_accessed_by_tool: false,
          mutation_performed: false,
        },
      }
      const qualityGates = {
        schema: 'rikune.html_report.quality_gates.v1',
        passive_correlation_only: true,
        sample_executed_by_tool: false,
        network_accessed_by_tool: false,
        mutation_performed: false,
        artifact_persisted: artifactRegistered,
        artifact_file_written: true,
        artifact_registered: artifactRegistered,
        html_nonempty: html.length > 0,
        evidence_present: allEvidence.length > 0,
        section_count: input.sections.length,
      }
      const artifacts: ArtifactRef[] = [artifact]

      return {
        ok: true,
        data: {
          report_path: outFile,
          artifact_id: artifact.id,
          artifact,
          sha256: artifact.sha256,
          artifact_refs: artifacts,
          artifact_read: artifactRead,
          sections_included: input.sections,
          evidence_used: allEvidence.length,
          html_size: Buffer.byteLength(html, 'utf8'),
          recommended_next_tools: HTML_REPORT_RECOMMENDED_NEXT_TOOLS,
          next_actions: [
            'Use artifact.read with the returned html_report artifact_id to inspect or download the generated report.',
            'Use workflow.search when you need another report, evidence, or visualization follow-up.',
          ],
          workflow_handoff: workflowHandoff,
          quality_gates: qualityGates,
        },
        warnings: warnings.length > 0 ? warnings : undefined,
        artifacts,
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    } catch (err) {
      return {
        ok: false,
        errors: [`${TOOL_NAME} failed: ${err instanceof Error ? err.message : String(err)}`],
        metrics: { elapsed_ms: Date.now() - t0, tool: TOOL_NAME },
      }
    }
  }
}
