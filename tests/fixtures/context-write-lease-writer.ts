import fs from 'fs/promises'
import path from 'path'
import { DatabaseManager } from '../../src/database.js'
import { createAnalysisCaseCheckpointHandler } from '../../src/plugins/kb-collaboration/tools/analysis-case-checkpoint.js'
import { createAnalysisClaimsApplyHandler } from '../../src/plugins/kb-collaboration/tools/analysis-claims-apply.js'
import { WorkspaceManager } from '../../src/workspace-manager.js'

interface WriterConfig {
  kind: 'claim' | 'case'
  databasePath: string
  workspaceRoot: string
  sampleId: string
  caseId?: string
  suffix: string
  readyPath?: string
  releasePath?: string
}

interface WriterResult {
  ok: boolean
  errors?: string[]
}

const config = JSON.parse(process.argv[2] || '{}') as WriterConfig
const originalOpen = fs.open.bind(fs)
let paused = false

if (config.readyPath && config.releasePath) {
  // Pause at the first filesystem-lock open. The production writer reaches this point only
  // after acquiring its SQLite lease, which gives the parent a deterministic hand-off point.
  ;(fs as unknown as { open: typeof fs.open }).open = (async (
    ...args: Parameters<typeof fs.open>
  ) => {
    const target = String(args[0])
    const flags = args[1]
    const basename = path.basename(target)
    const isContextLock =
      basename === '.analysis-claim-ledger.lock' ||
      (basename.startsWith('.analysis-case-') && basename.endsWith('.lock'))

    if (!paused && flags === 'wx' && isContextLock) {
      paused = true
      await fs.writeFile(config.readyPath!, 'ready', 'utf8')
      await waitForFile(config.releasePath!, 30_000)
    }

    return await originalOpen(...args)
  }) as typeof fs.open
}

let database: DatabaseManager | null = null
let result: WriterResult

try {
  database = new DatabaseManager(config.databasePath)
  const workspaceManager = new WorkspaceManager(config.workspaceRoot)

  if (config.kind === 'claim') {
    const handler = createAnalysisClaimsApplyHandler(workspaceManager, database)
    result = await handler({
      sample_id: config.sampleId,
      producer: { kind: 'llm', model_name: `lease-${config.suffix}` },
      claims: [
        {
          claim_id: `claim-recovery-${config.suffix}`,
          category: 'open_question',
          subject: 'Cross-process lease recovery',
          statement: 'Only one stale-lock recovery writer may commit.',
          status: 'inferred',
        },
      ],
    })
  } else {
    if (!config.caseId) throw new Error('caseId is required for a Case writer.')
    const handler = createAnalysisCaseCheckpointHandler(workspaceManager, database)
    result = await handler({
      sample_id: config.sampleId,
      case_id: config.caseId,
      state: {
        objective: 'Only one stale-lock recovery writer may checkpoint.',
        decisions: [],
        open_questions: [],
        attempted_actions: [],
        active_claim_ids: [],
        pinned_artifact_ids: [],
        next_actions: [],
      },
    })
  }
} catch (error) {
  result = {
    ok: false,
    errors: [error instanceof Error ? error.message : String(error)],
  }
} finally {
  database?.close()
  ;(fs as unknown as { open: typeof fs.open }).open = originalOpen
}

process.stdout.write(`LEASE_RESULT:${JSON.stringify(result)}\n`)

async function waitForFile(filePath: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      await fs.access(filePath)
      return
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 5))
    }
  }
  throw new Error(`Timed out waiting for release file: ${filePath}`)
}
