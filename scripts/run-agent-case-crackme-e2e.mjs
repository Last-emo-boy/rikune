#!/usr/bin/env node

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js'

const DEFAULT_TIMEOUT_MS = 300_000
const CONTEXT_ONLY_ARTIFACT_TYPES = new Set([
  'analysis_claim_set',
  'analysis_case_state',
  'workflow_summary',
  'summary_triage_digest',
  'summary_static_digest',
  'summary_deep_digest',
  'summary_final_digest',
  'report_summary',
  'analysis_report',
  'html_report',
  'report',
])
const BASE_ACTIVATION_TARGETS = [
  'elf.structure.analyze',
  'binary.hardening.inventory',
  'strings.extract',
  'analysis.context.pack',
  'analysis.claims.apply',
  'analysis.case.checkpoint',
  'analysis.case.snapshot',
  'workflow.summarize',
  'artifact.read',
]
const DEEP_ACTIVATION_TARGETS = [
  'ghidra.analyze',
  'task.status',
  'code.functions.list',
  'code.function.decompile',
]

function usage() {
  return `Usage:
  node scripts/run-agent-case-crackme-e2e.mjs \\
    --container <running-rikune-container> \\
    --binary <absolute-path-inside-container> [options]

Required:
  --container <name>       Running Rikune container name.
                           Env fallback: RIKUNE_DOCKER_CONTAINER
  --binary <path>          Absolute crackme path inside that container.
                           Env fallback: RIKUNE_CRACKME_BINARY_PATH

Options:
  --node-entry <path>      MCP server entry inside the container (default: dist/index.js).
  --session-tag <tag>      Artifact/session tag (default: generated per run).
  --case-id <id>           Optional new Case Workspace ID; omit to let Rikune generate one.
  --deep                   Also run Ghidra, list functions, and decompile bounded candidates.
  --timeout-ms <ms>        Per MCP request timeout (default: ${DEFAULT_TIMEOUT_MS}).
  -h, --help               Show this usage text.

The container must already run the Rikune HTTP upload daemon. The script keeps one
StdioClientTransport (one long-lived docker exec MCP session) for every MCP call and
uses one additional docker exec curl command only to POST the crackme bytes.`
}

function optionValue(argv, index, inlineValue) {
  if (inlineValue !== undefined) return { value: inlineValue, nextIndex: index }
  if (index + 1 >= argv.length || argv[index + 1].startsWith('--')) {
    throw new Error(`Missing value for ${argv[index]}`)
  }
  return { value: argv[index + 1], nextIndex: index + 1 }
}

function parseArgs(argv) {
  const parsed = {}
  for (let index = 0; index < argv.length; index += 1) {
    const raw = argv[index]
    if (raw === '-h' || raw === '--help') {
      return { help: true }
    }
    if (!raw.startsWith('--')) {
      throw new Error(`Unexpected positional argument: ${raw}`)
    }
    const separator = raw.indexOf('=')
    const name = separator >= 0 ? raw.slice(0, separator) : raw
    const inlineValue = separator >= 0 ? raw.slice(separator + 1) : undefined
    if (name === '--deep') {
      if (inlineValue !== undefined) throw new Error('--deep does not accept a value.')
      parsed.deep = true
      continue
    }
    const supported = new Map([
      ['--container', 'container'],
      ['--binary', 'binaryPath'],
      ['--node-entry', 'nodeEntry'],
      ['--session-tag', 'sessionTag'],
      ['--case-id', 'caseId'],
      ['--timeout-ms', 'timeoutMs'],
    ])
    const key = supported.get(name)
    if (!key) throw new Error(`Unknown option: ${name}`)
    const resolved = optionValue(argv, index, inlineValue)
    parsed[key] = resolved.value
    index = resolved.nextIndex
  }

  const container = parsed.container || process.env.RIKUNE_DOCKER_CONTAINER
  const binaryPath = parsed.binaryPath || process.env.RIKUNE_CRACKME_BINARY_PATH
  if (!container || !binaryPath) {
    throw new Error('Both --container and --binary are required (or provide their env fallbacks).')
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(container)) {
    throw new Error('--container must be a Docker-safe container name.')
  }
  if (!binaryPath.startsWith('/') || binaryPath.includes('\0')) {
    throw new Error('--binary must be an absolute path inside the container.')
  }

  const nodeEntry = parsed.nodeEntry || 'dist/index.js'
  if (!nodeEntry || nodeEntry.includes('\0')) throw new Error('--node-entry must not be empty.')
  const sessionTag = parsed.sessionTag || `agent-case-crackme-e2e-${Date.now()}`
  if (sessionTag.length > 200) throw new Error('--session-tag must be at most 200 characters.')
  if (parsed.caseId && !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(parsed.caseId)) {
    throw new Error('--case-id must use letters, numbers, dot, underscore, colon, or hyphen.')
  }
  const timeoutMs = Number(parsed.timeoutMs || DEFAULT_TIMEOUT_MS)
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000) {
    throw new Error('--timeout-ms must be an integer greater than or equal to 1000.')
  }

  return {
    help: false,
    container,
    binaryPath,
    nodeEntry,
    sessionTag,
    caseId: parsed.caseId,
    deep: parsed.deep === true,
    timeoutMs,
  }
}

function isRecord(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value)
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function transportToolName(canonicalName) {
  const replaced = canonicalName
    .replaceAll('.', '_')
    .replace(/[^A-Za-z0-9_-]/g, '_')
    .replace(/_+/g, '_')
  return /^[A-Za-z]/.test(replaced) ? replaced : `tool_${replaced}`
}

function payloadFromCallResult(result, canonicalName) {
  if (isRecord(result.structuredContent)) return result.structuredContent
  for (const item of asArray(result.content)) {
    if (!isRecord(item) || item.type !== 'text' || typeof item.text !== 'string') continue
    try {
      const parsed = JSON.parse(item.text)
      if (isRecord(parsed)) return parsed
    } catch {
      continue
    }
  }
  throw new Error(`${canonicalName} returned no structured JSON payload.`)
}

function formatWorkerErrors(payload) {
  const errors = asArray(payload.errors).filter((item) => typeof item === 'string')
  return errors.length > 0 ? errors.join('; ') : 'unknown tool failure'
}

async function callTool(client, canonicalName, args, timeoutMs) {
  const result = await client.callTool(
    {
      name: transportToolName(canonicalName),
      arguments: args,
    },
    undefined,
    {
      timeout: timeoutMs,
      maxTotalTimeout: timeoutMs,
    }
  )
  const payload = payloadFromCallResult(result, canonicalName)
  if (result.isError || payload.ok !== true) {
    throw new Error(`${canonicalName} failed: ${formatWorkerErrors(payload)}`)
  }
  assert.ok(isRecord(payload.data), `${canonicalName} must return a data object.`)
  return payload
}

async function visibleToolNames(client, timeoutMs) {
  const names = []
  let cursor
  do {
    const response = await client.listTools(cursor ? { cursor } : undefined, {
      timeout: timeoutMs,
      maxTotalTimeout: timeoutMs,
    })
    names.push(...asArray(response.tools).map((tool) => tool.name))
    cursor = response.nextCursor
  } while (cursor)
  return new Set(names)
}

async function activateExactTool(client, canonicalName, timeoutMs) {
  const target = transportToolName(canonicalName)
  const before = await visibleToolNames(client, timeoutMs)
  const discovery = await callTool(
    client,
    'workflow.search',
    {
      query: `tool:${canonicalName}`,
      top_k: 5,
    },
    timeoutMs
  )
  assert.ok(
    asArray(discovery.data.results).some(
      (result) =>
        result?.result_id === `tool:${canonicalName}` && result?.tool_name === canonicalName
    ),
    `Exact discovery did not return tool:${canonicalName}.`
  )
  const activation = await callTool(
    client,
    'workflow.search',
    {
      action: 'activate',
      result_id: `tool:${canonicalName}`,
      query: `tool:${canonicalName}`,
    },
    timeoutMs
  )
  const data = activation.data
  assert.deepEqual(
    data.activated_tools,
    [canonicalName],
    `Exact activation for ${canonicalName} exposed an unexpected tool set.`
  )
  assert.equal(
    data.activation_audit?.policy?.backend_execution_started,
    false,
    `Activation for ${canonicalName} must not start a backend.`
  )
  const after = await visibleToolNames(client, timeoutMs)
  assert.ok(after.has(target), `${canonicalName} was not visible after exact activation.`)
  const newlyVisible = [...after].filter((name) => !before.has(name)).sort()
  const expectedNew = before.has(target) ? [] : [target]
  assert.deepEqual(
    newlyVisible,
    expectedNew,
    `Exact activation for ${canonicalName} exposed sibling tools: ${newlyVisible.join(', ')}`
  )
  return canonicalName
}

function filenameFromContainerPath(binaryPath) {
  const segments = binaryPath.replaceAll('\\', '/').split('/').filter(Boolean)
  return segments.at(-1) || 'crackme.bin'
}

function uploadWithContainerCurl(config, uploadUrl) {
  const result = spawnSync(
    'docker',
    [
      'exec',
      config.container,
      'curl',
      '--fail-with-body',
      '--silent',
      '--show-error',
      '--request',
      'POST',
      '--header',
      'Content-Type: application/octet-stream',
      '--data-binary',
      `@${config.binaryPath}`,
      uploadUrl,
    ],
    {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      timeout: config.timeoutMs,
    }
  )
  if (result.error) throw result.error
  if (result.status !== 0) {
    throw new Error(
      `Container curl upload failed (exit=${result.status}): ${(result.stderr || result.stdout).trim()}`
    )
  }
  let payload
  try {
    payload = JSON.parse(result.stdout)
  } catch {
    throw new Error(`Container curl upload returned invalid JSON: ${result.stdout.trim()}`)
  }
  assert.equal(payload.ok, true, 'Upload response must have ok=true.')
  assert.ok(isRecord(payload.data), 'Upload response must contain data.')
  assert.match(payload.data.sample_id, /^sha256:[a-f0-9]{64}$/i)
  return payload.data
}

function artifactRefsFromEvidenceEntries(entries) {
  return asArray(entries).flatMap((entry) => (isRecord(entry) ? asArray(entry.artifact_refs) : []))
}

function assertNoClaimOrCaseRefs(refs, forbiddenIds, label) {
  for (const ref of refs) {
    assert.ok(isRecord(ref), `${label} contains a non-object artifact reference.`)
    const artifactType = ref.type || ref.artifact_type
    assert.ok(
      !CONTEXT_ONLY_ARTIFACT_TYPES.has(artifactType) &&
        !(typeof artifactType === 'string' && artifactType.startsWith('report_')),
      `${label} promoted context-only artifact type ${artifactType} into evidence/source refs.`
    )
    assert.ok(
      !forbiddenIds.has(ref.id) && !forbiddenIds.has(ref.artifact_id),
      `${label} promoted a Claim/Case artifact ID into evidence/source refs.`
    )
  }
}

function assertContextPackBoundaries(data, forbiddenIds = new Set()) {
  const primary = asArray(data.primary_evidence)
  const derived = asArray(data.derived_evidence)
  assertNoClaimOrCaseRefs(
    artifactRefsFromEvidenceEntries(primary),
    forbiddenIds,
    'context.primary_evidence'
  )
  assertNoClaimOrCaseRefs(
    artifactRefsFromEvidenceEntries(derived),
    forbiddenIds,
    'context.derived_evidence'
  )
  for (const entry of primary) assert.equal(entry.evidence_class, 'primary')
  for (const entry of derived) assert.equal(entry.evidence_class, 'derived')
  const evidenceJson = JSON.stringify({ primary, derived })
  for (const artifactId of forbiddenIds) {
    assert.ok(
      !evidenceJson.includes(artifactId),
      `Claim/Case artifact ${artifactId} leaked into primary or derived evidence.`
    )
  }
}

function assertSummaryBoundaries(data, forbiddenIds, claimStatement, caseQuestion) {
  const final = data.stages?.final
  assert.ok(isRecord(final), 'workflow.summarize must return the final stage.')
  assert.equal(data.synthesis?.resolved_mode, 'deterministic')
  assert.equal(final.synthesis_mode, 'deterministic')
  assert.equal(final.claim_context?.artifact_role, 'context_only')
  assert.equal(final.case_context?.artifact_role, 'context_only')
  assert.equal(final.review_required, true)
  assert.ok(
    asArray(final.unresolved_questions).includes(claimStatement),
    'Final summary must preserve the new inferred open question.'
  )

  for (const [stageName, stage] of Object.entries(data.stages || {})) {
    assertNoClaimOrCaseRefs(
      asArray(stage?.source_artifact_refs),
      forbiddenIds,
      `summary.${stageName}.source_artifact_refs`
    )
  }
  const finalSourceJson = JSON.stringify(final.source_artifact_refs || [])
  for (const artifactId of forbiddenIds) assert.ok(!finalSourceJson.includes(artifactId))

  const triageEvidence = JSON.stringify(data.stages?.triage?.evidence || [])
  assert.ok(!triageEvidence.includes(claimStatement), 'Claim text must not become triage evidence.')
  assert.ok(!triageEvidence.includes(caseQuestion), 'Case text must not become triage evidence.')
  for (const claim of asArray(final.claim_context?.claims)) {
    assert.ok(
      !('supporting_evidence' in claim),
      'Final claim context must not inline evidence refs.'
    )
    assert.ok(
      !('claim_set_artifact_id' in claim),
      'Final claim context must not inline Claim refs.'
    )
  }
  assert.ok(!('pinned_artifacts' in final.case_context))
  assert.ok(!('result_artifacts' in final.case_context))
}

function logStep(message) {
  process.stderr.write(`[agent-case-e2e] ${message}\n`)
}

function wait(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds))
}

async function waitForJob(client, jobId, timeoutMs) {
  const deadline = Date.now() + timeoutMs
  let latest
  while (Date.now() < deadline) {
    latest = await callTool(
      client,
      'task.status',
      { job_id: jobId, include_result: true },
      timeoutMs
    )
    const status = latest.data.job?.status
    if (status === 'completed') return latest
    if (status === 'failed' || status === 'cancelled' || status === 'interrupted') {
      throw new Error(`Ghidra job ${jobId} ended with status=${status}.`)
    }
    await wait(2_000)
  }
  throw new Error(`Timed out waiting for Ghidra job ${jobId}.`)
}

function selectDecompileCandidates(functions, limit = 8) {
  const ranked = [...functions].sort((left, right) => {
    const leftMain = left?.name === 'main' ? 1 : 0
    const rightMain = right?.name === 'main' ? 1 : 0
    if (leftMain !== rightMain) return rightMain - leftMain
    return Number(right?.size || 0) - Number(left?.size || 0)
  })
  const preferred = ranked.filter(
    (entry) =>
      entry?.name === 'main' || (typeof entry?.name === 'string' && entry.name.startsWith('FUN_'))
  )
  return (preferred.length > 0 ? preferred : ranked).slice(0, limit)
}

async function main() {
  let config
  try {
    config = parseArgs(process.argv.slice(2))
  } catch (error) {
    process.stderr.write(`${error.message}\n\n${usage()}\n`)
    process.exitCode = 2
    return
  }
  if (config.help) {
    process.stdout.write(`${usage()}\n`)
    return
  }

  const transport = new StdioClientTransport({
    command: 'docker',
    args: [
      'exec',
      '-i',
      '-e',
      'API_ENABLED=false',
      '-e',
      'NODE_ENV=production',
      '-e',
      'PYTHONUNBUFFERED=1',
      config.container,
      'node',
      config.nodeEntry,
    ],
    stderr: 'inherit',
  })
  const client = new Client(
    { name: 'rikune-agent-case-crackme-e2e', version: '1.0.0' },
    { capabilities: {} }
  )

  try {
    logStep(`connecting to ${config.container} through one persistent stdio transport`)
    await client.connect(transport)
    const initialTools = await visibleToolNames(client, config.timeoutMs)
    assert.ok(initialTools.has(transportToolName('workflow.search')))
    assert.ok(initialTools.has(transportToolName('workflow.run')))

    const activationTargets = config.deep
      ? [...BASE_ACTIVATION_TARGETS, ...DEEP_ACTIVATION_TARGETS]
      : BASE_ACTIVATION_TARGETS
    const activated = []
    for (const canonicalName of activationTargets) {
      logStep(`exact activation: ${canonicalName}`)
      activated.push(await activateExactTool(client, canonicalName, config.timeoutMs))
    }

    logStep('creating upload session')
    const uploadSession = await callTool(
      client,
      'workflow.run',
      {
        action: 'request_upload',
        filename: filenameFromContainerPath(config.binaryPath),
        ttl_seconds: 600,
      },
      config.timeoutMs
    )
    assert.equal(uploadSession.data.action, 'request_upload')
    assert.equal(uploadSession.data.routed_tool, 'sample.request_upload')
    assert.equal(typeof uploadSession.data.upload_url, 'string')

    logStep('uploading crackme bytes with curl inside the container')
    const uploaded = uploadWithContainerCurl(config, uploadSession.data.upload_url)
    const sampleId = uploaded.sample_id

    const elfArgs = { sample_id: sampleId }
    logStep('analyzing ELF structure without execution')
    const elfResult = await callTool(client, 'elf.structure.analyze', elfArgs, config.timeoutMs)
    const elfArtifact = asArray(elfResult.artifacts).find(
      (artifact) => artifact?.type === 'elf_structure'
    )
    assert.ok(elfArtifact?.id, 'elf.structure.analyze must persist an ELF structure artifact.')

    const hardeningArgs = {
      sample_id: sampleId,
      max_read_bytes: 16 * 1024 * 1024,
      persist_artifact: true,
      session_tag: config.sessionTag,
    }
    logStep('inventorying passive binary hardening')
    const hardeningResult = await callTool(
      client,
      'binary.hardening.inventory',
      hardeningArgs,
      config.timeoutMs
    )
    const hardeningArtifact = asArray(hardeningResult.artifacts).find(
      (artifact) => artifact?.type === 'binary_hardening_inventory'
    )
    assert.ok(
      hardeningArtifact?.id,
      'binary.hardening.inventory must persist a hardening artifact.'
    )
    assert.equal(hardeningResult.data.policy?.no_execute, true)
    assert.equal(hardeningResult.data.quality_gates?.sample_executed_by_tool, false)
    assert.equal(hardeningResult.data.quality_gates?.loader_invoked_by_tool, false)
    assert.equal(hardeningResult.data.quality_gates?.network_used_by_tool, false)

    const staticArgs = {
      sample_id: sampleId,
      mode: 'preview',
      min_len: 4,
      encoding: 'all',
      max_strings: 200,
      max_string_length: 512,
      max_scan_bytes: 1024 * 1024,
      enrich_result: true,
      persist_artifact: true,
      force_refresh: true,
      defer_if_slow: false,
      session_tag: config.sessionTag,
    }
    logStep('running bounded static strings extraction')
    const staticResult = await callTool(client, 'strings.extract', staticArgs, config.timeoutMs)
    assert.equal(staticResult.data.status, 'ready')
    assert.notEqual(staticResult.data.execution_state, 'queued')
    const staticArtifact = asArray(staticResult.artifacts).find(
      (artifact) => artifact?.type === 'enriched_string_analysis'
    )
    assert.ok(staticArtifact?.id, 'strings.extract must persist an enriched string artifact.')

    logStep('persisting a bounded fast-profile analysis run')
    const analysisRun = await callTool(
      client,
      'workflow.run',
      {
        action: 'start',
        sample_id: sampleId,
        goal: 'triage',
        depth: 'safe',
        backend_policy: 'auto',
        allow_transformations: false,
        allow_live_execution: false,
        force_refresh: true,
      },
      config.timeoutMs
    )
    assert.equal(analysisRun.data.action, 'start')
    assert.equal(analysisRun.data.routed_tool, 'workflow.analyze.start')
    assert.match(analysisRun.data.plan_id, /\S+/)
    assert.equal(analysisRun.data.sample_id, sampleId)

    let deepAnalysis = null
    if (config.deep) {
      logStep('starting or reusing queued Ghidra analysis')
      const ghidra = await callTool(
        client,
        'ghidra.analyze',
        {
          sample_id: sampleId,
          options: {
            timeout: 240,
            max_cpu: '2',
          },
        },
        config.timeoutMs
      )
      let terminalJob = null
      if (ghidra.data.status === 'queued') {
        assert.match(ghidra.data.job_id, /\S+/)
        logStep(`waiting for Ghidra job ${ghidra.data.job_id}`)
        terminalJob = await waitForJob(client, ghidra.data.job_id, config.timeoutMs)
      } else {
        assert.ok(
          ghidra.data.status === 'completed' ||
            ghidra.data.status === 'reused' ||
            ghidra.data.status === 'partial_success',
          `Unexpected Ghidra status: ${ghidra.data.status}`
        )
      }

      logStep('listing Ghidra-backed functions')
      const functionList = await callTool(
        client,
        'code.functions.list',
        { sample_id: sampleId, backend: 'ghidra', limit: 256 },
        config.timeoutMs
      )
      assert.ok(functionList.data.count > 0, 'Ghidra must produce a non-empty function index.')
      const candidates = selectDecompileCandidates(functionList.data.functions)
      const decompiled = []
      for (const candidate of candidates) {
        logStep(`decompiling ${candidate.name} at ${candidate.address}`)
        try {
          const result = await callTool(
            client,
            'code.function.decompile',
            {
              sample_id: sampleId,
              address: candidate.address,
              include_xrefs: true,
              timeout: 120,
            },
            config.timeoutMs
          )
          decompiled.push(result.data)
        } catch (error) {
          decompiled.push({
            function: candidate.name,
            address: candidate.address,
            error: error instanceof Error ? error.message : String(error),
          })
        }
      }
      assert.ok(
        decompiled.some((entry) => typeof entry?.pseudocode === 'string'),
        'At least one bounded candidate must decompile successfully.'
      )
      deepAnalysis = {
        ghidra: {
          status: ghidra.data.status,
          result_mode: ghidra.data.result_mode,
          analysis_id: ghidra.data.analysis_id,
          job_id: ghidra.data.job_id || null,
          terminal_job_status: terminalJob?.data?.job?.status || null,
        },
        function_count: functionList.data.count,
        selected_functions: candidates,
        decompiled,
      }
    }

    const contextArgs = {
      sample_id: sampleId,
      goal: 'Explain the crackme validation path while preserving Claim and Case boundaries.',
      token_budget: 16_000,
      evidence_scope: 'latest',
      claim_scope: 'all',
      include_case: false,
    }
    logStep('building baseline analysis context')
    const baseline = await callTool(client, 'analysis.context.pack', contextArgs, config.timeoutMs)
    assert.match(baseline.data.marker, /^rikune-context-v1\./)
    assert.ok(
      asArray(baseline.data.primary_evidence).length +
        asArray(baseline.data.derived_evidence).length >
        0,
      'Baseline context must contain the static evidence produced above.'
    )
    assertContextPackBoundaries(baseline.data)

    const runKey = createHash('sha256')
      .update(`${config.sessionTag}:${sampleId}:${Date.now()}`)
      .digest('hex')
      .slice(0, 16)
    const hypothesisClaimId = `claim_crackme_strings_${runKey}`
    const hardeningClaimId = `claim_crackme_hardening_${runKey}`
    const questionClaimId = `claim_crackme_input_${runKey}`
    const hypothesisStatement =
      'The passive ELF and string artifacts do not yet establish which input satisfies the validation path.'
    const hardeningSummary = String(
      hardeningResult.data.summary || 'Passive hardening inventory completed.'
    ).slice(0, 900)
    const openQuestion = 'Which concrete input satisfies the crackme validation path?'

    logStep('persisting inferred Claim Ledger entries')
    const claims = await callTool(
      client,
      'analysis.claims.apply',
      {
        sample_id: sampleId,
        goal: 'Record bounded crackme hypotheses for follow-up analysis.',
        session_tag: config.sessionTag,
        producer: {
          kind: 'llm',
          client_name: 'run-agent-case-crackme-e2e',
          model_name: 'scripted-e2e',
        },
        claims: [
          {
            claim_id: hardeningClaimId,
            category: 'finding',
            subject: 'ELF hardening posture',
            statement: hardeningSummary,
            status: 'inferred',
            supporting_evidence: [
              {
                artifact_id: hardeningArtifact.id,
                summary: 'Passive hardening inventory produced in this E2E session.',
              },
            ],
            falsification_tests: [
              'Re-parse the ELF program headers and dynamic flags with an independent parser.',
            ],
          },
          {
            claim_id: hypothesisClaimId,
            category: 'hypothesis',
            subject: 'Crackme validation path',
            statement: hypothesisStatement,
            status: 'inferred',
            supporting_evidence: [
              {
                artifact_id: elfArtifact.id,
                summary: 'Canonical ELF structure artifact produced in this E2E session.',
              },
              {
                artifact_id: staticArtifact.id,
                summary: 'Bounded static strings artifact produced in this E2E session.',
              },
            ],
            assumptions: ['The decisive validation logic remains in native code.'],
            alternatives: [
              'The decisive check may be encoded or computed without readable strings.',
            ],
            falsification_tests: [
              'Trace references to high-value strings and verify whether they reach an input comparison.',
            ],
          },
          {
            claim_id: questionClaimId,
            category: 'open_question',
            subject: 'Satisfying input',
            statement: openQuestion,
            status: 'inferred',
            falsification_tests: [
              'Recover the validation branch and test a candidate input in an explicitly approved runtime.',
            ],
          },
        ],
      },
      config.timeoutMs
    )
    assert.equal(claims.data.accepted_count, 3)
    assert.deepEqual(
      asArray(claims.data.claims)
        .map((claim) => claim.claim_id)
        .sort(),
      [hardeningClaimId, hypothesisClaimId, questionClaimId].sort()
    )
    assert.ok(asArray(claims.data.claims).every((claim) => claim.status === 'inferred'))
    assert.ok(asArray(claims.data.claims).every((claim) => claim.review_required === true))
    assert.equal(claims.data.artifact.type, 'analysis_claim_set')

    const caseQuestion = 'What deeper static analysis best resolves the satisfying input?'
    const caseState = {
      objective: 'Resume crackme analysis without treating agent memory as evidence.',
      decisions: [
        'Use bounded static extraction before any runtime execution.',
        'Keep every generated Claim inferred until an analyst review boundary is available.',
      ],
      open_questions: [openQuestion, caseQuestion],
      attempted_actions: [
        {
          tool: 'elf.structure.analyze',
          args_fingerprint: createHash('sha256').update(JSON.stringify(elfArgs)).digest('hex'),
          outcome: 'completed',
          result_artifact_ids: [elfArtifact.id],
          summary: 'Parsed ELF headers, sections, segments, symbols, and dynamic metadata.',
        },
        {
          tool: 'binary.hardening.inventory',
          args_fingerprint: createHash('sha256')
            .update(JSON.stringify(hardeningArgs))
            .digest('hex'),
          outcome: 'completed',
          result_artifact_ids: [hardeningArtifact.id],
          summary: 'Recorded passive hardening posture without executing the sample.',
        },
        {
          tool: 'strings.extract',
          args_fingerprint: createHash('sha256').update(JSON.stringify(staticArgs)).digest('hex'),
          outcome: 'completed',
          result_artifact_ids: [staticArtifact.id],
          summary: 'Completed bounded preview string extraction and persisted its artifact.',
        },
      ],
      active_claim_ids: [hardeningClaimId, hypothesisClaimId, questionClaimId],
      pinned_artifact_ids: [elfArtifact.id, hardeningArtifact.id, staticArtifact.id],
      next_actions: [
        'Inspect xrefs or decompilation around candidate validation strings.',
        'Keep runtime verification opt-in and separate from this passive E2E.',
      ],
    }

    logStep('checkpointing context-only Case Workspace state')
    const checkpoint = await callTool(
      client,
      'analysis.case.checkpoint',
      {
        sample_id: sampleId,
        ...(config.caseId ? { case_id: config.caseId } : {}),
        parent_artifact_id: null,
        session_tag: config.sessionTag,
        producer: {
          kind: 'external_agent',
          agent_name: 'run-agent-case-crackme-e2e',
        },
        state: caseState,
      },
      config.timeoutMs
    )
    assert.equal(checkpoint.data.artifact_role, 'context_only')
    assert.equal(checkpoint.data.state.artifact_role, 'context_only')
    assert.equal(checkpoint.data.artifact.type, 'analysis_case_state')
    assert.deepEqual(
      checkpoint.data.state.pinned_artifacts.map((ref) => ref.artifact_id),
      [elfArtifact.id, hardeningArtifact.id, staticArtifact.id]
    )
    const caseId = checkpoint.data.case_id

    logStep('loading Case Workspace snapshot')
    const snapshot = await callTool(
      client,
      'analysis.case.snapshot',
      {
        sample_id: sampleId,
        case_id: caseId,
        session_tag: config.sessionTag,
        max_artifacts: 64,
      },
      config.timeoutMs
    )
    assert.equal(snapshot.data.artifact_role, 'context_only')
    assert.equal(snapshot.data.state.artifact_role, 'context_only')
    assert.equal(snapshot.data.artifact.id, checkpoint.data.artifact.id)
    assert.equal(snapshot.data.case_id, caseId)

    logStep('building a Case-scoped context baseline')
    const caseBaseline = await callTool(
      client,
      'analysis.context.pack',
      {
        ...contextArgs,
        include_case: true,
        case_id: caseId,
      },
      config.timeoutMs
    )
    assert.equal(caseBaseline.data.case_id, caseId)
    assert.ok(asArray(caseBaseline.data.case_state).some((entry) => entry.case_id === caseId))

    const followupClaimId = `claim_crackme_followup_${runKey}`
    logStep('appending a follow-up Claim for incremental context validation')
    const followupClaim = await callTool(
      client,
      'analysis.claims.apply',
      {
        sample_id: sampleId,
        goal: 'Exercise Case-scoped incremental context after a persisted checkpoint.',
        session_tag: config.sessionTag,
        producer: {
          kind: 'llm',
          client_name: 'run-agent-case-crackme-e2e',
          model_name: 'scripted-e2e',
        },
        claims: [
          {
            claim_id: followupClaimId,
            category: 'open_question',
            subject: 'Incremental validation follow-up',
            statement: 'Which bounded static artifact should be read next for this selected case?',
            status: 'inferred',
          },
        ],
      },
      config.timeoutMs
    )
    assert.equal(followupClaim.data.accepted_count, 1)

    logStep('checkpointing the follow-up Claim into the selected Case')
    const followupCheckpoint = await callTool(
      client,
      'analysis.case.checkpoint',
      {
        sample_id: sampleId,
        case_id: caseId,
        parent_artifact_id: checkpoint.data.artifact.id,
        session_tag: config.sessionTag,
        producer: {
          kind: 'external_agent',
          agent_name: 'run-agent-case-crackme-e2e',
        },
        state: {
          ...caseState,
          active_claim_ids: [hardeningClaimId, hypothesisClaimId, questionClaimId, followupClaimId],
        },
      },
      config.timeoutMs
    )
    assert.equal(followupCheckpoint.data.revision, checkpoint.data.revision + 1)
    assert.ok(followupCheckpoint.data.state.active_claim_ids.includes(followupClaimId))

    logStep('building incremental context from the Case-scoped marker')
    const incremental = await callTool(
      client,
      'analysis.context.pack',
      {
        ...contextArgs,
        include_case: true,
        case_id: caseId,
        since_marker: caseBaseline.data.marker,
      },
      config.timeoutMs
    )
    assert.equal(incremental.data.case_id, caseId)
    assert.notEqual(incremental.data.marker, caseBaseline.data.marker)
    const incrementalClaimIds = new Set(
      asArray(incremental.data.claims).map((entry) => entry?.claim?.claim_id)
    )
    assert.ok(incrementalClaimIds.has(hardeningClaimId))
    assert.ok(incrementalClaimIds.has(hypothesisClaimId))
    assert.ok(incrementalClaimIds.has(questionClaimId))
    assert.ok(incrementalClaimIds.has(followupClaimId))
    assert.ok(asArray(incremental.data.case_state).some((entry) => entry.case_id === caseId))
    assert.ok(
      asArray(incremental.data.recent_changes).some(
        (entry) => entry.kind === 'claim' && entry.id === followupClaimId
      ),
      'Incremental context must identify the new Claim revision.'
    )
    const forbiddenIds = new Set([
      claims.data.artifact.id,
      followupClaim.data.artifact.id,
      checkpoint.data.artifact.id,
      followupCheckpoint.data.artifact.id,
    ])
    assertContextPackBoundaries(incremental.data, forbiddenIds)
    for (const entry of asArray(incremental.data.claims)) {
      const refs = [
        ...asArray(entry?.claim?.supporting_evidence),
        ...asArray(entry?.claim?.counter_evidence),
      ]
      assertNoClaimOrCaseRefs(refs, forbiddenIds, 'context.claims[].claim evidence')
    }

    logStep('building deterministic final summary')
    const summary = await callTool(
      client,
      'workflow.summarize',
      {
        sample_id: sampleId,
        case_id: caseId,
        through_stage: 'final',
        session_tag: config.sessionTag,
        reuse_digests: false,
        synthesis_mode: 'deterministic',
        force_refresh: true,
        evidence_scope: 'all',
        static_scope: 'latest',
        semantic_scope: 'all',
      },
      config.timeoutMs
    )
    const final = summary.data.stages?.final
    assert.ok(
      asArray(final?.claim_context?.claims).some((claim) => claim.claim_id === hypothesisClaimId)
    )
    assert.equal(final?.case_context?.case_id, caseId)
    assertSummaryBoundaries(summary.data, forbiddenIds, openQuestion, caseQuestion)
    const finalArtifact = summary.data.stage_artifacts?.final
    assert.ok(finalArtifact?.id, 'workflow.summarize must persist a final digest artifact.')
    logStep('reading the persisted final digest to verify lineage boundaries')
    const persistedSummary = await callTool(
      client,
      'artifact.read',
      {
        sample_id: sampleId,
        artifact_id: finalArtifact.id,
        read_mode: 'content',
        include_content: true,
        parse_json: true,
      },
      config.timeoutMs
    )
    const persistedFinal = persistedSummary.data.parsed_json
    assert.ok(isRecord(persistedFinal), 'Final digest must parse as JSON through artifact.read.')
    assert.equal(persistedFinal.claim_context?.artifact_role, 'context_only')
    assert.equal(persistedFinal.case_context?.artifact_role, 'context_only')
    assertNoClaimOrCaseRefs(
      asArray(persistedFinal.source_artifact_refs),
      forbiddenIds,
      'persisted_final.source_artifact_refs'
    )

    const output = {
      ok: true,
      container: config.container,
      binary_path: config.binaryPath,
      sample_id: sampleId,
      session_tag: config.sessionTag,
      exact_activations: activated,
      upload: {
        status: uploaded.status,
        existed: uploaded.existed,
        size: uploaded.size,
      },
      static: {
        elf_structure_artifact_id: elfArtifact.id,
        hardening_artifact_id: hardeningArtifact.id,
        hardening_summary: hardeningSummary,
        strings_artifact_id: staticArtifact.id,
        string_count: staticResult.data.count ?? staticResult.data.total_count ?? null,
      },
      analysis_run: {
        plan_id: analysisRun.data.plan_id,
        status: analysisRun.data.status,
        current_stage: analysisRun.data.current_stage,
      },
      deep: deepAnalysis,
      context: {
        baseline_marker: baseline.data.marker,
        case_baseline_marker: caseBaseline.data.marker,
        incremental_marker: incremental.data.marker,
        primary_evidence_count: asArray(incremental.data.primary_evidence).length,
        derived_evidence_count: asArray(incremental.data.derived_evidence).length,
        claim_count: asArray(incremental.data.claims).length,
        case_count: asArray(incremental.data.case_state).length,
      },
      claims: {
        ledger_revision: followupClaim.data.ledger_revision,
        artifact_ids: [claims.data.artifact.id, followupClaim.data.artifact.id],
        claim_ids: [hardeningClaimId, hypothesisClaimId, questionClaimId, followupClaimId],
        status: 'inferred',
      },
      case: {
        case_id: caseId,
        revision: followupCheckpoint.data.revision,
        artifact_id: followupCheckpoint.data.artifact.id,
        artifact_role: followupCheckpoint.data.artifact_role,
      },
      summary: {
        artifact_id: finalArtifact.id,
        synthesis_mode: final.synthesis_mode,
        review_required: final.review_required,
        unresolved_question_count: asArray(final.unresolved_questions).length,
      },
      assertions: {
        one_persistent_mcp_transport: true,
        exact_activation_only: true,
        claim_case_context_only: true,
        deterministic_final_summary: true,
        ghidra_decompile_completed: config.deep
          ? deepAnalysis?.decompiled?.some((entry) => typeof entry?.pseudocode === 'string') ===
            true
          : null,
      },
    }
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`)
  } finally {
    await client.close().catch(() => undefined)
  }
}

main().catch((error) => {
  process.stderr.write(
    `[agent-case-e2e] FAILED: ${error.stack || error.message || String(error)}\n`
  )
  process.exitCode = 1
})
