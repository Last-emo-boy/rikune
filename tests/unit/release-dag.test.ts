import { describe, expect, test } from '@jest/globals'
import fs from 'fs'
import path from 'path'
import YAML from 'yaml'

function readWorkflow(name: string): any {
  return YAML.parse(fs.readFileSync(path.join(process.cwd(), '.github', 'workflows', name), 'utf8'))
}

describe('v1.4.0 release DAG', () => {
  test('stages npm candidate and requires human 2FA publication before registry verification', () => {
    const workflow = readWorkflow('publish-npm.yml')
    expect(workflow.on.push.tags).toEqual(['v1.4.0'])
    expect(Object.keys(workflow.jobs)).toEqual([
      'preflight',
      'hybrid-build-verify',
      'static-build-push',
      'static-verify',
      'npm-candidate-ceremony',
      'npm-human-publication-verify',
      'release-and-alias',
    ])

    const preflightSteps = workflow.jobs.preflight.steps
    const releaseTestStep = preflightSteps.find(
      (step: any) => step.name === 'Run release test suite'
    )
    expect(releaseTestStep.run).toContain('npm run lint')
    expect(releaseTestStep.run).toContain('npm test -- --runInBand')
    expect(releaseTestStep.run).toContain('npm run test:node')
    expect(workflow.jobs.preflight.permissions.actions).toBe('read')
    const mainCiGate = preflightSteps.find((step: any) =>
      String(step.name).includes('exact-SHA main CI')
    )
    expect(mainCiGate.if).toContain("dry_run != 'true'")
    expect(mainCiGate.run).toContain('actions/workflows/ci.yml/runs')
    expect(mainCiGate.run).toContain('.head_sha == $sha')
    expect(mainCiGate.run).toContain('.head_branch == "main"')
    expect(mainCiGate.run).toContain('.conclusion == "success"')
    const workflowSource = fs.readFileSync(
      path.join(process.cwd(), '.github', 'workflows', 'publish-npm.yml'),
      'utf8'
    )
    expect(workflowSource).not.toMatch(/\bnpm\s+publish\b/u)
    expect(workflowSource).not.toContain('NPM_TOKEN')
    expect(workflowSource).not.toContain('NODE_AUTH_TOKEN')
    expect(workflow.on.workflow_dispatch.inputs.release_phase.options).toEqual([
      'stage',
      'verify-human-published',
    ])
    expect(preflightSteps.some((step: any) => step.with?.name === 'npm-release-candidate')).toBe(
      false
    )
    const ceremonyJob = workflow.jobs['npm-candidate-ceremony']
    expect(ceremonyJob.needs).toEqual(['preflight', 'hybrid-build-verify', 'static-verify'])
    expect(ceremonyJob.if).toContain("needs.preflight.outputs.phase == 'stage'")
    const candidateUpload = ceremonyJob.steps.find(
      (step: any) =>
        step.uses?.startsWith('actions/upload-artifact@') &&
        step.with?.name === 'npm-release-candidate'
    )
    expect(candidateUpload).toBeDefined()
    expect(String(candidateUpload.with.path)).toContain('DISCLOSURE')
    expect(String(candidateUpload.with.path)).toContain('release-candidate-manifest.json')
    const evidenceUpload = preflightSteps.find(
      (step: any) => step.with?.name === 'npm-release-evidence'
    )
    expect(evidenceUpload.if).toContain("steps.release.outputs.phase == 'verify-human-published'")
    const packScript = preflightSteps.find((step: any) => step.id === 'pack')?.run || ''
    expect(packScript).toContain('contentPolicy?.class')
    expect(packScript).toContain('package/DISCLOSURE')
    expect(packScript).toContain('bin/rikune.js')
    expect(packScript).toContain('file.mode & 0o111')
    expect(packScript).toContain('release-candidate-manifest.json')
    expect(packScript).toContain('run_url')
    const ceremonyPack = ceremonyJob.steps.find((step: any) => step.id === 'pack').run
    expect(ceremonyPack).toContain('test "$integrity" = "$EXPECTED_INTEGRITY"')
    expect(ceremonyPack).toContain('test "$HYBRID_IMAGE_REVISION" = "$GITHUB_SHA"')
    expect(ceremonyPack).toContain('static_oci_verified:true')
    expect(ceremonyJob.steps.find((step: any) => step.id === 'pack').env.STATIC_OCI_DIGEST).toBe(
      '${{ needs.static-verify.outputs.digest }}'
    )
    expect(
      ceremonyJob.steps.find((step: any) => step.id === 'pack').env.HYBRID_IMAGE_REVISION
    ).toBe('${{ needs.hybrid-build-verify.outputs.revision }}')
    expect(ceremonyPack).toContain('hybrid_image_revision:process.env.HYBRID_IMAGE_REVISION')
    expect(ceremonyPack).toContain('hybrid_image_verified:true')
    expect(
      preflightSteps.some(
        (step: any) =>
          String(step.run).includes('scripts/verify-release-package.mjs') &&
          String(step.name).includes('fresh install')
      )
    ).toBe(true)

    const hybridJob = workflow.jobs['hybrid-build-verify']
    expect(hybridJob.needs).toBe('preflight')
    expect(hybridJob.if).toBeUndefined()
    expect(hybridJob.outputs.revision).toBe('${{ steps.contract.outputs.revision }}')
    const hybridBuild = hybridJob.steps.find((step: any) =>
      step.uses?.startsWith('docker/build-push-action@')
    )
    expect(hybridBuild.with).toEqual(
      expect.objectContaining({
        file: './docker/Dockerfile.hybrid',
        platforms: 'linux/amd64',
        load: true,
        push: false,
        tags: 'rikune-analyzer-hybrid:release',
      })
    )
    expect(hybridBuild.with.labels).toContain('org.opencontainers.image.revision=${{ github.sha }}')
    expect(hybridBuild.with.labels).toContain('org.opencontainers.image.rikune.profile=hybrid')
    const hybridContract = hybridJob.steps.find((step: any) => step.id === 'contract')
    expect(hybridContract.run).toContain(
      'bash scripts/verify-hybrid-container.sh rikune-analyzer-hybrid:release'
    )
    expect(hybridContract.run).toContain('echo "revision=$GITHUB_SHA" >> "$GITHUB_OUTPUT"')
    expect(workflow.jobs['static-build-push'].needs).toEqual(['preflight', 'hybrid-build-verify'])

    const buildStep = workflow.jobs['static-build-push'].steps.find(
      (step: any) => step.id === 'build'
    )
    expect(buildStep.if).toBe("needs.preflight.outputs.phase == 'stage'")
    expect(buildStep.with).toEqual(
      expect.objectContaining({
        file: './docker/Dockerfile.analyzer',
        platforms: 'linux/amd64',
        push: true,
        provenance: 'mode=max',
        sbom: true,
      })
    )
    expect(workflow.env.STATIC_IMAGE).toBe('ghcr.io/last-emo-boy/rikune-analyzer-static')
    expect(workflow.jobs['static-build-push'].outputs.digest).toBe(
      '${{ steps.digest.outputs.digest }}'
    )
    const candidateState = workflow.jobs['static-build-push'].steps.find(
      (step: any) => step.id === 'candidate_state'
    )
    expect(candidateState.run).toContain(
      'Immutable candidate already exists; refusing to overwrite'
    )
    expect(candidateState.run).toContain(
      'The staged immutable candidate is missing; verification cannot create it.'
    )
    expect(candidateState.run).toContain('existing_digest=')
    expect(candidateState.run).not.toMatch(/\|not found/u)
    expect(candidateState.run).toContain('404 Not Found')
    for (const stepName of [
      'Build and push linux/amd64 candidate',
      'Sign GitHub build provenance attestation',
      'Sign GitHub SBOM attestation',
      'Keyless-sign immutable candidate digest',
    ]) {
      const mutationStep = workflow.jobs['static-build-push'].steps.find(
        (step: any) => step.name === stepName
      )
      expect(mutationStep.if).toBe("needs.preflight.outputs.phase == 'stage'")
    }
    expect(workflow.jobs['npm-human-publication-verify'].needs).toEqual([
      'preflight',
      'hybrid-build-verify',
      'static-verify',
    ])
    expect(workflow.jobs['npm-human-publication-verify'].if).toContain(
      "inputs.release_phase == 'verify-human-published'"
    )
    expect(workflow.jobs['release-and-alias'].needs).toEqual([
      'hybrid-build-verify',
      'static-verify',
      'npm-human-publication-verify',
    ])

    const registryVerifyScript = workflow.jobs['npm-human-publication-verify'].steps
      .map((step: any) => step.run || '')
      .join('\n')
    expect(registryVerifyScript).toContain('dist.integrity')
    expect(registryVerifyScript).toContain('gitHead')
    expect(registryVerifyScript).toContain('GITHUB_SHA')
    expect(registryVerifyScript).toContain('EXPECTED_INTEGRITY')
    expect(
      workflow.jobs['npm-human-publication-verify'].steps.some(
        (step: any) => step.with?.name === 'npm-release-candidate'
      )
    ).toBe(false)
    expect(
      workflow.jobs['release-and-alias'].steps.some(
        (step: any) => step.with?.name === 'npm-release-evidence'
      )
    ).toBe(true)

    const buildActions = workflow.jobs['static-build-push'].steps.map(
      (step: any) => step.uses || ''
    )
    expect(
      buildActions.some((action: string) => action.startsWith('actions/attest-build-provenance@'))
    ).toBe(true)
    expect(buildActions.some((action: string) => action.startsWith('actions/attest-sbom@'))).toBe(
      true
    )
    expect(
      buildActions.some((action: string) => action.startsWith('sigstore/cosign-installer@'))
    ).toBe(true)

    const verifyScript = workflow.jobs['static-verify'].steps
      .map((step: any) => step.run || '')
      .join('\n')
    expect(verifyScript).toContain('cosign verify')
    expect(verifyScript).toContain('gh attestation verify')
    expect(verifyScript).toContain('static-profile.lock.json')
    expect(verifyScript).toContain('bash scripts/verify-static-container.sh "$ref"')
    expect(verifyScript).toContain('RIKUNE_DOCKER_PROFILE=full')
    expect(workflow.jobs['static-verify'].permissions.attestations).toBe('read')
    expect(verifyScript).toContain('--predicate-type https://spdx.dev/Document/v2.3')
    expect(verifyScript).not.toMatch(/--predicate-type https:\/\/spdx\.dev\/Document(?:\s|$)/)
    expect(verifyScript).toContain("jq -r '.required_backends[].environment[].name'")
    const verifier = fs.readFileSync(
      path.join(process.cwd(), 'scripts', 'verify-static-container.sh'),
      'utf8'
    )
    expect(verifier).toContain("'{{.Config.User}}'")
    expect(verifier).toContain('--read-only')
    expect(verifier).toContain('/api/v1/health')
    expect(verifier).toContain('! -type l -a -perm /022')
    expect(verifier).toContain('-type l ! -exec test -e {} \\;')
    expect(verifier).toContain('-type l -exec readlink -e -- {} +')
    expect(verifier).toContain('/app/src/.write-probe')
    expect(verifier).toContain('/app/src/.runtime-write-probe')
    for (const directory of [
      '/app/workspaces',
      '/app/data',
      '/app/cache',
      '/app/logs',
      '/app/storage',
      '/app/uploads',
      '/ghidra-projects',
      '/ghidra-logs',
    ]) {
      expect(verifier).toContain(`--tmpfs "${directory}:`)
    }

    const aliasScript = workflow.jobs['release-and-alias'].steps
      .map((step: any) => step.run || '')
      .join('\n')
    expect(aliasScript).toContain(
      'test \'${{ needs.hybrid-build-verify.outputs.revision }}\' = "$GITHUB_SHA"'
    )
    expect(aliasScript).toContain('manifest unknown')
    expect(aliasScript).toContain('Unable to prove that immutable tag 1.4.0 is absent')
    expect(aliasScript).toContain('existing_digest')
    expect(registryVerifyScript).toContain('dist-tags.latest')

    const runbook = fs.readFileSync(path.join(process.cwd(), 'CONTRIBUTING.md'), 'utf8')
    const candidateVerifier = fs.readFileSync(
      path.join(process.cwd(), 'scripts', 'verify-staged-release-candidate.mjs'),
      'utf8'
    )
    expect(runbook).toContain('scripts/verify-staged-release-candidate.mjs')
    expect(runbook).toContain('npm publish "$candidate_tarball"')
    expect(candidateVerifier).toContain("createHash('sha512')")
    expect(candidateVerifier).toContain("'package/package.json'")
    expect(candidateVerifier).toContain('packageJson.gitHead')
    expect(candidateVerifier).toContain('packageJson.contentPolicy?.class')
    expect(candidateVerifier).toContain('manifest.artifact_name')
    expect(candidateVerifier).toContain('manifest.repository')
    expect(candidateVerifier).toContain('manifest.workflow')
  })

  test('packages the root dual-use disclosure contract', () => {
    const packageJson = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), 'package.json'), 'utf8')
    )
    expect(packageJson.contentPolicy).toEqual({ class: 'dual-use' })
    expect(packageJson.files).toContain('DISCLOSURE')
    expect(fs.readFileSync(path.join(process.cwd(), 'DISCLOSURE'), 'utf8')).toContain(
      'human maintainer'
    )
    expect(fs.readFileSync(path.join(process.cwd(), 'DISCLOSURE'), 'utf8')).toContain('2FA')
    const changelog = fs.readFileSync(path.join(process.cwd(), 'CHANGELOG.md'), 'utf8')
    expect(packageJson.files).toContain('CHANGELOG.md')
    expect(changelog).toContain('crash-safe `sample.delete`')
    expect(changelog).toContain('exact static OCI contract')
    expect(changelog).toContain('human maintainer 2FA ceremony')
  })

  test('keeps Docker CI off release tags and exercises static and Hybrid images', () => {
    const workflow = readWorkflow('docker-build.yml')
    expect(workflow.name).toContain('not a release gate')
    expect(workflow.on.push.tags).toBeUndefined()
    const staticJob = workflow.jobs['static-contract']
    expect(staticJob).toBeDefined()
    const staticSource = staticJob.steps.map((step: any) => step.run || '').join('\n')
    expect(staticSource).toContain('npm run docker:generate:all')
    expect(staticSource).toContain('bash scripts/verify-compose-config.sh')
    expect(staticSource).toContain('git diff --exit-code -- static-profile.lock.json')
    expect(staticSource).toContain(
      'bash scripts/verify-static-container.sh rikune-analyzer-static:ci'
    )
    expect(staticSource).toContain('RIKUNE_DOCKER_PROFILE=full')
    expect(staticSource).toContain("jq -r '.required_backends[].environment[].name'")
    const staticBuild = staticJob.steps.find((step: any) =>
      step.uses?.startsWith('docker/build-push-action@')
    )
    expect(staticBuild.with).toEqual(
      expect.objectContaining({
        file: './docker/Dockerfile.analyzer',
        platforms: 'linux/amd64',
        load: true,
        push: false,
      })
    )

    const hybridJob = workflow.jobs['hybrid-contract']
    expect(hybridJob).toBeDefined()
    const hybridSource = hybridJob.steps.map((step: any) => step.run || '').join('\n')
    expect(hybridSource).toContain('npm run docker:generate:hybrid')
    expect(hybridSource).toContain('git diff --exit-code -- docker/Dockerfile.hybrid')
    expect(hybridSource).toContain(
      'bash scripts/verify-hybrid-container.sh rikune-analyzer-hybrid:ci'
    )
    const hybridBuild = hybridJob.steps.find((step: any) =>
      step.uses?.startsWith('docker/build-push-action@')
    )
    expect(hybridBuild.with).toEqual(
      expect.objectContaining({
        file: './docker/Dockerfile.hybrid',
        platforms: 'linux/amd64',
        load: true,
        push: false,
        tags: 'rikune-analyzer-hybrid:ci',
      })
    )
    expect(hybridBuild.with.labels).toContain('org.opencontainers.image.revision=${{ github.sha }}')
    expect(hybridBuild.with.labels).toContain('org.opencontainers.image.rikune.profile=hybrid')

    const hybridVerifier = fs.readFileSync(
      path.join(process.cwd(), 'scripts', 'verify-hybrid-container.sh'),
      'utf8'
    )
    expect(hybridVerifier).toContain("'{{.Config.User}}'")
    expect(hybridVerifier).toContain("'{{json .Config.Entrypoint}}'")
    expect(hybridVerifier).toContain('org.opencontainers.image.rikune.profile')
    expect(hybridVerifier).toContain('org.opencontainers.image.revision')
    expect(hybridVerifier).toContain('RUNNING_IN_DOCKER=true')
    expect(hybridVerifier).toContain('/app/LICENSE')
    expect(hybridVerifier).toContain('/app/DISCLOSURE')
    expect(hybridVerifier).toContain('/app/scripts/verify-hybrid-runtime.mjs')
    expect(hybridVerifier).toContain('--read-only')
    expect(hybridVerifier).toContain('--network none')
    expect(hybridVerifier).toContain('--security-opt no-new-privileges:true')
    expect(hybridVerifier).toContain('--cap-drop ALL')
    expect(hybridVerifier).toContain('! -type l -a -perm /022')
    expect(hybridVerifier).toContain('-type l ! -exec test -e {} \\;')
    expect(hybridVerifier).toContain('-type l -exec readlink -e -- {} +')
    expect(hybridVerifier).toContain('/app/src/.hybrid-write-probe')
    expect(hybridVerifier).toContain('/app/src/.hybrid-runtime-write-probe')
    expect(hybridVerifier).toContain('RUNTIME_MODE=disabled')
    expect(hybridVerifier).toContain('test -z "${RUNTIME_HOST_AGENT_ENDPOINT:-}"')
    expect(hybridVerifier).toContain('test -z "${RUNTIME_HOST_AGENT_API_KEY:-}"')
    expect(hybridVerifier).toContain(
      'Hybrid image configuration must not bake runtime endpoints or credentials'
    )
    for (const directory of [
      '/tmp',
      '/app/workspaces',
      '/app/data',
      '/app/cache',
      '/app/logs',
      '/app/storage',
      '/app/uploads',
      '/ghidra-projects',
      '/ghidra-logs',
    ]) {
      expect(hybridVerifier).toContain(`--tmpfs "${directory}:`)
    }
  })

  test('pins every workflow action to a full commit SHA', () => {
    const workflowDirectory = path.join(process.cwd(), '.github', 'workflows')
    for (const workflowName of fs.readdirSync(workflowDirectory).sort()) {
      if (!workflowName.endsWith('.yml')) continue
      const source = fs.readFileSync(path.join(workflowDirectory, workflowName), 'utf8')
      for (const match of source.matchAll(/^\s*uses:\s*([^\s#]+)/gmu)) {
        expect(`${workflowName}: ${match[1]}`).toMatch(/^[^:]+:\s+[^@\s]+@[a-f0-9]{40}$/u)
      }
    }
  })
})
