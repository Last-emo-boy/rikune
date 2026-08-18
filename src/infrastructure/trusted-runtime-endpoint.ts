import {
  assertTrustedHttpEndpoint,
  endpointUrl,
  type EndpointCredentialSource,
  type ParsedHttpServiceEndpoint,
} from '@rikune/shared'

export type HostAgentRuntimeBackend = 'windows-sandbox' | 'hyperv-vm'

export type RuntimeEndpointProvenance =
  | {
      kind: 'live-host-agent'
      parentEndpoint: string
      backend?: string | null
    }
  | {
      kind: 'persisted-session'
      parentEndpoint?: string
      backend?: string | null
    }

export interface RuntimeEndpointResolution {
  endpoint?: string
  source: string
  configuredEndpoint?: string
  provenance?: RuntimeEndpointProvenance
}

export function validateRuntimeEndpointFromHostAgent(
  value: string,
  hostAgentEndpoint: string,
  backend?: string | null,
  label = 'runtime endpoint from Host Agent'
): ParsedHttpServiceEndpoint {
  assertTrustedHttpEndpoint(hostAgentEndpoint, { label: 'trusted Host Agent endpoint' })

  if (backend === 'hyperv-vm') {
    // Hyper-V returns the Runtime Node address configured on the trusted Host
    // Agent. Unlike Windows Sandbox portproxy endpoints, the VM may have a
    // different host/IP.
    return assertTrustedHttpEndpoint(value, { label })
  }

  return assertTrustedHttpEndpoint(value, {
    label,
    trustedParentEndpoint: hostAgentEndpoint,
    allowParentPortChange: true,
  })
}

export function getEndpointCredentialSource(
  inputKey: string | undefined,
  configuredKey: string | undefined
): EndpointCredentialSource {
  if (inputKey) return 'explicit'
  if (configuredKey) return 'configured'
  return 'none'
}

export function validateRuntimeEndpointResolution(
  resolution: Pick<RuntimeEndpointResolution, 'endpoint' | 'configuredEndpoint' | 'provenance'>,
  keySource: EndpointCredentialSource,
  label: string
): void {
  if (!resolution.endpoint) return
  if (resolution.provenance?.kind === 'persisted-session') {
    assertTrustedHttpEndpoint(resolution.endpoint, {
      label,
      allowedOrigins: resolution.configuredEndpoint ? [resolution.configuredEndpoint] : [],
      configuredEndpoint: resolution.configuredEndpoint,
      credentialSource: keySource,
    })
    return
  }
  const liveHostAgent =
    resolution.provenance?.kind === 'live-host-agent' ? resolution.provenance : undefined
  if (liveHostAgent?.backend === 'hyperv-vm') {
    if (!liveHostAgent.parentEndpoint.trim()) {
      throw new Error(`${label} is missing its trusted Host Agent provenance.`)
    }
    validateRuntimeEndpointFromHostAgent(
      resolution.endpoint,
      liveHostAgent.parentEndpoint,
      liveHostAgent.backend,
      label
    )
    return
  }
  assertTrustedHttpEndpoint(resolution.endpoint, {
    label,
    configuredEndpoint: resolution.configuredEndpoint,
    credentialSource: keySource,
    trustedParentEndpoint: liveHostAgent?.parentEndpoint,
    allowParentPortChange: Boolean(liveHostAgent?.parentEndpoint),
  })
}

export { endpointUrl }
