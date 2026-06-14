import type { BackendWorkerContract, PluginSystemDep } from '../plugins/sdk.js'

export type BackendInstallRoute =
  | 'installed'
  | 'profile-gated'
  | 'byo'
  | 'sidecar'
  | 'validation-only'
  | 'missing'

export type BackendInstallProfile =
  | 'default'
  | 'optional'
  | 'heavy'
  | 'research'
  | 'runtime'
  | 'gpu'
  | 'license-gated'

export type BackendProfileId =
  | 'default'
  | 'full'
  | 'optional'
  | 'heavy'
  | 'research'
  | 'runtime'
  | 'gpu'
  | 'all'

export const BACKEND_PROFILE_GROUPS: Record<BackendProfileId, BackendInstallProfile[]> = {
  default: ['default'],
  full: ['default', 'optional'],
  optional: ['default', 'optional'],
  heavy: ['default', 'optional', 'heavy'],
  research: ['default', 'optional', 'heavy', 'research', 'license-gated'],
  runtime: ['default', 'optional', 'runtime'],
  gpu: ['default', 'optional', 'gpu'],
  all: ['default', 'optional', 'heavy', 'research', 'runtime', 'gpu', 'license-gated'],
}

export interface BackendInstallProfileEntry {
  docker_feature: string
  backend_name: string
  install_route: BackendInstallRoute
  install_profile: BackendInstallProfile
  enabled_by_profiles: BackendProfileId[]
  default_enabled: boolean
  requires_profile: boolean
  requires_byo: boolean
  requires_sidecar: boolean
  validation_only: boolean
  safety_gate: string
  license_gate: boolean
  runtime_gate: boolean
  gpu_gate: boolean
  env_var?: string
  docker_default?: string
  setup_actions: string[]
  notes: string[]
}

function uniqueStrings(values: Array<string | undefined | null>): string[] {
  return Array.from(new Set(values.filter((value): value is string => Boolean(value?.trim()))))
}

export function backendProfileAllows(
  installRoute: BackendInstallRoute,
  installProfile: BackendInstallProfile,
  backendProfile: BackendProfileId = 'default'
): boolean {
  if (installRoute === 'byo' || installRoute === 'sidecar' || installRoute === 'validation-only') {
    return false
  }
  const allowedProfiles = BACKEND_PROFILE_GROUPS[backendProfile] ?? BACKEND_PROFILE_GROUPS.default
  if (installRoute === 'profile-gated' && !allowedProfiles.includes(installProfile)) return false
  return allowedProfiles.includes(installProfile)
}

function enabledByProfiles(
  installRoute: BackendInstallRoute,
  installProfile: BackendInstallProfile
): BackendProfileId[] {
  return (Object.keys(BACKEND_PROFILE_GROUPS) as BackendProfileId[]).filter((profile) =>
    backendProfileAllows(installRoute, installProfile, profile)
  )
}

function safetyGateFor(
  route: BackendInstallRoute,
  profile: BackendInstallProfile,
  workerKind?: BackendWorkerContract['backendKind']
): string {
  if (route === 'byo') return 'bring_your_own_backend'
  if (route === 'sidecar') return 'sidecar_required'
  if (route === 'validation-only') return 'validation_only'
  if (profile === 'license-gated') return 'license_gated'
  if (profile === 'runtime' || workerKind === 'delegated-runtime') return 'runtime_opt_in_required'
  if (profile === 'gpu') return 'gpu_opt_in_required'
  if (profile === 'heavy') return 'heavy_profile_required'
  if (route === 'profile-gated') return 'profile_opt_in_required'
  return 'default_static'
}

function entryFromDep(dep: PluginSystemDep): BackendInstallProfileEntry | null {
  if (!dep.dockerFeature) return null
  const installRoute = (dep.dockerInstallRoute ?? 'installed') as BackendInstallRoute
  const installProfile = (dep.dockerInstallProfile ?? 'default') as BackendInstallProfile
  const enabledProfiles = enabledByProfiles(installRoute, installProfile)

  return {
    docker_feature: dep.dockerFeature,
    backend_name: dep.name,
    install_route: installRoute,
    install_profile: installProfile,
    enabled_by_profiles: enabledProfiles,
    default_enabled: enabledProfiles.includes('default'),
    requires_profile: installRoute === 'profile-gated',
    requires_byo: installRoute === 'byo',
    requires_sidecar: installRoute === 'sidecar',
    validation_only: installRoute === 'validation-only',
    safety_gate: safetyGateFor(installRoute, installProfile),
    license_gate: installProfile === 'license-gated',
    runtime_gate: installProfile === 'runtime',
    gpu_gate: installProfile === 'gpu',
    env_var: dep.envVar,
    docker_default: dep.dockerDefault,
    setup_actions: uniqueStrings([
      dep.envVar ? `Set ${dep.envVar} or use the declared Docker default.` : null,
      dep.dockerInstall,
      ...(dep.dockerValidation ?? []),
    ]),
    notes: dep.dockerInstallNotes ?? [],
  }
}

function entryFromWorkerBackend(backend: BackendWorkerContract): BackendInstallProfileEntry | null {
  const packaging = backend.packaging
  if (!packaging?.dockerFeature) return null
  const installRoute = (packaging.installRoute ?? 'profile-gated') as BackendInstallRoute
  const installProfile = (packaging.installProfile ?? 'optional') as BackendInstallProfile
  const enabledProfiles = enabledByProfiles(installRoute, installProfile)

  return {
    docker_feature: packaging.dockerFeature,
    backend_name: backend.backendName,
    install_route: installRoute,
    install_profile: installProfile,
    enabled_by_profiles: enabledProfiles,
    default_enabled: enabledProfiles.includes('default'),
    requires_profile: installRoute === 'profile-gated',
    requires_byo: installRoute === 'byo',
    requires_sidecar: installRoute === 'sidecar',
    validation_only: installRoute === 'validation-only',
    safety_gate: safetyGateFor(installRoute, installProfile, backend.backendKind),
    license_gate: installProfile === 'license-gated',
    runtime_gate: installProfile === 'runtime' || backend.backendKind === 'delegated-runtime',
    gpu_gate: installProfile === 'gpu',
    env_var: packaging.envVar ?? backend.envVar,
    docker_default: packaging.dockerDefault,
    setup_actions: uniqueStrings([
      ...(backend.readiness?.setupActions ?? []),
      backend.readiness?.missingBackendBehavior,
    ]),
    notes: packaging.notes ?? [],
  }
}

export function buildPluginBackendInstallProfile(plugin: {
  systemDeps?: PluginSystemDep[]
  tools?: Array<{ definition: { workerBackend?: BackendWorkerContract } }>
}): {
  entries: BackendInstallProfileEntry[]
  summary: {
    total: number
    default_enabled: number
    profile_gated: number
    byo: number
    sidecar: number
    validation_only: number
    license_gated: number
    runtime_gated: number
    gpu_gated: number
  }
} {
  const byFeature = new Map<string, BackendInstallProfileEntry>()
  for (const dep of plugin.systemDeps ?? []) {
    const entry = entryFromDep(dep)
    if (entry) byFeature.set(entry.docker_feature, entry)
  }
  for (const tool of plugin.tools ?? []) {
    const entry = tool.definition.workerBackend
      ? entryFromWorkerBackend(tool.definition.workerBackend)
      : null
    if (entry && !byFeature.has(entry.docker_feature)) {
      byFeature.set(entry.docker_feature, entry)
    }
  }
  const entries = [...byFeature.values()].sort((a, b) =>
    a.docker_feature.localeCompare(b.docker_feature)
  )
  return {
    entries,
    summary: {
      total: entries.length,
      default_enabled: entries.filter((entry) => entry.default_enabled).length,
      profile_gated: entries.filter((entry) => entry.requires_profile).length,
      byo: entries.filter((entry) => entry.requires_byo).length,
      sidecar: entries.filter((entry) => entry.requires_sidecar).length,
      validation_only: entries.filter((entry) => entry.validation_only).length,
      license_gated: entries.filter((entry) => entry.license_gate).length,
      runtime_gated: entries.filter((entry) => entry.runtime_gate).length,
      gpu_gated: entries.filter((entry) => entry.gpu_gate).length,
    },
  }
}
