import { createHash } from 'crypto'

export const STATIC_PROFILE_LOCK_FILE = 'static-profile.lock.json'
export const STATIC_WORKFLOW_STAGES = ['fast_profile', 'enrich_static', 'function_map']
export const STATIC_PROFILE_PLUGIN_COUNT = 100
export const STATIC_PROFILE_BOTH_PLUGINS = ['batch', 'observability', 'reporting']

export const STATIC_REQUIRED_BACKENDS = [
  {
    name: 'java',
    path: '/opt/java/openjdk/bin/java',
    environment: [
      { name: 'JAVA_HOME', value: '/opt/java/openjdk', required: true },
      {
        name: 'PATH',
        value: '/opt/java/openjdk/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin',
        required: true,
      },
      { name: 'PYTHON_PATH', value: '/usr/local/bin/python3.12', required: true },
      { name: 'PYTHONPATH', value: '/app/workers', required: true },
      { name: 'HOME', value: '/tmp/rikune-home', required: true },
      { name: 'XDG_CONFIG_HOME', value: '/tmp/rikune-home/.config', required: true },
      { name: 'XDG_CACHE_HOME', value: '/tmp/rikune-home/.cache', required: true },
      { name: 'CONFIG_PATH', must_be_unset: true },
      { name: 'NODE_OPTIONS', must_be_unset: true },
      { name: 'NODE_PATH', must_be_unset: true },
      { name: 'LD_PRELOAD', must_be_unset: true },
      { name: 'PYTHONHOME', must_be_unset: true },
    ],
    version_args: ['-version'],
    allowed_exit_codes: [0],
    version_pattern: '(?:openjdk|java) version "(?:2[1-9]|[3-9][0-9])(?:\\.|\")',
  },
  {
    name: 'ghidra-analyze-headless',
    path: '/opt/ghidra/support/analyzeHeadless',
    environment: [
      { name: 'GHIDRA_INSTALL_DIR', value: '/opt/ghidra', required: true },
      { name: 'GHIDRA_PATH', value: '/opt/ghidra', required: true },
    ],
    version_args: [],
    allowed_exit_codes: [1],
    version_file: '/opt/ghidra/Ghidra/application.properties',
    version_pattern: '(?:^|\\n)application\\.version=12\\.1\\.3(?:\\r?\\n|$)',
  },
  {
    name: 'rizin',
    path: '/opt/rizin/bin/rizin',
    environment: [{ name: 'RIZIN_PATH', value: '/opt/rizin/bin/rizin', required: true }],
    version_args: ['-v'],
    allowed_exit_codes: [0],
    version_pattern: '[Rr][Ii][Zz][Ii][Nn][^0-9]*0\\.8\\.2(?:[^0-9]|$)',
  },
  {
    name: 'capa',
    path: '/usr/local/bin/capa',
    environment: [
      { name: 'CAPA_PATH', value: '/usr/local/bin/capa', required: true },
      { name: 'CAPA_RULES_PATH', value: '/opt/capa-rules', required: true },
    ],
    version_args: ['--version'],
    allowed_exit_codes: [0],
    version_pattern: '(?:[Cc][Aa][Pp][Aa]|[Mm][Aa][Ii][Nn]\\.[Pp][Yy])[^0-9]*9\\.3\\.1(?:[^0-9]|$)',
  },
  {
    name: 'detect-it-easy',
    path: '/usr/bin/diec',
    environment: [{ name: 'DIE_PATH', value: '/usr/bin/diec', required: true }],
    version_args: ['--version'],
    allowed_exit_codes: [0],
    version_pattern:
      '(?:[Dd][Ee][Tt][Ee][Cc][Tt] [Ii][Tt] [Ee][Aa][Ss][Yy]|[Dd][Ii][Ee])[^0-9]*3\\.10(?:[^0-9]|$)',
  },
  {
    name: 'upx',
    path: '/opt/upx/upx',
    environment: [{ name: 'UPX_PATH', value: '/opt/upx/upx', required: true }],
    version_args: ['--version'],
    allowed_exit_codes: [0],
    version_pattern: '[Uu][Pp][Xx][^0-9]*5\\.1\\.1(?:[^0-9]|$)',
  },
  {
    name: 'flare-floss',
    path: '/usr/local/bin/floss',
    environment: [{ name: 'FLOSS_PATH', value: '/usr/local/bin/floss', required: true }],
    version_args: ['--version'],
    allowed_exit_codes: [0],
    version_pattern: '[Ff][Ll][Oo][Ss][Ss][^0-9]*3\\.1\\.1(?:[^0-9]|$)',
  },
  {
    name: 'yara-x-python',
    path: '/usr/local/bin/python3.12',
    environment: [
      { name: 'YARAX_PYTHON', value: '/usr/local/bin/python3.12', required: true },
      // The static image intentionally bundles no default YARA-X rule file.
      // This discriminator freezes that absence; any operator override fails.
      { name: 'YARA_X_RULES_PATH', must_be_unset: true },
    ],
    version_args: ['-c', 'import importlib.metadata as m; print("yara-x", m.version("yara-x"))'],
    allowed_exit_codes: [0],
    version_pattern: '[Yy][Aa][Rr][Aa]-[Xx][^0-9]*1\\.14\\.0(?:[^0-9]|$)',
  },
]

export function orderedPluginCsvSha256(plugins) {
  return createHash('sha256').update(plugins.join(','), 'utf8').digest('hex')
}

export function createStaticProfileLock(plugins) {
  if (!Array.isArray(plugins) || plugins.length !== STATIC_PROFILE_PLUGIN_COUNT) {
    throw new Error(
      `Static profile must contain exactly ${STATIC_PROFILE_PLUGIN_COUNT} plugins; received ${plugins?.length ?? 'non-array'}`
    )
  }
  if (new Set(plugins).size !== plugins.length) {
    throw new Error('Static profile plugin list contains duplicate IDs')
  }
  return {
    schema_version: 1,
    profile: 'static',
    plugins: [...plugins],
    ordered_csv_sha256: orderedPluginCsvSha256(plugins),
    static_workflow_stages: [...STATIC_WORKFLOW_STAGES],
    required_backends: STATIC_REQUIRED_BACKENDS.map((backend) => ({
      ...backend,
      environment: backend.environment.map((binding) => ({ ...binding })),
      version_args: [...backend.version_args],
      allowed_exit_codes: [...backend.allowed_exit_codes],
    })),
    generated_by: 'scripts/generate-docker.mjs',
    generator_version: 1,
  }
}
