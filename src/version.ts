import { createRequire } from 'module'

interface PackageMetadata {
  version?: unknown
}

const require = createRequire(import.meta.url)
const packageMetadata = require('../package.json') as PackageMetadata

export const RIKUNE_VERSION =
  typeof packageMetadata.version === 'string' && packageMetadata.version.length > 0
    ? packageMetadata.version
    : '0.0.0-dev'
