import { describe, expect, test } from '@jest/globals'
import { createRequire } from 'module'
import { RIKUNE_VERSION } from '../../src/version.js'

const require = createRequire(import.meta.url)
const packageMetadata = require('../../package.json') as { version: string }

describe('Rikune product version', () => {
  test('uses package.json as the single runtime version source', () => {
    expect(RIKUNE_VERSION).toBe(packageMetadata.version)
  })
})
