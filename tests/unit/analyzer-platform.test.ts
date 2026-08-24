import { describe, expect, test } from '@jest/globals'
import {
  ANALYZER_PLATFORM_ERROR,
  assertSupportedAnalyzerPlatform,
} from '../../src/analyzer-platform.js'

describe('Analyzer platform contract', () => {
  test('accepts Linux and fails closed on native Windows/macOS', () => {
    expect(() => assertSupportedAnalyzerPlatform('linux')).not.toThrow()
    expect(() => assertSupportedAnalyzerPlatform('win32')).toThrow(ANALYZER_PLATFORM_ERROR)
    expect(() => assertSupportedAnalyzerPlatform('darwin')).toThrow(ANALYZER_PLATFORM_ERROR)
  })
})
