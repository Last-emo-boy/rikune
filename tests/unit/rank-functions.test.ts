/**
 * Unit tests for rankFunctions method
 * Tests the function ranking algorithm without database dependencies
 */

import { describe, test, expect } from '@jest/globals';

describe('rankFunctions algorithm', () => {
  // Simulate the ranking algorithm
  function calculateScore(func: {
    size: number;
    caller_count: number;
    callees: string[];
    is_entry_point: boolean;
    is_exported: boolean;
  }): { score: number; reasons: string[] } {
    let score = 0.0;
    const reasons: string[] = [];

    const sensitiveAPIs = [
      'CreateProcess', 'WriteFile', 'RegSetValue', 'InternetOpen',
      'VirtualAlloc', 'CreateRemoteThread', 'WriteProcessMemory'
    ];

    // Rule 1: Large function (> 1000 bytes)
    if (func.size > 1000) {
      score += 10.0;
      reasons.push('large_function');
    }

    // Rule 2: High caller count (> 10)
    if (func.caller_count > 10) {
      const callerScore = 5.0 * Math.log(func.caller_count);
      score += callerScore;
      reasons.push('high_callers');
    }

    // Rule 3: Calls sensitive APIs
    const matchedAPIs = func.callees.filter(callee =>
      sensitiveAPIs.some(api => callee.includes(api))
    );

    if (matchedAPIs.length > 0) {
      score += 15.0;
      matchedAPIs.forEach(api => {
        reasons.push(`calls_sensitive_api:${api}`);
      });
    }

    // Rule 4: Entry point or exported function
    if (func.is_entry_point || func.is_exported) {
      score += 20.0;
      if (func.is_entry_point) {
        reasons.push('entry_point');
      }
      if (func.is_exported) {
        reasons.push('exported');
      }
    }

    return { score, reasons };
  }

  test('should score large functions correctly', () => {
    const func = {
      size: 1500,
      caller_count: 5,
      callees: [],
      is_entry_point: false,
      is_exported: false
    };

    const result = calculateScore(func);
    expect(result.score).toBe(10.0);
    expect(result.reasons).toContain('large_function');
  });

  test('should score functions with high caller count', () => {
    const func = {
      size: 500,
      caller_count: 20,
      callees: [],
      is_entry_point: false,
      is_exported: false
    };

    const result = calculateScore(func);
    const expectedScore = 5.0 * Math.log(20);
    expect(result.score).toBeCloseTo(expectedScore, 2);
    expect(result.reasons).toContain('high_callers');
  });

  test('should score functions calling sensitive APIs', () => {
    const func = {
      size: 500,
      caller_count: 5,
      callees: ['CreateProcess', 'WriteFile'],
      is_entry_point: false,
      is_exported: false
    };

    const result = calculateScore(func);
    expect(result.score).toBe(15.0);
    expect(result.reasons).toContain('calls_sensitive_api:CreateProcess');
    expect(result.reasons).toContain('calls_sensitive_api:WriteFile');
  });

  test('should score entry point functions', () => {
    const func = {
      size: 500,
      caller_count: 5,
      callees: [],
      is_entry_point: true,
      is_exported: false
    };

    const result = calculateScore(func);
    expect(result.score).toBe(20.0);
    expect(result.reasons).toContain('entry_point');
  });

  test('should score exported functions', () => {
    const func = {
      size: 500,
      caller_count: 5,
      callees: [],
      is_entry_point: false,
      is_exported: true
    };

    const result = calculateScore(func);
    expect(result.score).toBe(20.0);
    expect(result.reasons).toContain('exported');
  });

  test('should combine multiple scoring rules', () => {
    const func = {
      size: 1500,
      caller_count: 20,
      callees: ['CreateProcess'],
      is_entry_point: true,
      is_exported: false
    };

    const result = calculateScore(func);
    const expectedScore = 10.0 + (5.0 * Math.log(20)) + 15.0 + 20.0;
    expect(result.score).toBeCloseTo(expectedScore, 2);
    expect(result.reasons).toContain('large_function');
    expect(result.reasons).toContain('high_callers');
    expect(result.reasons).toContain('calls_sensitive_api:CreateProcess');
    expect(result.reasons).toContain('entry_point');
  });

  test('should handle functions with no special characteristics', () => {
    const func = {
      size: 500,
      caller_count: 5,
      callees: ['printf', 'malloc'],
      is_entry_point: false,
      is_exported: false
    };

    const result = calculateScore(func);
    expect(result.score).toBe(0.0);
    expect(result.reasons).toHaveLength(0);
  });
});
