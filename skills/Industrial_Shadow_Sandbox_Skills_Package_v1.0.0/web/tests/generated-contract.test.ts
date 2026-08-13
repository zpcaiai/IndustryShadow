import { describe, expect, it } from 'vitest'
import { API_CONTRACT_DIGEST, API_ROUTE_COUNT, matchesApiRoute } from '../src/api/generated-contract'

describe('generated backend route contract', () => {
  it('binds the checked-in client to the complete backend contract', () => {
    expect(API_ROUTE_COUNT).toBe(89)
    expect(API_CONTRACT_DIGEST).toMatch(/^[a-f0-9]{64}$/)
    expect(matchesApiRoute('GET', '/runs/run-1/timeline')).toBe(true)
    expect(matchesApiRoute('POST', '/runs/run-1/timeline')).toBe(false)
    expect(matchesApiRoute('PATCH', '/scenarios/scenario-1')).toBe(true)
    expect(matchesApiRoute('GET', '/unknown')).toBe(false)
  })
})
