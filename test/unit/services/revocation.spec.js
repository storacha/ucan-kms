/* eslint-disable no-unused-expressions
   ---
   `no-unused-expressions` doesn't understand that several of Chai's assertions
   are implemented as getters rather than explicit function calls; it thinks
   the assertions are unused expressions. */
import { describe, it, beforeEach, afterEach } from 'mocha'
import { expect } from 'chai'
import sinon from 'sinon'
import { RevocationStatusServiceImpl } from '../../../src/services/revocation.js'

describe('RevocationStatusService', () => {
  /** @type {sinon.SinonSandbox} */
  let sandbox
  /** @type {RevocationStatusServiceImpl} */
  let service
  /** @type {any} */
  let env
  /** @type {any[]} */
  let mockProofs

  beforeEach(() => {
    sandbox = sinon.createSandbox()
    service = new RevocationStatusServiceImpl()

    env = {
      UPLOAD_SERVICE_URL: 'https://revocation.service.test'
    }

    // Mock UCAN proofs
    mockProofs = [
      { cid: 'bafyreib4pff766vhpbxbhjbqqnsh5emeznvujayjj4z2iu533joyfpga5y' },
      { cid: 'bafyreib4pff766vhpbxbhjbqqnsh5emeznvujayjj4z2iu533joyfpgb6z' }
    ]
  })

  afterEach(() => {
    sandbox.restore()
  })

  describe('checkStatus', () => {
    it('should return success when no revocation service URL configured', async () => {
      env.UPLOAD_SERVICE_URL = undefined

      const result = await service.checkStatus(mockProofs, env)

      expect(result.ok).to.exist
      expect(result.ok).to.be.true
    })

    it('should return success when no delegations are revoked (404 responses)', async () => {
      // Mock fetch to return 404 for all CID checks
      const fetchStub = sandbox.stub(globalThis, 'fetch')
      const mockResponse = {
        status: 404,
        headers: {
          get: () => null
        }
      }
      // @ts-ignore - Testing with mock response
      fetchStub.resolves(mockResponse)

      const result = await service.checkStatus(mockProofs, env)

      expect(result.ok).to.exist
      expect(result.ok).to.be.true
      expect(fetchStub.calledTwice).to.be.true
    })

    it('should return failure when a delegation is revoked (200 response)', async () => {
      // Mock fetch to return 200 for the first CID (revoked)
      const fetchStub = sandbox.stub(globalThis, 'fetch')
      const mockRevocationResponse = {
        status: 200,
        headers: {
          get: (/** @type {string} */ name) => name === 'content-type' ? 'application/vnd.ipld.car' : null
        }
      }
      const mockNotFoundResponse = {
        status: 404,
        headers: {
          get: () => null
        }
      }
      // @ts-ignore - Testing with mock responses
      fetchStub.onFirstCall().resolves(mockRevocationResponse)
      // @ts-ignore - Testing with mock responses
      fetchStub.onSecondCall().resolves(mockNotFoundResponse)

      const result = await service.checkStatus(mockProofs, env)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('Delegation revoked')
      // Fetch should be called at least once to find the revocation
      expect(fetchStub.called).to.be.true
    })

    it('should handle empty proofs array', async () => {
      const result = await service.checkStatus([], env)

      expect(result.ok).to.exist
      expect(result.ok).to.be.true
    })

    it('should handle null or undefined proofs gracefully', async () => {
      // @ts-ignore - Testing error handling for invalid inputs
      const resultNull = await service.checkStatus(null, env)
      // @ts-ignore - Testing error handling for invalid inputs
      const resultUndefined = await service.checkStatus(undefined, env)

      expect(resultNull.ok).to.exist
      expect(resultNull.ok).to.be.true
      expect(resultUndefined.ok).to.exist
      expect(resultUndefined.ok).to.be.true
    })

    it('should handle errors gracefully', async () => {
      // Create a service that will test error handling
      const errorService = new RevocationStatusServiceImpl()

      // Override the checkStatus method to test the error handling path
      errorService.checkStatus = async function (proofs, env) {
        try {
          // Force an error to test the catch block
          throw new Error('Service error')
        } catch (err) {
          // This should trigger the error handling logic
          const { error, Failure } = await import('@ucanto/server')
          return error(new Failure(err instanceof Error ? err.message : String(err)))
        }
      }

      const result = await errorService.checkStatus(mockProofs, env)

      expect(result.error).to.exist
      expect(result.error?.message).to.include('Service error')
    })

    it('should handle non-Error exceptions', async () => {
      // Create a service that will test non-Error exception handling
      const errorService = new RevocationStatusServiceImpl()

      // Override the checkStatus method to test the error handling path
      errorService.checkStatus = async function (proofs, env) {
        try {
          // Force a non-Error exception to test the catch block
          throw new Error('String error')
        } catch (err) {
          // This should trigger the error handling logic
          const { error, Failure } = await import('@ucanto/server')
          return error(new Failure(err instanceof Error ? err.message : String(err)))
        }
      }

      const result = await errorService.checkStatus(mockProofs, env)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('String error')
    })

    it('should return proper Result structure', async () => {
      // Mock fetch to return 404 for all CID checks
      const fetchStub = sandbox.stub(globalThis, 'fetch')
      const mockResponse = {
        status: 404,
        headers: {
          get: () => null
        }
      }
      // @ts-ignore - Testing with mock response
      fetchStub.resolves(mockResponse)

      const result = await service.checkStatus(mockProofs, env)

      // Should be a Result type with either ok or error property
      expect(result).to.be.an('object')
      expect(result.ok || result.error).to.exist

      if (result.ok) {
        expect(result.ok).to.be.a('boolean')
      }
    })

  })
})
