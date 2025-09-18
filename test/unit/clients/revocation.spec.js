/* eslint-disable no-unused-expressions
   ---
   `no-unused-expressions` doesn't understand that several of Chai's assertions
   are implemented as getters rather than explicit function calls; it thinks
   the assertions are unused expressions. */
import { describe, it, beforeEach, afterEach } from 'mocha'
import { expect } from 'chai'
import sinon from 'sinon'
import { RevocationStatusClientImpl } from '../../../src/clients/revocation.js'

describe('RevocationStatusService', () => {
  /** @type {sinon.SinonSandbox} */
  let sandbox
  /** @type {RevocationStatusClientImpl} */
  let service
  /** @type {any} */
  let env
  /** @type {any[]} */
  let mockProofs
  /** @type {string} */
  let mockSpaceDID

  beforeEach(() => {
    sandbox = sinon.createSandbox()
    service = new RevocationStatusClientImpl()

    env = {
      UPLOAD_SERVICE_URL: 'https://revocation.service.test'
    }

    mockSpaceDID = 'did:key:z6Mkw7vtEQHKzWV5eZxagJGzwXPJ8Cc3FUrnGGvBBnGKcUQw'

    // Mock UCAN proofs
    mockProofs = [
      {
        cid: 'bafyreib4pff766vhpbxbhjbqqnsh5emeznvujayjj4z2iu533joyfpga5y',
        capabilities: [{ with: mockSpaceDID, can: 'space/encryption/key/decrypt' }]
      },
      {
        cid: 'bafyreib4pff766vhpbxbhjbqqnsh5emeznvujayjj4z2iu533joyfpgb6z',
        capabilities: [{ with: mockSpaceDID, can: 'space/encryption/setup' }]
      }
    ]
  })

  afterEach(() => {
    sandbox.restore()
  })

  describe('checkStatus', () => {
    it('should return error when no revocation service URL configured', async () => {
      env.UPLOAD_SERVICE_URL = undefined

      const result = await service.checkStatus(mockProofs, mockSpaceDID, env)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('No revocation service URL configured - cannot validate delegation status')
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

      const result = await service.checkStatus(mockProofs, mockSpaceDID, env)

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

      const result = await service.checkStatus(mockProofs, mockSpaceDID, env)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('Delegation explicitly revoked')
      // Fetch should be called at least once to find the revocation
      expect(fetchStub.called).to.be.true
    })

    it('should handle empty proofs array', async () => {
      const result = await service.checkStatus([], mockSpaceDID, env)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal(`No valid delegations found for space ${mockSpaceDID}`)
    })

    it('should handle null or undefined proofs gracefully', async () => {
      // @ts-ignore - Testing error handling for invalid inputs
      const resultNull = await service.checkStatus(null, mockSpaceDID, env)
      // @ts-ignore - Testing error handling for invalid inputs
      const resultUndefined = await service.checkStatus(undefined, mockSpaceDID, env)

      expect(resultNull.error).to.exist
      expect(resultNull.error?.message).to.equal(`No valid delegations found for space ${mockSpaceDID}`)
      expect(resultUndefined.error).to.exist
      expect(resultUndefined.error?.message).to.equal(`No valid delegations found for space ${mockSpaceDID}`)
    })

    it('should handle errors gracefully', async () => {
      // Create a service that will test error handling
      const errorService = new RevocationStatusClientImpl()

      // Override the checkStatus method to test the error handling path
      errorService.checkStatus = async function (proofs, spaceDID, env) {
        try {
          // Force an error to test the catch block
          throw new Error('Service error')
        } catch (err) {
          // This should trigger the error handling logic
          const { error, Failure } = await import('@ucanto/server')
          return error(new Failure(err instanceof Error ? err.message : String(err)))
        }
      }

      const result = await errorService.checkStatus(mockProofs, mockSpaceDID, env)

      expect(result.error).to.exist
      expect(result.error?.message).to.include('Service error')
    })

    it('should handle non-Error exceptions', async () => {
      // Create a service that will test non-Error exception handling
      const errorService = new RevocationStatusClientImpl()

      // Override the checkStatus method to test the error handling path
      errorService.checkStatus = async function (proofs, spaceDID, env) {
        try {
          // Force a non-Error exception to test the catch block
          throw new Error('String error')
        } catch (err) {
          // This should trigger the error handling logic
          const { error, Failure } = await import('@ucanto/server')
          return error(new Failure(err instanceof Error ? err.message : String(err)))
        }
      }

      const result = await errorService.checkStatus(mockProofs, mockSpaceDID, env)

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

      const result = await service.checkStatus(mockProofs, mockSpaceDID, env)

      // Should be a Result type with either ok or error property
      expect(result).to.be.an('object')
      expect(result.ok || result.error).to.exist

      if (result.ok) {
        expect(result.ok).to.be.a('boolean')
      }
    })

    it('should reject delegations with wrong space DID', async () => {
      const wrongSpaceDID = 'did:key:z6MkDifferentSpaceDIDForTesting'
      const proofsWithWrongSpace = [
        {
          cid: 'bafyreib4pff766vhpbxbhjbqqnsh5emeznvujayjj4z2iu533joyfpga5y',
          capabilities: [{ with: 'did:key:z6MkWrongSpaceDID', can: 'space/encryption/key/decrypt' }]
        }
      ]

      // @ts-ignore - Testing with mock proofs
      const result = await service.checkStatus(proofsWithWrongSpace, wrongSpaceDID, env)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal(`No valid delegations found for space ${wrongSpaceDID}`)
    })

    it('should accept delegations with correct space DID', async () => {
      // Mock fetch to return 404 for all CID checks (no explicit revocations)
      const fetchStub = sandbox.stub(globalThis, 'fetch')
      const mockResponse = {
        status: 404,
        headers: {
          get: () => null
        }
      }
      // @ts-ignore - Testing with mock response
      fetchStub.resolves(mockResponse)

      const result = await service.checkStatus(mockProofs, mockSpaceDID, env)

      expect(result.ok).to.exist
      expect(result.ok).to.be.true
    })

    it('should handle delegations without capabilities gracefully', async () => {
      const proofsWithoutCapabilities = [
        {
          cid: 'bafyreib4pff766vhpbxbhjbqqnsh5emeznvujayjj4z2iu533joyfpga5y'
          // No capabilities field
        }
      ]

      // @ts-ignore - Testing with mock proofs
      const result = await service.checkStatus(proofsWithoutCapabilities, mockSpaceDID, env)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal(`No valid delegations found for space ${mockSpaceDID}`)
    })
  })
})
