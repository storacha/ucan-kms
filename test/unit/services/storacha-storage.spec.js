/* eslint-disable no-unused-expressions
   ---
   `no-unused-expressions` doesn't understand that several of Chai's assertions
   are implemented as getters rather than explicit function calls; it thinks
   the assertions are unused expressions. */
import { describe, it, beforeEach, afterEach } from 'mocha'
import { expect } from 'chai'
import sinon from 'sinon'
import { StorachaStorageService } from '../../../src/services/storacha-storage.js'
import * as ed25519 from '@ucanto/principal/ed25519'
import { Plan } from '@storacha/capabilities'

describe('StorachaStorageService', () => {
  /** @type {sinon.SinonSandbox} */
  let sandbox
  /** @type {StorachaStorageService} */
  let service
  /** @type {any} */
  let mockClient
  /** @type {any} */
  let mockSigner

  const accountDID = 'did:key:z6MkgHB5sTThaRVihKGb2onkNDQu4vDwKoXJweRCF9m28TkL'

  beforeEach(async () => {
    sandbox = sinon.createSandbox()
    
    // Create mock signer
    mockSigner = await ed25519.Signer.generate()
    
    // Create mock client
    mockClient = {
      addProof: sandbox.stub().resolves(),
      proofs: sandbox.stub().returns(['mock-proof']),
      agent: {
        invokeAndExecute: sandbox.stub().resolves({
          out: { 
            ok: {
              product: 'did:web:starter.storacha.network',
              updatedAt: '2024-01-01T00:00:00Z'
            }
          }
        })
      }
    }
    
    // Create service with mock client
    service = new StorachaStorageService({ client: /** @type {any} */(mockClient) })
  })

  afterEach(() => {
    sandbox.restore()
  })

  describe('constructor', () => {
    it('should create service with signer', () => {
      const testService = new StorachaStorageService({ signer: mockSigner })
      expect(testService).to.be.instanceOf(StorachaStorageService)
    })

    it('should create service with client', () => {
      const mockClient = /** @type {any} */({ addProof: sinon.stub() })
      const testService = new StorachaStorageService({ client: mockClient })
      expect(testService).to.be.instanceOf(StorachaStorageService)
    })

    it('should throw error when neither client nor signer provided', () => {
      expect(() => new StorachaStorageService()).to.throw('Either client or signer must be provided')
    })
  })

  describe('getPlan', () => {
    it('should successfully retrieve plan information', async () => {
      // Create mock delegation
      const mockDelegation = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      const result = await service.getPlan(mockDelegation)

      expect(result).to.deep.equal({
        plan: {
          product: 'did:web:starter.storacha.network',
          updatedAt: '2024-01-01T00:00:00Z'
        },
        accountDID
      })
      
      // Verify client interactions
      sinon.assert.calledOnce(mockClient.addProof)
      sinon.assert.calledWith(mockClient.addProof, mockDelegation)
      sinon.assert.calledOnce(mockClient.proofs)
      sinon.assert.calledOnce(mockClient.agent.invokeAndExecute)
    })

    it('should throw error when plan/get invocation fails', async () => {
      // Create service with mock client that returns an error
      const errorMockClient = /** @type {any} */({
        addProof: sandbox.stub().resolves(),
        proofs: sandbox.stub().returns(['mock-proof']),
        agent: {
          invokeAndExecute: sandbox.stub().resolves({
            out: { 
              ok: false,
              error: {
                message: 'Invalid delegation'
              }
            }
          })
        }
      })
      const errorService = new StorachaStorageService({ client: errorMockClient })

      // Create mock delegation
      const mockDelegation = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      try {
        await errorService.getPlan(mockDelegation)
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error instanceof Error ? error.message : String(error)).to.include('Plan/Get invocation failed: Invalid delegation')
      }
    })

    it('should throw error when plan/get invocation fails without error message', async () => {
      // Create service with mock client that returns an error without message
      const errorMockClient = /** @type {any} */({
        addProof: sandbox.stub().resolves(),
        proofs: sandbox.stub().returns(['mock-proof']),
        agent: {
          invokeAndExecute: sandbox.stub().resolves({
            out: { 
              ok: false
            }
          })
        }
      })
      const errorService = new StorachaStorageService({ client: errorMockClient })

      // Create mock delegation
      const mockDelegation = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      try {
        await errorService.getPlan(mockDelegation)
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error instanceof Error ? error.message : String(error)).to.include('Plan/Get invocation failed: Unknown error')
      }
    })

    // it('should handle client creation errors', async () => {
    //   // Create a service that will fail during client creation
    //   // We'll mock the createClient import to throw an error
    //   const failingService = new StorachaStorageService({ signer: mockSigner })
      
    //   // Override the clientPromise to reject
    //   failingService.clientPromise = Promise.reject(new Error('Client creation failed'))

    //   // Create mock delegation
    //   const mockDelegation = /** @type {any} */({
    //     capabilities: [{
    //       can: Plan.get.can,
    //       with: accountDID
    //     }]
    //   })

    //   try {
    //     await failingService.getPlan(mockDelegation)
    //     expect.fail('Should have thrown an error')
    //   } catch (error) {
    //     expect(error instanceof Error ? error.message : String(error)).to.equal('Client creation failed')
    //   }
    // })
  })

  describe('isPaidPlan', () => {
    it('should return true for lite plan', () => {
      const result = service.isPaidPlan('did:web:lite.web3.storage')
      expect(result).to.be.true
    })

    it('should return true for business plan', () => {
      const result = service.isPaidPlan('did:web:business.web3.storage')
      expect(result).to.be.true
    })

    it('should return false for free plan', () => {
      const result = service.isPaidPlan('did:web:free.web3.storage')
      expect(result).to.be.false
    })

    it('should return false for unknown plan', () => {
      const result = service.isPaidPlan('did:web:unknown.web3.storage')
      expect(result).to.be.false
    })

    it('should return false for trial plan', () => {
      const result = service.isPaidPlan('did:web:trial.web3.storage')
      expect(result).to.be.false
    })

    it('should return false for empty string', () => {
      const result = service.isPaidPlan('')
      expect(result).to.be.false
    })

    it('should return false for null/undefined', () => {
      expect(service.isPaidPlan(/** @type {any} */(null))).to.be.false
      expect(service.isPaidPlan(/** @type {any} */(undefined))).to.be.false
    })
  })
})
