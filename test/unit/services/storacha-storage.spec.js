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
  let mockUploadServiceConnection
  /** @type {any} */
  let mockSigner

  const accountDID = 'did:mailto:test@example.com'
  const uploadServiceDID = 'did:web:upload.storacha.network'
  const uploadServiceURL = new URL('https://upload.storacha.network')

  beforeEach(async () => {
    sandbox = sinon.createSandbox()
    
    // Create mock signer
    mockSigner = await ed25519.Signer.generate()
    
    // Create mock upload service connection
    mockUploadServiceConnection = {
      id: { did: () => uploadServiceDID },
      execute: sandbox.stub().resolves([{
        out: { 
          ok: {
            product: 'did:web:starter.storacha.network',
            updatedAt: '2024-01-01T00:00:00Z'
          }
        }
      }])
    }
    
    // Create service with config
    service = new StorachaStorageService({ 
      uploadServiceDID,
      uploadServiceURL
    })
    
    // Mock the uploadServiceConnection
    service.uploadServiceConnection = mockUploadServiceConnection
  })

  afterEach(() => {
    sandbox.restore()
  })

  describe('constructor', () => {
    it('should create service with config', () => {
      const testService = new StorachaStorageService({ 
        uploadServiceDID,
        uploadServiceURL
      })
      expect(testService).to.be.instanceOf(StorachaStorageService)
      expect(testService.uploadServiceConnection).to.exist
    })

    it('should create service with empty config', () => {
      const testService = new StorachaStorageService()
      expect(testService).to.be.instanceOf(StorachaStorageService)
      expect(testService.uploadServiceConnection).to.exist
    })

    it('should create service with partial config', () => {
      const testService = new StorachaStorageService({ uploadServiceDID })
      expect(testService).to.be.instanceOf(StorachaStorageService)
      expect(testService.uploadServiceConnection).to.exist
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

      const result = await service.getPlan(mockDelegation, mockSigner)

      expect(result).to.deep.equal({
        plan: {
          product: 'did:web:starter.storacha.network',
          updatedAt: '2024-01-01T00:00:00Z'
        },
        accountDID
      })
      
      // Verify uploadServiceConnection.execute was called
      sinon.assert.calledOnce(mockUploadServiceConnection.execute)
    })

    it('should throw error when no receipt returned', async () => {
      // Mock execute to return empty array
      mockUploadServiceConnection.execute.resolves([])
      
      const mockDelegation = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      try {
        await service.getPlan(mockDelegation, mockSigner)
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error instanceof Error ? error.message : String(error)).to.include('Plan/Get invocation failed: No receipt')
      }
    })

    it('should throw error when no result in receipt', async () => {
      // Mock execute to return receipt without result
      mockUploadServiceConnection.execute.resolves([{ out: null }])
      
      const mockDelegation = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      try {
        await service.getPlan(mockDelegation, mockSigner)
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error instanceof Error ? error.message : String(error)).to.include('Plan/Get invocation failed: No result')
      }
    })

    it('should throw error when result is not ok', async () => {
      // Mock execute to return error result
      mockUploadServiceConnection.execute.resolves([{
        out: { 
          ok: false,
          error: {
            message: 'Invalid delegation'
          }
        }
      }])
      
      const mockDelegation = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      try {
        await service.getPlan(mockDelegation, mockSigner)
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error instanceof Error ? error.message : String(error)).to.include('Plan/Get invocation failed: Invalid delegation')
      }
    })

    it('should throw error when plan has no product', async () => {
      // Mock execute to return plan without product
      mockUploadServiceConnection.execute.resolves([{
        out: { 
          ok: {
            updatedAt: '2024-01-01T00:00:00Z'
          }
        }
      }])
      
      const mockDelegation = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      try {
        await service.getPlan(mockDelegation, mockSigner)
        expect.fail('Should have thrown an error')
      } catch (error) {
        expect(error instanceof Error ? error.message : String(error)).to.include('Plan/Get invocation failed: No product')
      }
    })
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
