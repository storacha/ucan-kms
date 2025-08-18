/* eslint-disable no-unused-expressions
   ---
   `no-unused-expressions` doesn't understand that several of Chai's assertions
   are implemented as getters rather than explicit function calls; it thinks
   the assertions are unused expressions. */
import { describe, it, beforeEach, afterEach } from 'mocha'
import { expect } from 'chai'
import sinon from 'sinon'
import { PlanSubscriptionServiceImpl } from '../../../src/services/subscription.js'
import { AuditLogService } from '../../../src/services/auditLog.js'
import { StorachaStorageService } from '../../../src/services/storacha-storage.js'
import { Plan } from '@storacha/capabilities'
import * as ed25519 from '@ucanto/principal/ed25519'

describe('PlanSubscriptionService', () => {
  /** @type {sinon.SinonSandbox} */
  let sandbox
  /** @type {PlanSubscriptionServiceImpl} */
  let service
  /** @type {sinon.SinonStubbedInstance<AuditLogService>} */
  let mockAuditLog
  /** @type {sinon.SinonStubbedInstance<StorachaStorageService>} */
  let mockStorachaStorage
  /** @type {any} */
  let mockContext
  /** @type {any} */
  let mockSigner

  const spaceDID = 'did:key:z6Mko5igLB7NBgBcDYjM7MnRZDFKCLYAfbsEYAnx8HRJGJmu'
  const accountDID = 'did:key:z6MkgHB5sTThaRVihKGb2onkNDQu4vDwKoXJweRCF9m28TkL'

  beforeEach(async () => {
    sandbox = sinon.createSandbox()

    // Create mock audit log
    mockAuditLog = sandbox.createStubInstance(AuditLogService)

    // Create mock storacha storage service
    mockStorachaStorage = sandbox.createStubInstance(StorachaStorageService)

    // Create mock signer
    mockSigner = await ed25519.Signer.generate()

    // Create mock context
    mockContext = {
      ucanKmsSigner: mockSigner,
      ucanKmsIdentity: mockSigner.withDID('did:key:z6MkgHB5sTThaRVihKGb2onkNDQu4vDwKoXJweRCF9m28TkL')
    }

    // Create service with mock dependencies
    service = new PlanSubscriptionServiceImpl({
      UPLOAD_SERVICE_DID: '',
      UPLOAD_SERVICE_URL: '',
      UCAN_KMS_PRINCIPAL_KEY: '',
      UCAN_KMS_SERVICE_DID: '',
      FF_KMS_RATE_LIMITER_ENABLED: '',
      GOOGLE_KMS_PROJECT_ID: '',
      GOOGLE_KMS_LOCATION: '',
      GOOGLE_KMS_KEYRING_NAME: '',
      GOOGLE_KMS_TOKEN: '',
      ENVIRONMENT: 'test'
    }, {
      auditLog: mockAuditLog,
      storachaStorage: mockStorachaStorage,
      environment: 'test'
    })
  })

  afterEach(() => {
    sandbox.restore()
  })

  describe('constructor', () => {
    it('should create service with default audit log when none provided', () => {
      const defaultService = new PlanSubscriptionServiceImpl({
        UPLOAD_SERVICE_DID: '',
        UPLOAD_SERVICE_URL: '',
        UCAN_KMS_PRINCIPAL_KEY: '',
        UCAN_KMS_SERVICE_DID: '',
        FF_KMS_RATE_LIMITER_ENABLED: '',
        GOOGLE_KMS_PROJECT_ID: '',
        GOOGLE_KMS_LOCATION: '',
        GOOGLE_KMS_KEYRING_NAME: '',
        GOOGLE_KMS_TOKEN: '',
        ENVIRONMENT: 'test'
      })
      expect(defaultService.auditLog).to.be.instanceOf(AuditLogService)
    })

    it('should use provided audit log and storage service', () => {
      const customAuditLog = new AuditLogService({ serviceName: 'custom', environment: 'test' })
      const customStorageService = new StorachaStorageService()
      const customService = new PlanSubscriptionServiceImpl({
        UPLOAD_SERVICE_DID: '',
        UPLOAD_SERVICE_URL: '',
        UCAN_KMS_PRINCIPAL_KEY: '',
        UCAN_KMS_SERVICE_DID: '',
        FF_KMS_RATE_LIMITER_ENABLED: '',
        GOOGLE_KMS_PROJECT_ID: '',
        GOOGLE_KMS_LOCATION: '',
        GOOGLE_KMS_KEYRING_NAME: '',
        GOOGLE_KMS_TOKEN: '',
        ENVIRONMENT: 'test'
      }, {
        auditLog: customAuditLog,
        storachaStorage: customStorageService
      })
      expect(customService.auditLog).to.equal(customAuditLog)
      expect(customService.storachaStorage).to.equal(customStorageService)
    })

    it('should use provided environment', () => {
      const customService = new PlanSubscriptionServiceImpl({
        UPLOAD_SERVICE_DID: '',
        UPLOAD_SERVICE_URL: '',
        UCAN_KMS_PRINCIPAL_KEY: '',
        UCAN_KMS_SERVICE_DID: '',
        FF_KMS_RATE_LIMITER_ENABLED: '',
        GOOGLE_KMS_PROJECT_ID: '',
        GOOGLE_KMS_LOCATION: '',
        GOOGLE_KMS_KEYRING_NAME: '',
        GOOGLE_KMS_TOKEN: '',
        ENVIRONMENT: 'test'
      }, { environment: 'production' })
      expect(customService.auditLog).to.be.instanceOf(AuditLogService)
      expect(customService.storachaStorage).to.be.undefined
    })
  })

  describe('isProvisioned', () => {
    it('should return error when no proofs provided', async () => {
      const result = await service.isProvisioned(spaceDID, [], mockContext)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('No Plan/Get Delegation proofs provided')
      sinon.assert.calledWith(
        mockAuditLog.logSecurityEvent,
        'subscription_plan_delegation_missing',
        sinon.match({
          operation: 'subscription_check',
          status: 'denied',
          metadata: sinon.match({
            space: spaceDID,
            reason: 'no_plan_get_delegation_provided',
            proofsCount: 0
          })
        })
      )
    })

    it('should return error when no plan/get delegation found in proofs', async () => {
      // Create mock proof without plan/get capability
      const mockProof = /** @type {any} */({
        capabilities: [{
          can: 'space/info',
          with: accountDID
        }]
      })

      const result = await service.isProvisioned(spaceDID, [mockProof], mockContext)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('No Plan/Get Delegation proofs found')
      sinon.assert.calledWith(
        mockAuditLog.logSecurityEvent,
        'subscription_plan_delegation_missing',
        sinon.match({
          operation: 'subscription_check',
          status: 'denied',
          metadata: sinon.match({
            space: spaceDID,
            reason: 'no_plan_get_delegation_in_proofs',
            proofsCount: 1
          })
        })
      )
    })

    it('should return error when plan/get delegation is invalid', async () => {
      // Mock StorachaStorageService to throw an error
      mockStorachaStorage.getPlan.rejects(new Error('Invalid delegation'))

      // Create mock proof with plan/get capability
      const mockProof = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      const result = await service.isProvisioned(spaceDID, [mockProof], mockContext)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('Subscription validation failed')
      sinon.assert.calledWith(
        mockAuditLog.logSecurityEvent,
        'subscription_plan_service_failure',
        sinon.match({
          operation: 'subscription_check',
          status: 'failure',
          error: 'Invalid delegation'
        })
      )
    })

    it('should return error when plan is not a paid plan', async () => {
      // Mock StorachaStorageService to return a free plan
      const planInfo = {
        plan: { product: 'did:web:free.web3.storage' },
        accountDID
      }
      mockStorachaStorage.getPlan.resolves(planInfo)
      mockStorachaStorage.isPaidPlan.returns(false)

      // Create mock proof with plan/get capability
      const mockProof = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      const result = await service.isProvisioned(spaceDID, [mockProof], mockContext)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('User is not subscribed to a paid plan')
      sinon.assert.calledWith(
        mockAuditLog.logSecurityEvent,
        'subscription_plan_invalid',
        sinon.match({
          operation: 'subscription_check',
          status: 'denied',
          metadata: sinon.match({
            space: spaceDID,
            accountDID,
            reason: 'not_paid_plan',
            planProduct: 'did:web:free.web3.storage'
          })
        })
      )
    })

    it('should return success when valid paid plan delegation is provided', async () => {
      // Mock StorachaStorageService to return a paid plan
      const planInfo = {
        plan: { product: 'did:web:lite.web3.storage' },
        accountDID
      }
      mockStorachaStorage.getPlan.resolves(planInfo)
      mockStorachaStorage.isPaidPlan.returns(true)

      // Create mock proof with plan/get capability
      const mockProof = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      const result = await service.isProvisioned(spaceDID, [mockProof], mockContext)

      expect(result.ok).to.exist
      expect(result.ok?.isProvisioned).to.be.true
      sinon.assert.calledWith(
        mockAuditLog.logSecurityEvent,
        'subscription_plan_validated',
        sinon.match({
          operation: 'subscription_check',
          status: 'success',
          metadata: sinon.match({
            space: spaceDID,
            accountDID,
            planProofsFound: 1,
            validationMethod: 'delegation_presence'
          })
        })
      )
    })

    it('should handle business plan as valid paid plan', async () => {
      // Mock StorachaStorageService to return a business plan
      const planInfo = {
        plan: { product: 'did:web:business.web3.storage' },
        accountDID
      }
      mockStorachaStorage.getPlan.resolves(planInfo)
      mockStorachaStorage.isPaidPlan.returns(true)

      // Create mock proof with plan/get capability
      const mockProof = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      const result = await service.isProvisioned(spaceDID, [mockProof], mockContext)

      expect(result.ok).to.exist
      expect(result.ok?.isProvisioned).to.be.true
    })

    it('should handle errors gracefully and log security events', async () => {
      // Mock StorachaStorageService to throw an unexpected error
      mockStorachaStorage.getPlan.rejects(new Error('Network error'))

      // Create mock proof with plan/get capability
      const mockProof = /** @type {any} */({
        capabilities: [{
          can: Plan.get.can,
          with: accountDID
        }]
      })

      const result = await service.isProvisioned(spaceDID, [mockProof], mockContext)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('Subscription validation failed')
      sinon.assert.calledWith(
        mockAuditLog.logSecurityEvent,
        'subscription_plan_service_failure',
        sinon.match({
          operation: 'subscription_check',
          status: 'failure',
          error: 'Network error'
        })
      )
    })

    it('should handle multiple proofs and find the correct plan/get delegation', async () => {
      // Mock StorachaStorageService to return a paid plan
      const planInfo = {
        plan: { product: 'did:web:lite.web3.storage' },
        accountDID
      }
      mockStorachaStorage.getPlan.resolves(planInfo)
      mockStorachaStorage.isPaidPlan.returns(true)

      // Create multiple proofs, only one with plan/get capability
      const proofs = /** @type {any} */([
        {
          capabilities: [{
            can: 'space/info',
            with: accountDID
          }]
        },
        {
          capabilities: [{
            can: Plan.get.can,
            with: accountDID
          }]
        },
        {
          capabilities: [{
            can: 'store/add',
            with: spaceDID
          }]
        }
      ])

      const result = await service.isProvisioned(spaceDID, proofs, mockContext)

      expect(result.ok).to.exist
      expect(result.ok?.isProvisioned).to.be.true
      // Verify that getPlan was called with the correct delegation (proofs[1])
      sinon.assert.calledOnce(mockStorachaStorage.getPlan)
      sinon.assert.calledWith(mockStorachaStorage.getPlan, proofs[1])
    })
  })
})
