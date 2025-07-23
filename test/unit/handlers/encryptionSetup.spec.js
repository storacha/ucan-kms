/* eslint-disable no-unused-expressions */
import { strict as assert } from 'assert'
import { describe, it, beforeEach, afterEach } from 'mocha'
import sinon from 'sinon'
import { handleEncryptionSetup } from '../../../src/handlers/encryptionSetup.js'
import { AuditLogService } from '../../../src/services/auditLog.js'
import { EncryptionSetup } from '@storacha/capabilities/space'

describe('Encryption Setup Handler', () => {
  /** @type {sinon.SinonSandbox} */
  let sandbox
  /** @type {any} */
  let mockCtx
  /** @type {any} */
  let mockEnv
  /** @type {any} */
  let mockRequest
  /** @type {any} */
  let mockInvocation
  /** @type {sinon.SinonStub} */
  let auditLogStub
  /** @type {sinon.SinonStub} */
  let validateEncryptionStub
  /** @type {sinon.SinonStub} */
  let isProvisionedStub
  /** @type {sinon.SinonStub} */
  let kmsServiceStub

  beforeEach(() => {
    sandbox = sinon.createSandbox()
    
    // Mock request
    mockRequest = {
      space: 'did:key:test123'
    }
    
    // Mock invocation
    mockInvocation = {
      proofs: []
    }
    
    // Mock context
    mockCtx = {
      ucanKmsIdentity: { did: () => 'did:key:kms' },
      ucanPrivacyValidationService: {
        validateEncryption: () => ({ ok: true })
      },
      subscriptionStatusService: {
        isProvisioned: () => ({ ok: true })
      },
      kms: {
        setupKeyForSpace: () => Promise.resolve({
          ok: {
            publicKey: 'test-public-key',
            algorithm: 'RSA-OAEP-256',
            provider: 'test-provider'
          }
        })
      }
    }
    
    // Mock environment
    mockEnv = {
      FF_DECRYPTION_ENABLED: 'true'
    }
    
    // Stub AuditLogService
    auditLogStub = sandbox.stub(AuditLogService.prototype, 'logInvocation')
    
    // Stub validation methods
    validateEncryptionStub = sandbox.stub(mockCtx.ucanPrivacyValidationService, 'validateEncryption')
      .resolves({ ok: true })
    
    isProvisionedStub = sandbox.stub(mockCtx.subscriptionStatusService, 'isProvisioned')
      .resolves({ ok: true })
    
    // Stub KMS service
    kmsServiceStub = sandbox.stub(mockCtx.kms, 'setupKeyForSpace')
      .resolves({
        ok: {
          publicKey: 'test-public-key',
          algorithm: 'RSA-OAEP-256',
          provider: 'test-provider'
        }
      })
  })

  afterEach(() => {
    sandbox.restore()
  })

  it('should handle encryption setup successfully', async () => {
    const result = await handleEncryptionSetup(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert.ok(result.ok)
    assert.equal(result.ok.publicKey, 'test-public-key')
    assert.equal(result.ok.algorithm, 'RSA-OAEP-256')
    assert.equal(result.ok.provider, 'test-provider')
    
    // Verify audit log was called with success
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionSetup.can,
      true,
      undefined,
      undefined,
      sinon.match.number
    ))
  })

  it('should return error when encryption is disabled', async () => {
    mockEnv.FF_DECRYPTION_ENABLED = 'false'
    
    const result = await handleEncryptionSetup(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error.message, 'Encryption setup is not enabled')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionSetup.can,
      false,
      'Encryption setup is not enabled',
      undefined,
      sinon.match.number
    ))
  })

  it('should return error when ucanKmsIdentity is not configured', async () => {
    mockEnv.FF_DECRYPTION_ENABLED = 'true'
    delete mockCtx.ucanKmsIdentity
    
    const result = await handleEncryptionSetup(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error.message, 'Encryption setup not available - ucanKms identity not configured')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionSetup.can,
      false,
      'Encryption setup not available - ucanKms identity not configured',
      undefined,
      sinon.match.number
    ))
  })

  it('should return error when validation fails', async () => {
    mockEnv.FF_DECRYPTION_ENABLED = 'true'
    mockCtx.ucanKmsIdentity = 'mock-identity'
    
    // Add cid to mockInvocation for audit logging
    mockInvocation.cid = {
      toString: () => 'mock-invocation-cid'
    }
    
    const { Failure } = await import('@ucanto/server')
    mockCtx.ucanPrivacyValidationService = {
      validateEncryption: sinon.stub().resolves({ error: new Failure('Invalid request') })
    }
    
    const result = await handleEncryptionSetup(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error.message, 'Invalid request')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionSetup.can,
      false,
      'Invalid request',
      'mock-invocation-cid',
      sinon.match.number
    ))
  })

  it('should return error when space is not provisioned', async () => {
    mockEnv.FF_DECRYPTION_ENABLED = 'true'
    mockCtx.ucanKmsIdentity = 'mock-identity'
    
    // Add cid to mockInvocation for audit logging
    mockInvocation.cid = {
      toString: () => 'mock-invocation-cid-2'
    }
    
    const { Failure } = await import('@ucanto/server')
    mockCtx.ucanPrivacyValidationService = {
      validateEncryption: sinon.stub().resolves({ ok: true })
    }
    mockCtx.subscriptionStatusService = {
      isProvisioned: sinon.stub().resolves({ error: new Failure('Space not provisioned') })
    }
    
    const result = await handleEncryptionSetup(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error.message, 'Space not provisioned')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionSetup.can,
      false,
      'Subscription validation failed: Space not provisioned',
      'mock-invocation-cid-2',
      sinon.match.number
    ))
  })

  it('should handle errors during key setup', async () => {
    mockEnv.FF_DECRYPTION_ENABLED = 'true'
    mockCtx.ucanKmsIdentity = 'mock-identity'
    mockCtx.ucanPrivacyValidationService = {
      validateEncryption: sinon.stub().resolves({ ok: true })
    }
    mockCtx.subscriptionStatusService = {
      isProvisioned: sinon.stub().resolves({ ok: { ok: true } })
    }
    mockCtx.kms = {
      setupKeyForSpace: sinon.stub().resolves({ error: new Error('Failed to setup key') })
    }
    
    const result = await handleEncryptionSetup(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error.message, 'Failed to setup key')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionSetup.can,
      false,
      'KMS setup failed',
      undefined,
      sinon.match.number
    ))
  })
})
