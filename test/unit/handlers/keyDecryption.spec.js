import { strict as assert } from 'assert'
import { describe, it, beforeEach, afterEach } from 'mocha'
import sinon from 'sinon'
import { handleKeyDecryption } from '../../../src/handlers/keyDecryption.js'
import { AuditLogService } from '../../../src/services/auditLog.js'
import { EncryptionKeyDecrypt } from '@storacha/capabilities/space'

describe('Key Decryption Handler', () => {
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
  let validateDecryptionStub
  /** @type {sinon.SinonStub} */
  let checkStatusStub
  /** @type {sinon.SinonStub} */
  let decryptStub

  beforeEach(() => {
    sandbox = sinon.createSandbox()
    
    // Mock request
    mockRequest = {
      space: 'did:key:test123',
      encryptedSymmetricKey: 'encrypted-key-data'
    }
    
    // Mock invocation
    mockInvocation = {
      proofs: ['proof1', 'proof2']
    }
    
    // Mock context
    mockCtx = {
      ucanKmsIdentity: { did: () => 'did:key:kms' },
      ucanPrivacyValidationService: {
        validateDecryption: () => ({ ok: true })
      },
      revocationStatusService: {
        checkStatus: () => ({ ok: true })
      },
      kms: {
        decryptSymmetricKey: () => Promise.resolve({
          ok: {
            decryptedKey: 'decrypted-key-data'
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
    validateDecryptionStub = sandbox.stub(mockCtx.ucanPrivacyValidationService, 'validateDecryption')
      .resolves({ ok: true })
    
    // Stub revocation status check
    checkStatusStub = sandbox.stub(mockCtx.revocationStatusService, 'checkStatus')
      .resolves({ ok: true })
    
    // Stub KMS decrypt
    decryptStub = sandbox.stub(mockCtx.kms, 'decryptSymmetricKey')
      .resolves({
        ok: {
          decryptedKey: 'decrypted-key-data'
        }
      })
  })

  afterEach(() => {
    sandbox.restore()
  })

  it('should handle key decryption successfully', async () => {
    const result = await handleKeyDecryption(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert.ok(result.ok)
    assert.equal(result.ok.decryptedSymmetricKey, 'decrypted-key-data')
    
    // Verify audit log was called with success
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionKeyDecrypt.can,
      true,
      undefined,
      undefined,
      sinon.match.number
    ))
  })

  it('should return error when decryption is disabled', async () => {
    mockEnv.FF_DECRYPTION_ENABLED = 'false'
    
    const result = await handleKeyDecryption(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error?.message, 'Decryption is not enabled')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionKeyDecrypt.can,
      false,
      'Decryption is not enabled',
      undefined,
      sinon.match.number
    ))
  })

  it('should return error when ucanKmsIdentity is not configured', async () => {
    mockCtx.ucanKmsIdentity = null
    
    const result = await handleKeyDecryption(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error?.message, 'Encryption not available - ucanKms identity not configured')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionKeyDecrypt.can,
      false,
      'Encryption not available - ucanKms identity not configured',
      undefined,
      sinon.match.number
    ))
  })

  it('should return error when encryptedSymmetricKey is missing', async () => {
    delete mockRequest.encryptedSymmetricKey
    
    const result = await handleKeyDecryption(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error?.message, 'Missing encryptedSymmetricKey in invocation')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionKeyDecrypt.can,
      false,
      'Missing encryptedSymmetricKey in invocation',
      undefined,
      sinon.match.number
    ))
  })

  it('should return error when UCAN validation fails', async () => {
    const validationError = new Error('UCAN validation failed')
    validateDecryptionStub.resolves({ error: validationError })
    
    const result = await handleKeyDecryption(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error?.message, 'UCAN validation failed')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionKeyDecrypt.can,
      false,
      'UCAN validation failed',
      undefined,
      sinon.match.number
    ))
  })

  it('should return error when UCAN is revoked', async () => {
    const revocationError = new Error('UCAN has been revoked')
    checkStatusStub.resolves({ error: revocationError })
    
    const result = await handleKeyDecryption(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error?.message, 'UCAN has been revoked')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionKeyDecrypt.can,
      false,
      'Revocation check failed',
      undefined,
      sinon.match.number
    ))
  })

  it('should handle errors during decryption', async () => {
    const decryptionError = new Error('Failed to decrypt key')
    decryptStub.resolves({ error: decryptionError })
    
    const result = await handleKeyDecryption(mockRequest, mockInvocation, mockCtx, mockEnv)
    
    assert(!result.ok)
    assert.equal(result.error?.message, 'Failed to decrypt key')
    
    // Verify audit log was called with error
    assert(auditLogStub.calledWith(
      mockRequest.space,
      EncryptionKeyDecrypt.can,
      false,
      'KMS decryption failed',
      undefined,
      sinon.match.number
    ))
  })
})
