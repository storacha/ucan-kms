import { access } from '@ucanto/validator'
import { error, ok, Failure } from '@ucanto/server'
import { Verifier } from '@ucanto/principal'
import { EncryptionSetup, EncryptionKeyDecrypt, decrypt as ContentDecrypt } from '@storacha/capabilities/space'
import { AuditLogService } from './auditLog.js'

/**
 * @import { UcanPrivacyValidationService } from './ucanValidation.types.js'
 */

/**
 * UCAN Validation service implementation
 * @implements {UcanPrivacyValidationService}
 */
export class UcanPrivacyValidationServiceImpl {
  /**
   * Creates a new UCAN validation service
   * @param {Object} [options] - Service options
   * @param {AuditLogService} [options.auditLog] - Audit log service instance
   * @param {string} [options.environment] - Environment name for audit logging
   */
  constructor (options = {}) {
    this.auditLog = options.auditLog || new AuditLogService({
      serviceName: 'ucan-validation-service',
      environment: options.environment || 'unknown'
    })
    // Only log service initialization in development
    if (process.env.NODE_ENV === 'development') {
      this.auditLog.logServiceInitialization('UcanPrivacyValidationService', true)
    }
  }

  /**
   * Validates an encryption setup invocation
   *
   * @param {import('@ucanto/interface').Invocation} invocation
   * @param {import('@storacha/capabilities/types').SpaceDID} spaceDID
   * @returns {Promise<import('@ucanto/server').Result<boolean, import('@ucanto/server').Failure>>}
   */
  async validateEncryption (invocation, spaceDID) {
    try {
      const setupCapability = invocation.capabilities.find(
        /** @param {{can: string}} cap */(cap) => cap.can === EncryptionSetup.can
      )
      if (!setupCapability) {
        const errorMsg = `Invocation does not contain ${EncryptionSetup.can} capability`
        this.auditLog.logUCANValidationFailure(spaceDID, 'encryption', errorMsg)
        throw new Error(errorMsg)
      }
      if (setupCapability.with !== spaceDID) {
        const errorMsg = `Invalid "with" in the invocation. Setup is allowed only for spaceDID: ${spaceDID}`
        this.auditLog.logUCANValidationFailure(spaceDID, 'encryption', errorMsg)
        throw new Error(errorMsg)
      }
      // Success - only log in debug environments to reduce noise
      if (process.env.NODE_ENV === 'development') {
        this.auditLog.logUCANValidationSuccess(spaceDID, 'encryption')
      }
      return ok(true)
    } catch (err) {
      console.error('[validateEncryption] something went wrong:', err)
      this.auditLog.logUCANValidationFailure(spaceDID, 'validate_encryption', err instanceof Error ? err.message : String(err))
      // Generic error message must be returned to the client to avoid leaking information
      return error(new Failure('Encryption validation failed'))
    }
  }

  /**
   * Validates a decrypt delegation.
   * The invocation should have space/encryption/key/decrypt capability.
   * The delegation proof should contain space/content/decrypt capability.
   * The issuer of the invocation must be in the audience of the delegation.
   * The provided space must be the same as the space in the delegation.
   *
   * @param {import('@ucanto/interface').Invocation} invocation
   * @param {import('@storacha/capabilities/types').SpaceDID} spaceDID
   * @param {import('@ucanto/interface').Verifier} ucanKmsIdentity
   * @returns {Promise<import('@ucanto/server').Result<boolean, import('@ucanto/server').Failure>>}
   */
  async validateDecryption (invocation, spaceDID, ucanKmsIdentity) {
    try {
      // Check invocation has the key decrypt capability
      const decryptCapability = invocation.capabilities.find(
        (cap) => cap.can === EncryptionKeyDecrypt.can
      )
      if (!decryptCapability) {
        const errorMsg = `Invocation does not contain ${EncryptionKeyDecrypt.can} capability!`
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_invocation_capability', errorMsg)
        return error(new Failure(errorMsg))
      }

      if (decryptCapability.with !== spaceDID) {
        const errorMsg = `Invalid "with" in the invocation. Decryption is allowed only for files associated with spaceDID: ${spaceDID}!`
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_resource', errorMsg)
        return error(new Failure(errorMsg))
      }

      // Check that we have exactly one delegation proof
      if (invocation.proofs.length !== 1) {
        const errorMsg = 'Expected exactly one delegation proof!'
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_proof', errorMsg)
        return error(new Failure(errorMsg))
      }

      const delegation = /** @type {import('@ucanto/interface').Delegation} */ (invocation.proofs[0])

      // Check delegation contains space/content/decrypt capability
      if (
        !delegation.capabilities.some(
          (c) => c.can === ContentDecrypt.can
        )
      ) {
        const errorMsg = `Delegation does not contain ${ContentDecrypt.can} capability!`
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_delegation_capability', errorMsg)
        return error(new Failure(errorMsg))
      }

      // Check delegation is for the correct space
      if (
        !delegation.capabilities.some(
          (c) => c.with === spaceDID && c.can === ContentDecrypt.can
        )
      ) {
        const errorMsg = `Invalid "with" in the delegation. Decryption is allowed only for files associated with spaceDID: ${spaceDID}!`
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_with', errorMsg)
        return error(new Failure(errorMsg))
      }

      // Check that the invocation issuer matches the delegation audience
      if (invocation.issuer.did() !== delegation.audience.did()) {
        const errorMsg = 'The invoker must be equal to the delegated audience!'
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_audience', errorMsg)
        return error(new Failure(errorMsg))
      }

      // Validate the content decrypt delegation authorization
      const authorization = await access(/** @type {any} */(delegation), {
        principal: Verifier,
        capability: ContentDecrypt,
        authority: ucanKmsIdentity,
        validateAuthorization: () => ok({})
      })

      if (authorization.error) {
        const errorMsg = authorization.error.toString()
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_authorization', errorMsg)
        return error(new Failure(errorMsg))
      }

      // Success
      this.auditLog.logUCANValidationSuccess(spaceDID, 'decryption')
      return ok(true)
    } catch (err) {
      console.error('[validateDecryption] something went wrong:', err)
      this.auditLog.logUCANValidationFailure(spaceDID, 'decryption', err instanceof Error ? err.message : String(err))
      // Generic error message must be returned to the client to avoid leaking information
      return error(new Failure('Decryption validation failed'))
    }
  }
}
