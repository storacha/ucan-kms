import { access, DID } from '@ucanto/validator'
import { error, ok, Failure } from '@ucanto/server'
import { Verifier } from '@ucanto/principal'
import { EncryptionSetup, EncryptionKeyDecrypt, decrypt as ContentDecrypt } from '@storacha/capabilities/space'
import { AuditLogService } from './auditLog.js'

/**
 * @import { UcanPrivacyValidationService } from './ucanValidation.types.js'
 */

/**
 * Authority is the identity that can authorize the decryption of content.
 */
const Authority = Verifier.parse(
  DID.from('did:key:z6MkqdncRZ1wj8zxCTDUQ8CRT8NQWd63T7mZRvZUX8B7XDFi')
).withDID(DID.from('did:web:web3.storage'))

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
      const decryptKeyCapability = invocation.capabilities.find(
        (cap) => cap.can === EncryptionKeyDecrypt.can
      )
      if (!decryptKeyCapability) {
        const errorMsg = `Invocation does not contain ${EncryptionKeyDecrypt.can} capability!`
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_invocation_capability', errorMsg)
        return error(new Failure(errorMsg))
      }

      if (decryptKeyCapability.with !== spaceDID) {
        const errorMsg = `Invalid "with" in the invocation. Decryption is allowed only for files associated with spaceDID: ${spaceDID}!`
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_resource', errorMsg)
        return error(new Failure(errorMsg))
      }

      // Find proofs that contain ContentDecrypt capability for the correct space
      const contentDecryptProofs = invocation.proofs.filter(proof => {
        const delegation = /** @type {import('@ucanto/interface').Delegation} */(proof)
        const now = Math.floor(Date.now() / 1000)
        return delegation.expiration > now &&
          delegation.capabilities.some(capability =>
            capability.can === ContentDecrypt.can &&
            capability.with === spaceDID
          )
      })

      if (contentDecryptProofs.length === 0) {
        const errorMsg = 'No valid ContentDecrypt delegation found in proofs!'
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_proof', errorMsg)
        return error(new Failure(errorMsg))
      }

      // Check that the invocation issuer matches the delegation audience
      const decryptDelegation = /** @type {import('@ucanto/interface').Delegation} */(contentDecryptProofs[0])
      if (invocation.issuer.did() !== decryptDelegation.audience.did()) {
        const errorMsg = 'The invoker must be equal to the delegated audience!'
        this.auditLog.logUCANValidationFailure(spaceDID, 'decryption_audience', errorMsg)
        return error(new Failure(errorMsg))
      }

      // Validate the clean invocation has proper authorization to decrypt content
      const authorization = await access(/** @type {any} */(decryptDelegation), {
        principal: Verifier,
        capability: ContentDecrypt,
        authority: Authority,
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
