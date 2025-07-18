import { ok, error } from '@ucanto/validator'
import { AuditLogService } from '../services/auditLog.js'
import { EncryptionKeyDecrypt } from '@storacha/capabilities/space'

/**
 * Handles space/encryption/key/decrypt delegation to decrypt symmetric key using the Space's KMS Asymmetric Key.
 *
 * @param {import('../services/kms.types.js').DecryptionKeyRequest} request
 * @param {import('@ucanto/interface').Invocation} invocation
 * @param {import('../api.types.js').Context} ctx
 * @param {import('../types/env.js').Env} env
 * @returns {Promise<import('@ucanto/client').Result<{decryptedSymmetricKey: string}, Error>>}
 */
export async function handleKeyDecryption (request, invocation, ctx, env) {
  const auditLog = new AuditLogService({
    serviceName: 'key-decryption-handler',
    environment: 'unknown'
  })

  const startTime = Date.now()

  try {
    if (env.FF_DECRYPTION_ENABLED !== 'true') {
      const errorMsg = 'Decryption is not enabled'
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, errorMsg, undefined, Date.now() - startTime)
      return error(errorMsg)
    }

    if (!ctx.ucanKmsIdentity) {
      const errorMsg = 'Encryption not available - ucanKms identity not configured'
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, errorMsg, undefined, Date.now() - startTime)
      return error(errorMsg)
    }

    if (!request.encryptedSymmetricKey) {
      const errorMsg = 'Missing encryptedSymmetricKey in invocation'
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, errorMsg, undefined, Date.now() - startTime)
      return error(errorMsg)
    }

    // Step 1: Validate decrypt delegation and invocation
    const validationResult = await ctx.ucanPrivacyValidationService?.validateDecryption(invocation, request.space, ctx.ucanKmsIdentity)
    if (validationResult?.error) {
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, 'UCAN validation failed', undefined, Date.now() - startTime)
      return error(validationResult.error.message)
    }

    // Step 2: Check revocation status
    const revocationResult = await ctx.revocationStatusService?.checkStatus(invocation.proofs, env)
    if (revocationResult?.error) {
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, 'Revocation check failed', undefined, Date.now() - startTime)
      return error(revocationResult.error.message)
    }

    // Step 3: Decrypt symmetric key using KMS
    if (!ctx.kms) {
      const errorMsg = 'KMS service not available'
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, errorMsg, undefined, Date.now() - startTime)
      return error(errorMsg)
    }

    const kmsResult = await ctx.kms.decryptSymmetricKey(request, env)
    if (kmsResult?.error) {
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, 'KMS decryption failed', undefined, Date.now() - startTime)
      return error(kmsResult.error.message)
    }
    const decryptedSymmetricKey = kmsResult?.ok?.decryptedKey
    if (!decryptedSymmetricKey) {
      const errorMsg = 'Unable to decrypt symmetric key with KMS'
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, errorMsg, undefined, Date.now() - startTime)
      return error(errorMsg)
    }

    // Success
    const duration = Date.now() - startTime
    auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, true, undefined, undefined, duration)
    return ok({ decryptedSymmetricKey })
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err)
    auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, errorMessage, undefined, Date.now() - startTime)
    return error(errorMessage)
  }
}
