import { AuditLogService } from '../services/auditLog.js'
import { EncryptionKeyDecrypt } from '@storacha/capabilities/space'
import { error, ok, Failure } from '@ucanto/server'

/**
 * Handles space/encryption/key/decrypt - decrypts symmetric keys using KMS
 *
 * @param {import('../services/kms.types.js').DecryptionKeyRequest} request
 * @param {import('@ucanto/interface').Invocation} invocation
 * @param {import('../api.types.js').Context} ctx
 * @param {import('../types/env.d.ts').Env} env
 * @returns {Promise<import('@ucanto/server').Result<{decryptedSymmetricKey: string}, import('@ucanto/server').Failure>>} - decryptedSymmetricKey encoded with multiformats/bases/base64
 */
export async function handleKeyDecryption (request, invocation, ctx, env) {
  const auditLog = new AuditLogService({
    serviceName: 'key-decryption-handler',
    environment: env.ENVIRONMENT || 'unknown'
  });
  const startTime = Date.now()
  // Extract invocation CID for audit correlation
  const invocationCid = invocation.cid?.toString()
  const proofs = invocation.proofs

  try {
    if (!ctx.ucanKmsIdentity) {
      const errorMsg = 'Encryption not available - ucanKms identity not configured'
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, errorMsg, invocationCid, Date.now() - startTime)
      return error(new Failure(errorMsg))
    }

    if (!request.encryptedSymmetricKey) {
      const errorMsg = 'Missing encryptedSymmetricKey in invocation'
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, errorMsg, invocationCid, Date.now() - startTime)
      return error(new Failure(errorMsg))
    }

    // Step 1: Validate decrypt delegation and invocation
    const validationResult = await ctx.ucanPrivacyValidationService?.validateDecryption(invocation, request.space, ctx.ucanKmsIdentity)
    if (validationResult?.error) {
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, 'UCAN validation failed', invocationCid, Date.now() - startTime)
      return error(validationResult.error)
    }

    // Step 2: Validate space has paid plan
    const planResult = await ctx.subscriptionStatusService.isProvisioned(request.space, proofs, ctx)
    if (planResult?.error) {
      const errorMsg = planResult.error.message || 'Subscription validation failed'
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, 'Subscription validation failed: ' + errorMsg, invocationCid, Date.now() - startTime)
      return error(planResult.error)
    }

    // Step 3: Check revocation status
    const revocationResult = await ctx.revocationStatusService?.checkStatus(invocation.proofs, env)
    if (revocationResult?.error) {
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, 'Revocation check failed', invocationCid, Date.now() - startTime)
      return error(revocationResult.error)
    }

    if (!ctx.kms) {
      const errorMsg = 'KMS service not available'
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, errorMsg, invocationCid, Date.now() - startTime)
      return error(new Failure(errorMsg))
    }

    // Step 4: Decrypt symmetric key using KMS
    const kmsResult = await ctx.kms.decryptSymmetricKey(request, env)
    if (kmsResult.error) {
      auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, 'KMS decryption failed', invocationCid, Date.now() - startTime)
      return error(kmsResult.error)
    }

    auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, true, undefined, invocationCid, Date.now() - startTime)
    return ok({ decryptedSymmetricKey: kmsResult.ok.decryptedKey })
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err)
    auditLog.logInvocation(request.space, EncryptionKeyDecrypt.can, false, errorMessage, invocationCid, Date.now() - startTime)
    return error(new Failure(errorMessage))
  }
}
