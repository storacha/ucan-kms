import { AuditLogService } from '../services/auditLog.js'
import { EncryptionSetup } from '@storacha/capabilities/space'
import { error, ok, Failure } from '@ucanto/server'

/**
 * Handles space/encryption/setup - creates/retrieves RSA key pair from KMS
 *
 * @param {import('../services/kms.types.js').EncryptionSetupRequest} request
 * @param {import('@ucanto/interface').Invocation} invocation
 * @param {import('../api.types.js').Context} ctx
 * @param {import('../types/env.d.ts').Env} env
 * @returns {Promise<import('@ucanto/server').Result<{publicKey: string, algorithm: string, provider: string}, import('@ucanto/server').Failure>>}
 */
export async function handleEncryptionSetup (request, invocation, ctx, env) {
  const auditLog = new AuditLogService({
    serviceName: 'encryption-setup-handler',
    environment: env.ENVIRONMENT || 'unknown'
  });
  
  const startTime = Date.now()
  // Extract invocation CID for audit correlation
  const invocationCid = invocation.cid?.toString()
  
  try {
    // Validate inputs first before logging any success
    if (env.FF_DECRYPTION_ENABLED !== 'true') {
      const errorMsg = 'Encryption setup is not enabled';
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, errorMsg, invocationCid, Date.now() - startTime);
      return error(new Failure(errorMsg))
    }

    if (!ctx.ucanKmsIdentity) {
      const errorMsg = 'Encryption setup not available - ucanKms identity not configured';
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, errorMsg, invocationCid, Date.now() - startTime);
      return error(new Failure(errorMsg))
    }

    // Step 1: Validate UCAN invocation
    const ucanValidationResult = await ctx.ucanPrivacyValidationService?.validateEncryption(invocation, request.space)
    if (ucanValidationResult?.error) {
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, ucanValidationResult.error.message, invocationCid, Date.now() - startTime)
      return error(ucanValidationResult.error)
    }

    // Step 2: Validate space has paid plan (if subscription service is available)
    const planResult = await ctx.subscriptionStatusService?.isProvisioned(invocation, request.space, env)
    if (planResult?.error) {
      const errorMsg = planResult.error.message || 'Subscription validation failed'
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, 'Subscription validation failed: ' + errorMsg, invocationCid, Date.now() - startTime)
      return error(planResult.error)
    }
    if (!planResult?.ok.provisioned) {
      const errorMsg = 'User account owner of the space does not have a paid plan'
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, errorMsg, invocationCid, Date.now() - startTime)
      return error(new Failure(errorMsg))
    }

    // Step 3: Ensure KMS service is available
    if (!ctx.kms) {
      const errorMsg = 'KMS service not available';
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, errorMsg, invocationCid, Date.now() - startTime);
      return error(new Failure(errorMsg))
    }

    // Step 4: Setup KMS key
    const kmsResult = await ctx.kms.setupKeyForSpace(request, env);
    if (kmsResult.error) {
      console.error('[EncryptionSetup] KMS setup failed:', kmsResult.error.message);
              // KMS service already logs detailed failure - just log handler-level failure
        auditLog.logInvocation(request.space, EncryptionSetup.can, false, 'KMS setup failed', invocationCid, Date.now() - startTime);
      return error(kmsResult.error);
    }

    // Step 5: Validate KMS result
    const { publicKey, algorithm, provider } = kmsResult.ok
    if (!publicKey || !algorithm || !provider) {
      const errorMsg = 'Missing public key, algorithm, or provider in encryption setup'
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, errorMsg, invocationCid, Date.now() - startTime)
      return error(new Failure(errorMsg))
    }

    // Step 5: Success - Return KMS result
    const duration = Date.now() - startTime;
    auditLog.logInvocation(request.space, EncryptionSetup.can, true, undefined, invocationCid, duration);
    return ok(kmsResult.ok);
  } catch (/** @type {any} */ err) {
    console.error('[EncryptionSetup] Error during encryption setup:', err);
    auditLog.logInvocation(request.space, EncryptionSetup.can, false, err.message, invocationCid, Date.now() - startTime);
    // Generic error message must be returned to the client to avoid leaking information
    return error(new Failure('Encryption setup failed'));
  }
}
