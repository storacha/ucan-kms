import { ok, error } from '@ucanto/validator'
import { AuditLogService } from '../services/auditLog.js'
import { EncryptionSetup } from '@storacha/capabilities/space'

/**
 * Handles space/encryption/setup - creates/retrieves RSA key pair from KMS
 *
 * @param {import('../services/kms.types.js').EncryptionSetupRequest} request
 * @param {import('@ucanto/interface').Invocation} invocation
 * @param {import('../api.types.js').Context} ctx
 * @param {import('../types/env.d.ts').Env} env
 * @returns {Promise<import('@ucanto/client').Result<{publicKey: string, algorithm: string, provider: string}, Error>>}
 */
export async function handleEncryptionSetup (request, invocation, ctx, env) {
  console.log('[EncryptionSetup] Starting encryption setup for space:', request.space);
  const auditLog = new AuditLogService({
    serviceName: 'encryption-setup-handler',
    environment: env.ENVIRONMENT || 'unknown'
  });
  console.log('[EncryptionSetup] Audit log service initialized');
  
  const startTime = Date.now()
  
  try {
    auditLog.logInvocation(request.space, EncryptionSetup.can, true, undefined, undefined, Date.now() - startTime)
    if (env.FF_DECRYPTION_ENABLED !== 'true') {
      const errorMsg = 'Encryption setup is not enabled';
      console.log('[EncryptionSetup] Feature flag FF_DECRYPTION_ENABLED is not enabled');
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, errorMsg, undefined, Date.now() - startTime);
      return error(errorMsg);
    }

    if (!ctx.ucanKmsIdentity) {
      const errorMsg = 'Encryption setup not available - ucanKms identity not configured';
      console.log('[EncryptionSetup] Error: ucanKmsIdentity not found in context');
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, errorMsg, undefined, Date.now() - startTime);
      return error(errorMsg);
    }

    // Step 1: Validate encryption setup delegation
    const validationResult = await ctx.ucanPrivacyValidationService?.validateEncryption(invocation, request.space, ctx.ucanKmsIdentity)
    if (validationResult?.error) {
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, 'UCAN validation failed', undefined, Date.now() - startTime)
      return validationResult
    }

    // Step 2: Validate space has paid plan
    const planResult = await ctx.subscriptionStatusService?.isProvisioned(request.space, env)
    if (planResult?.error) {
      const errorMsg = planResult.error.message
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, 'Subscription validation failed', undefined, Date.now() - startTime)
      return error(errorMsg)
    }

    // Step 3: Create or retrieve KMS key
    console.log('[EncryptionSetup] Checking KMS service availability');
    if (!ctx.kms) {
      const errorMsg = 'KMS service not available';
      console.error('[EncryptionSetup] Error: KMS service not found in context');
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, errorMsg, undefined, Date.now() - startTime);
      return error(errorMsg);
    }

    console.log('[EncryptionSetup] Setting up KMS key for space');
    const kmsResult = await ctx.kms.setupKeyForSpace(request, env);
    if (kmsResult?.error) {
      console.error('[EncryptionSetup] KMS setup failed:', kmsResult.error.message);
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, 'KMS setup failed', undefined, Date.now() - startTime);
      return error(kmsResult.error.message);
    }

    // Step 4: Validate KMS result
    const { publicKey, algorithm, provider } = kmsResult.ok
    if (!publicKey || !algorithm || !provider) {
      const errorMsg = 'Missing public key, algorithm, or provider in encryption setup'
      auditLog.logInvocation(request.space, EncryptionSetup.can, false, errorMsg, undefined, Date.now() - startTime)
      return error(errorMsg)
    }

    // Step 5: Success - Return KMS result
    const duration = Date.now() - startTime;
    console.log(`[EncryptionSetup] Successfully set up KMS key for space ${request.space}`);
    console.log('[EncryptionSetup] Provider:', provider);
    console.log('[EncryptionSetup] Algorithm:', algorithm);
    auditLog.logInvocation(request.space, EncryptionSetup.can, true, undefined, undefined, duration);
    return ok({ provider, publicKey, algorithm });
  } catch (/** @type {any} */ err) {
    const errorMessage = err?.message ? String(err.message) : 'Unknown error during encryption setup';
    console.error('[EncryptionSetup] Error during encryption setup:', errorMessage);
    if (err?.stack) {
      console.error('[EncryptionSetup] Stack trace:', err.stack);
    }
    auditLog.logInvocation(request.space, EncryptionSetup.can, false, errorMessage, undefined, Date.now() - startTime);
    return error(errorMessage);
  }
}
