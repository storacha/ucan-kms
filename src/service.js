import * as UcantoServer from '@ucanto/server'
import { handleEncryptionSetup } from './handlers/encryptionSetup.js'
import { handleKeyDecryption } from './handlers/keyDecryption.js'
import { Schema } from '@ucanto/validator'
import { error } from '@ucanto/client'
import { EncryptionSetup, EncryptionKeyDecrypt } from '@storacha/capabilities/space'

/**
 * @param {import('./api.types.js').Context} ctx
 * @param {import('./types/env.js').Env} env
 * @returns {import('./api.types.js').Service}
 */
export function createService (ctx, env) {
  console.log('[createService] Creating service handler...')
  return {
    space: {
      encryption: {
        setup: UcantoServer.provideAdvanced({
          capability: EncryptionSetup,
          audience: Schema.did({ method: 'web' }),
          handler: async ({ capability, invocation }) => {
            console.log('[createService] Handling encryption setup...')
            if (ctx.kmsRateLimiter) {
              console.log('[createService] Checking rate limit...')
              const rateLimitViolation = await ctx.kmsRateLimiter.checkRateLimit(invocation, EncryptionSetup.can, capability.with)
              if (rateLimitViolation) {
                console.log('[createService] Rate limit violation:', rateLimitViolation)
                return error(new Error(rateLimitViolation))
              }
            }

            console.log('[createService] Validating space...')
            const space = /** @type {import('@storacha/capabilities/types').SpaceDID} */ (capability.with)
            const request = {
              space,
              location: capability.nb?.location,
              keyring: capability.nb?.keyring
            }

            const result = await handleEncryptionSetup(request, invocation, ctx, env)

            // Record successful operation for rate limiting
            if (result.ok && ctx.kmsRateLimiter) {
              ctx.waitUntil(ctx.kmsRateLimiter.recordOperation(invocation, EncryptionSetup.can, capability.with))
            }

            return result
          }
        }),
        key: {
          decrypt: UcantoServer.provideAdvanced({
            capability: EncryptionKeyDecrypt,
            audience: Schema.did({ method: 'web' }),
            handler: async ({ capability, invocation }) => {
              console.log('[createService] Handling key decryption...')
              if (ctx.kmsRateLimiter) {
                console.log('[createService] Checking rate limit...')
                const rateLimitViolation = await ctx.kmsRateLimiter.checkRateLimit(invocation, EncryptionKeyDecrypt.can, capability.with)
                if (rateLimitViolation) {
                  console.log('[createService] Rate limit violation:', rateLimitViolation)
                  return error(new Error(rateLimitViolation))
                }
              }

              console.log('[createService] Decrypting key...')
              const space = /** @type {import('@storacha/capabilities/types').SpaceDID} */ (capability.with)
              const encryptedSymmetricKey = capability.nb?.key
              const request = {
                space,
                encryptedSymmetricKey
              }

              const result = await handleKeyDecryption(request, invocation, ctx, env)

              // Record successful operation for rate limiting
              if (result.ok && ctx.kmsRateLimiter) {
                ctx.waitUntil(ctx.kmsRateLimiter.recordOperation(invocation, EncryptionKeyDecrypt.can, capability.with))
              }

              return result
            }
          })
        }
      }
    }
  }
}
