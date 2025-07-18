import { GoogleKMSService } from './services/googleKms.js'
import { KmsRateLimiter } from './services/kmsRateLimiter.js'
import { AuditLogService } from './services/auditLog.js'
import { createService } from './service.js'
import { createServer } from './server.js'
import { ed25519 } from '@ucanto/principal'
import { Schema as UcantoSchema } from '@ucanto/core'
import { RevocationStatusServiceImpl } from './services/revocation.js'
import { PlanSubscriptionServiceImpl } from './services/subscription.js'
import { UcanPrivacyValidationServiceImpl } from './services/ucanValidation.js'

export default {
  /**
   *
   * @param {Request} request
   * @param {import('./types/env.js').Env} env
   * @param {import('./api.types.js').Context} ctx
   * @returns
   */
  async fetch (request, env, ctx) {
    // UCAN Server needs to handle OPTIONS requests
    if (request.method === 'OPTIONS') {
      const headers = new Headers()
      headers.set('Access-Control-Allow-Origin', '*')
      headers.set('Access-Control-Allow-Methods', 'POST, OPTIONS')
      headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
      return new Response(null, { headers, status: 204 })
    }
    if (request.method !== 'POST' || new URL(request.url).pathname !== '/') {
      // Not supported
      return new Response(null, { status: 405 })
    }

    // Prepare audit log
    const auditLog = new AuditLogService({
      serviceName: 'ucan-kms',
      environment: env.ENVIRONMENT || 'development',
      requestId: request.headers.get('cf-ray') || `req-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
    })

    try {
      // Prepare context
      const ucanKmsSigner = ed25519.Signer.parse(env.UCAN_KMS_PRINCIPAL_KEY);
      const ucanKmsIdentity = ucanKmsSigner.withDID(
        UcantoSchema.DID.from(env.UCAN_KMS_SERVICE_DID)
      );
            
      const newCtx = {
        ...ctx,
        ucanKmsSigner,
        ucanKmsIdentity,
        kms: new GoogleKMSService(env, { auditLog, environment: env.ENVIRONMENT }),
        kmsRateLimiter: new KmsRateLimiter(env, { auditLog }),
        revocationStatusService: new RevocationStatusServiceImpl({ auditLog }),
        subscriptionStatusService: new PlanSubscriptionServiceImpl({ auditLog }),
        ucanPrivacyValidationService: new UcanPrivacyValidationServiceImpl({ auditLog })
      };
      // Create service handler and ucan server
      const service = ctx.service ?? createService(newCtx, env)
      const server = ctx.server ?? createServer(newCtx, service)

      // Process request
      console.log('[Main] Processing request...');
      const { headers, body, status } = await server.request({
        body: new Uint8Array(await request.arrayBuffer()),
        headers: Object.fromEntries(request.headers),
      })

      console.log('[Main] Request processed');
      return new Response(body, { headers, status: status ?? 200 })
    } catch (error) {
      console.error('Error processing request:', error)
      return new Response('Internal Server Error', { status: 500 })
    }
  }
}
