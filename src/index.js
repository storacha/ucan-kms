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
  async fetch(request, env, ctx) {
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
      const ucanKmsSigner = ed25519.Signer.parse(env.UCAN_KMS_PRINCIPAL_KEY)
      const newCtx = {
        ...ctx,
        ucanKmsSigner,
        ucanKmsIdentity: ucanKmsSigner.withDID(
          UcantoSchema.DID.from(env.UCAN_KMS_SERVICE_DID)
        ),
        kms: new GoogleKMSService(env, { auditLog }),
        kmsRateLimiter: new KmsRateLimiter(env, { auditLog }),
        revocationStatusService: new RevocationStatusServiceImpl({ auditLog }),
        subscriptionStatusService: new PlanSubscriptionServiceImpl({ auditLog }),
        ucanPrivacyValidationService: new UcanPrivacyValidationServiceImpl({ auditLog })
      }

      // Create service handler and ucan server
      const service = ctx.service ?? createService(newCtx, env)
      const server = ctx.server ?? createServer(newCtx, service)

      // Process request
      const { headers, body, status } = await server.request({
        body: new Uint8Array(await request.arrayBuffer()),
        headers: Object.fromEntries(request.headers)
      })

      return new Response(body, { headers, status: status ?? 200 })
    } catch (error) {
      console.error('Error processing request:', error)
      return new Response('Internal Server Error', { status: 500 })
    }
  }
}
