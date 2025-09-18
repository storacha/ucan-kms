import { GoogleKMSService } from './services/googleKms.js'
import { KmsRateLimiter } from './services/kmsRateLimiter.js'
import { AuditLogService } from './services/auditLog.js'
import { createService } from './service.js'
import { createServer } from './server.js'
import { ed25519 } from '@ucanto/principal'
import { Schema as UcantoSchema } from '@ucanto/core'
import { RevocationStatusClientImpl } from './clients/revocation.js'
import { PlanSubscriptionServiceImpl } from './services/subscription.js'
import { UcanPrivacyValidationServiceImpl } from './services/ucanValidation.js'
/* eslint-disable-next-line */
import packageJson from '../package.json' with { type: 'json' }

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

    const ucanKmsSigner = ed25519.Signer.parse(env.UCAN_KMS_PRINCIPAL_KEY);
    const ucanKmsIdentity = ucanKmsSigner.withDID(
      UcantoSchema.DID.from(env.UCAN_KMS_SERVICE_DID)
    );

    if (request.method === 'GET' && new URL(request.url).pathname === '/') {
      const apiInfo = `🔥 ucan-kms v${packageJson.version}\nhttps://github.com/storacha/ucan-kms\n${ucanKmsIdentity.did()}\n${ucanKmsSigner.did()}`
      return new Response(apiInfo, { status: 200 })
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
      // Add services to the existing context
      ctx.ucanKmsSigner = ucanKmsSigner;
      ctx.ucanKmsIdentity = ucanKmsIdentity;
      ctx.kms = new GoogleKMSService(env, { auditLog, environment: env.ENVIRONMENT });
      ctx.kmsRateLimiter = new KmsRateLimiter(env, { auditLog });
      ctx.revocationStatusClient = new RevocationStatusClientImpl({ auditLog });
      ctx.subscriptionStatusService = new PlanSubscriptionServiceImpl(env, { auditLog });
      ctx.ucanPrivacyValidationService = new UcanPrivacyValidationServiceImpl({ auditLog });

      // Create service handler and ucan server
      const service = ctx.service ?? createService(ctx, env)
      const server = ctx.server ?? await createServer(ctx, service, env)

      const { body, headers } = await server.request({
        body: new Uint8Array(await request.arrayBuffer()),
        headers: Object.fromEntries(request.headers),
      })
      
      // Add CORS headers to the response
      const responseHeaders = new Headers(headers)
      responseHeaders.set('Access-Control-Allow-Origin', '*')
      responseHeaders.set('Access-Control-Allow-Methods', 'POST, OPTIONS')
      responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
      
      // Convert ByteView to Uint8Array for Response constructor
      // TypeScript workaround: explicitly cast the body to handle ByteView types
      const responseBody = /** @type {Uint8Array} */ (
        body instanceof Uint8Array 
          ? body 
          : new Uint8Array(body)
      )
      return new Response(responseBody, { status: 200, headers: responseHeaders })
    } catch (error) {
      console.error('Error processing request:', error)
      const errorHeaders = new Headers()
      errorHeaders.set('Access-Control-Allow-Origin', '*')
      errorHeaders.set('Access-Control-Allow-Methods', 'POST, OPTIONS')
      errorHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
      return new Response('Internal Server Error', { status: 500, headers: errorHeaders })
    }
  }
}
