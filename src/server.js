import * as Server from '@ucanto/server'
import * as CAR from '@ucanto/transport/car'

/**
 * Creates a UCAN server.
 *
 * @param {import('./api.types.js').Context} ctx
 * @param {import('./api.types.js').Service} service
 */
export function createServer (ctx, service) {
  return Server.create({
    id: ctx.ucanKmsSigner.withDID(ctx.ucanKmsIdentity.did()),
    codec: CAR.inbound,
    service,
    catch: err => {
      console.error('[UCAN Server Catch] Error in server:', err)
      if (err && err.stack) {
        console.error('[UCAN Server Catch] Stack trace:', err.stack)
      }
      try {
        console.error('[UCAN Server Catch] Error (JSON):', JSON.stringify(err, Object.getOwnPropertyNames(err)))
      } catch (e) {
        // ignore circular refs
      }
    },
    // TODO: wire into revocations
    validateAuthorization: () => {
      return { ok: {} }
    }
  })
}
