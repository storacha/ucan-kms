import * as Server from '@ucanto/server'
import * as CAR from '@ucanto/transport/car'

/**
 * Creates a UCAN server.
 *
 * @param {import('./api.types.js').Context} ctx
 * @param {import('./api.types.js').Service} service
 */
export function createServer(ctx, service) {
  return Server.create({
    id: ctx.ucanKmsSigner,
    codec: CAR.inbound,
    service,
    catch: err => console.error(err),
    // TODO: wire into revocations
    validateAuthorization: () => ({ ok: {} })
  })
}
