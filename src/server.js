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
    validateAuthorization: () => ({ ok: {} })
  })
}
