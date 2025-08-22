import * as Server from '@ucanto/server'
import * as CAR from '@ucanto/transport/car'
import { DIDResolutionError } from '@ucanto/validator'
import * as Proof from '@storacha/client/proof'

/**
 * @type {Record<`did:${string}:${string}`, `did:key:${string}`>}
 */
export const knownWebDIDs = {
  // Production
  'did:web:up.storacha.network': 'did:key:z6MkqdncRZ1wj8zxCTDUQ8CRT8NQWd63T7mZRvZUX8B7XDFi',
  'did:web:web3.storage': 'did:key:z6MkqdncRZ1wj8zxCTDUQ8CRT8NQWd63T7mZRvZUX8B7XDFi', // legacy
  'did:web:w3s.link': 'did:key:z6Mkha3NLZ38QiZXsUHKRHecoumtha3LnbYEL21kXYBFXvo5',
  'did:web:kms.storacha.network': 'did:key:z6MksQJobJmBfPhjHWgFXVppqM6Fcjc1k7xu4z6xvusVrtKv',

  // Staging
  'did:web:staging.up.storacha.network': 'did:key:z6MkhcbEpJpEvNVDd3n5RurquVdqs5dPU16JDU5VZTDtFgnn',
  'did:web:staging.web3.storage': 'did:key:z6MkhcbEpJpEvNVDd3n5RurquVdqs5dPU16JDU5VZTDtFgnn', // legacy
  'did:web:staging.w3s.link': 'did:key:z6MkqK1d4thaCEXSGZ6EchJw3tDPhQriwynWDuR55ayATMNf',
  'did:web:staging.kms.storacha.network': 'did:key:z6MkmRf149D6oc9wq9ioXCsT5fgTn6esd7JjB9S5JnM4Y9qj'
}

/**
 * Creates a UCAN server.
 *
 * @param {import('./api.types.js').Context} ctx
 * @param {import('./api.types.js').Service} service
 * @param {import('./types/env.js').Env} env
 */
export async function createServer (ctx, service, env) {
  console.log('Creating server...')
  const validatorProofs = await getValidatorProofs(env)
  console.log('Validator proofs loaded: ' + validatorProofs.length)
  const server = Server.create({
    id: ctx.ucanKmsSigner.withDID(ctx.ucanKmsIdentity.did()),
    codec: CAR.inbound,
    service,
    validateAuthorization: () => ({ ok: {} }),
    resolveDIDKey,
    proofs: validatorProofs
  })
  console.log('Server created')
  return server
}

/**
 *
 * @param {import('@ucanto/interface').DID} did
 * @returns
 */
export const resolveDIDKey = async (did) => {
  if (knownWebDIDs[did]) {
    const didKey = /** @type {`did:key:${string}`} */ (knownWebDIDs[did])
    return Server.ok(didKey)
  }
  return Server.error(new DIDResolutionError(did))
}

/**
 * @type {import('@ucanto/interface').Delegation[]}
 */
let cachedValidatorProofs

/**
 * @param {import('./types/env.js').Env} env
 * @returns {Promise<import('@ucanto/interface').Delegation[]>}
 */
export const getValidatorProofs = async (env) => {
  if (cachedValidatorProofs) {
    return cachedValidatorProofs
  }
  cachedValidatorProofs = []
  if (env.UCAN_VALIDATOR_PROOF) {
    const proof = await Proof.parse(env.UCAN_VALIDATOR_PROOF)
    const delegation = /** @type {import('@ucanto/interface').Delegation} */ (proof)
    console.log(`Validator proof loaded: [issuer: ${delegation.issuer.did()}, audience: ${delegation.audience.did()}, capabilities: ${delegation.capabilities.map(c => `{${c.can} @ ${c.with}}`).join(', ')}]`)
    cachedValidatorProofs = [delegation]
  }
  return cachedValidatorProofs
}
