/**
 * Create a "ucan/attest" delegation allowing UCANs that have attestions issued
 * by "alias-did" to be validated.
 *
 * Usage: node mk-validator-proof.mjs <service-did-web> <service-private-key> <alias-did-web>
 */
import * as DID from '@ipld/dag-ucan/did'
import { CAR, delegate } from '@ucanto/core'
import * as ed25519 from '@ucanto/principal/ed25519'
import { base64 } from 'multiformats/bases/base64'
import { identity } from 'multiformats/hashes/identity'
import * as Link from 'multiformats/link'

const serviceDIDWeb = process.argv[2]
console.log(`Service DID Web: ${serviceDIDWeb}`)
const servicePrivateKey = process.argv[3]
console.log(`Service Private Key: ${servicePrivateKey.slice(0, 7)}...${servicePrivateKey.slice(-7)}`)
const aliasDIDWeb = process.argv[4]
console.log(`Alias DID Web: ${aliasDIDWeb}`)

const service = ed25519
  .parse(servicePrivateKey)
  .withDID(DID.parse(serviceDIDWeb).did())
const alias = DID.parse(aliasDIDWeb)

const delegation = await delegate({
  issuer: service,
  audience: alias,
  capabilities: [{ can: 'ucan/attest', with: service.did() }],
  expiration: Infinity
})

console.log('Delegation created: [issuer: ' + service.did() + ', audience: ' + alias.did() + ', capabilities: [{can: "ucan/attest", with: "' + service.did() + '"}]]')

const res = await delegation.archive()
if (res.error) throw res.error

console.log(Link.create(CAR.code, identity.digest(res.ok)).toString(base64))
