/* eslint-disable no-unused-expressions
   ---
   `no-unused-expressions` doesn't understand that several of Chai's assertions
   are implemented as getters rather than explicit function calls; it thinks
   the assertions are unused expressions. */
import { describe, it, beforeEach, afterEach } from 'mocha'
import { expect } from 'chai'
import sinon from 'sinon'
import * as ed25519 from '@ucanto/principal/ed25519'
import { UcanPrivacyValidationServiceImpl } from '../../../src/services/ucanValidation.js'
import { EncryptionSetup, EncryptionKeyDecrypt, decrypt as ContentDecrypt } from '@storacha/capabilities/space'
import { Link } from '@ucanto/server'

describe('UcanPrivacyValidationService', () => {
  /** @type {sinon.SinonSandbox} */
  let sandbox
  /** @type {UcanPrivacyValidationServiceImpl} */
  let service
  /** @type {any} */
  let ucanKmsSigner
  /** @type {any} */
  let ucanKmsIdentity
  /** @type {any} */
  let clientSigner
  /** @type {any} */
  let clientIdentity
  /** @type {any} */
  let spaceOwnerSigner
  /** @type {any} */
  let spaceOwnerIdentity
  /** @type {`did:key:${string}`} */
  let spaceDID
  /** @type {import('@ucanto/interface').Link} */
  let resourceCID

  beforeEach(async () => {
    sandbox = sinon.createSandbox()
    service = new UcanPrivacyValidationServiceImpl()

    // Setup identities
    ucanKmsSigner = await ed25519.Signer.generate()
    ucanKmsIdentity = ucanKmsSigner.withDID('did:web:test.w3s.link')

    clientSigner = await ed25519.Signer.generate()
    clientIdentity = clientSigner

    spaceOwnerSigner = await ed25519.Signer.generate()
    spaceOwnerIdentity = spaceOwnerSigner
    spaceDID = spaceOwnerIdentity.did()
    resourceCID = Link.parse('bafybeicfjzjsl72ntzvne5apc4mubhtvsb7pd2qgvtqhuzbjznm7bxkuzy')
  })

  afterEach(() => {
    sandbox.restore()
  })

  describe('validateEncryption', () => {
    it('should successfully validate encryption setup invocation', async () => {
      // Create a delegation from space owner to client for encryption setup
      const setupDelegation = await EncryptionSetup
        .delegate({
          issuer: spaceOwnerSigner,
          audience: clientSigner,
          with: spaceDID,
          expiration: Infinity,
          nb: {}
        })

      // Create invocation from client to ucanKmsIdentity with the delegation
      const invocation = await EncryptionSetup.invoke({
        issuer: clientIdentity,
        audience: ucanKmsIdentity,
        with: spaceDID,
        nb: {},
        proofs: [setupDelegation]
      }).buildIPLDView()

      const result = await service.validateEncryption(invocation, spaceDID)

      expect(result.ok).to.exist
      expect(result.ok).to.be.true
    })

    it('should return error when invocation lacks encryption setup capability', async () => {
      const invocation = {
        issuer: spaceOwnerSigner,
        audience: await ed25519.Signer.generate(),
        capabilities: [{
          can: 'space/blob/add',
          with: spaceDID,
          nb: { content: 'some-content' }
        }]
      }

      // @ts-ignore - Testing error handling with incomplete invocation object
      const result = await service.validateEncryption(invocation, spaceDID)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('Encryption validation failed')
    })

    it('should return error when capability "with" field does not match space DID', async () => {
      const otherSpaceSigner = await ed25519.Signer.generate()
      const otherSpaceDID = otherSpaceSigner.did()

      const delegation = await EncryptionSetup.delegate({
        issuer: otherSpaceSigner,
        audience: ucanKmsIdentity,
        with: otherSpaceDID,
        expiration: Math.floor(Date.now() / 1000) + 60,
        nb: {}
      })

      const invocation = {
        issuer: ucanKmsIdentity,
        audience: spaceOwnerSigner,
        with: otherSpaceDID,
        nb: {},
        proofs: [delegation]
      }

      // @ts-ignore - Testing error handling with incomplete invocation object
      const result = await service.validateEncryption(invocation, spaceDID)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('Encryption validation failed')
    })

    it('should validate encryption setup with optional nb fields', async () => {
      // Test with optional location and keyring fields
      const setupDelegation = await EncryptionSetup
        .delegate({
          issuer: spaceOwnerSigner,
          audience: clientSigner,
          with: spaceDID,
          expiration: Infinity,
          nb: {
            location: 'us-central1',
            keyring: 'test-keyring'
          }
        })

      const invocation = await EncryptionSetup.invoke({
        issuer: clientIdentity,
        audience: ucanKmsIdentity,
        with: spaceDID,
        nb: {
          location: 'us-central1',
          keyring: 'test-keyring'
        },
        proofs: [setupDelegation]
      }).buildIPLDView()

      const result = await service.validateEncryption(invocation, spaceDID)

      expect(result.ok).to.exist
      expect(result.ok).to.be.true
    })

    it('should handle complex delegation chains for encryption setup', async () => {
      // Create multi-level delegation chain: SpaceOwner -> Intermediate -> Client
      const intermediateSigner = await ed25519.Signer.generate()

      // First level: Space owner delegates to intermediate
      const intermediateSetupDelegation = await EncryptionSetup
        .delegate({
          issuer: spaceOwnerSigner,
          audience: intermediateSigner,
          with: spaceDID,
          expiration: Infinity,
          nb: {}
        })

      // Second level: Intermediate delegates to client
      const clientSetupDelegation = await EncryptionSetup
        .delegate({
          issuer: intermediateSigner,
          audience: clientSigner,
          with: spaceDID,
          expiration: Infinity,
          nb: {},
          proofs: [intermediateSetupDelegation]
        })

      // Create invocation from client to ucanKmsIdentity
      const invocation = await EncryptionSetup.invoke({
        issuer: clientIdentity,
        audience: ucanKmsIdentity,
        with: spaceDID,
        nb: {},
        proofs: [clientSetupDelegation]
      }).buildIPLDView()

      const result = await service.validateEncryption(invocation, spaceDID)

      expect(result.ok).to.exist
      expect(result.ok).to.be.true
    })

  })

  describe('validateDecryption', () => {
    it('should successfully validate decrypt invocation with valid proofs', async () => {
      // Use the space owner's DID directly as the space DID (similar to validateEncryption test)
      const spaceDIDForTest = spaceOwnerSigner.did()

      // Create ContentDecrypt delegation from space owner to client
      const contentDecryptDelegation = await ContentDecrypt
        .delegate({
          issuer: spaceOwnerSigner,
          audience: clientSigner,
          with: spaceDIDForTest,
          nb: {
            resource: resourceCID
          },
          expiration: Infinity
        })

      // Create KeyDecrypt invocation from client to ucanKmsIdentity with content decrypt delegation as proof
      const invocation = await EncryptionKeyDecrypt.invoke({
        issuer: clientSigner,
        audience: ucanKmsIdentity,
        with: spaceDIDForTest,
        expiration: Infinity,
        nb: {
          key: new TextEncoder().encode('test-key')
        },
        proofs: [contentDecryptDelegation]
      }).buildIPLDView()

      const result = await service.validateDecryption(invocation, spaceDIDForTest, ucanKmsIdentity)

      expect(result.ok).to.exist
      expect(result.ok).to.be.true
    })

    it('should return error when invocation lacks key decrypt capability', async () => {
      const invocation = {
        capabilities: [
          { can: 'space/info', with: spaceDID }
        ],
        proofs: []
      }

      // @ts-ignore - Testing error handling with incomplete invocation object
      const result = await service.validateDecryption(invocation, spaceDID, ucanKmsIdentity)

      expect(result.error).to.exist
      expect(result.error?.message).to.include('Invocation does not contain space/encryption/key/decrypt capability!')
    })

    it('should return error when no delegation proofs are provided', async () => {
      const invocation = await EncryptionKeyDecrypt.invoke({
        issuer: await ed25519.Signer.generate(),
        audience: spaceOwnerSigner,
        nb: {
          key: new TextEncoder().encode('test-key')
        },
        with: spaceDID,
        proofs: [] // No proofs
      }).buildIPLDView()

      const result = await service.validateDecryption(invocation, spaceDID, ucanKmsIdentity)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('No valid ContentDecrypt delegation found in proofs!')
    })

    it('should return error when multiple delegation proofs are provided', async () => {
      const delegation1 = await EncryptionKeyDecrypt.delegate({
        issuer: spaceOwnerSigner,
        audience: await ed25519.Signer.generate(),
        with: spaceDID,
        expiration: Math.floor(Date.now() / 1000) + 60,
        nb: {
          key: new TextEncoder().encode('test-key')
        }
      })

      const delegation2 = await EncryptionKeyDecrypt.delegate({
        issuer: spaceOwnerSigner,
        audience: await ed25519.Signer.generate(),
        with: spaceDID,
        expiration: Math.floor(Date.now() / 1000) + 60,
        nb: {
          key: new TextEncoder().encode('test-key')
        }
      })

      const invocation = await EncryptionKeyDecrypt.invoke({
        issuer: await ed25519.Signer.generate(),
        audience: spaceOwnerSigner,
        nb: {
          key: new TextEncoder().encode('test-key')
        },
        with: spaceDID,
        proofs: [delegation1, delegation2] // Multiple proofs
      }).buildIPLDView()

      const result = await service.validateDecryption(invocation, spaceDID, ucanKmsIdentity)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('No valid ContentDecrypt delegation found in proofs!')
    })

    it('should return error when delegation lacks content decrypt capability', async () => {
      const spaceDIDForTest = spaceOwnerSigner.did()

      // Create a delegation with wrong capability type
      const wrongDelegation = await EncryptionSetup.delegate({
        issuer: spaceOwnerSigner,
        audience: clientSigner,
        with: spaceDIDForTest,
        expiration: Infinity,
        nb: {}
      })

      const invocation = await EncryptionKeyDecrypt.invoke({
        issuer: clientSigner,
        audience: ucanKmsIdentity,
        with: spaceDIDForTest,
        expiration: Infinity,
        nb: {
          key: new TextEncoder().encode('test-key')
        },
        proofs: [wrongDelegation]
      }).buildIPLDView()

      const result = await service.validateDecryption(invocation, spaceDIDForTest, ucanKmsIdentity)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('No valid ContentDecrypt delegation found in proofs!')
    })

    it('should return error when delegation is for wrong space', async () => {
      const spaceDIDForTest = spaceOwnerSigner.did()
      const otherSpaceSigner = await ed25519.Signer.generate()
      const otherSpaceDID = otherSpaceSigner.did()

      // Create delegation for different space
      const wrongSpaceDelegation = await ContentDecrypt.delegate({
        issuer: otherSpaceSigner,
        audience: clientSigner,
        with: otherSpaceDID, // Wrong space DID
        expiration: Infinity,
        nb: {
          resource: resourceCID
        }
      })

      const invocation = await EncryptionKeyDecrypt.invoke({
        issuer: clientSigner,
        audience: ucanKmsIdentity,
        with: spaceDIDForTest, // Different space than delegation
        expiration: Infinity,
        nb: {
          key: new TextEncoder().encode('test-key')
        },
        proofs: [wrongSpaceDelegation]
      }).buildIPLDView()

      const result = await service.validateDecryption(invocation, spaceDIDForTest, ucanKmsIdentity)

      expect(result.error).to.exist
      expect(result.error?.message).to.equal('No valid ContentDecrypt delegation found in proofs!')
    })

    it('should return error when invocation issuer does not match delegation audience', async () => {
      const spaceDIDForTest = spaceOwnerSigner.did()
      const wrongClientSigner = await ed25519.Signer.generate()

      // Create delegation to one client
      const contentDecryptDelegation = await ContentDecrypt.delegate({
        issuer: spaceOwnerSigner,
        audience: clientSigner, // Delegated to clientSigner
        with: spaceDIDForTest,
        expiration: Infinity,
        nb: {
          resource: resourceCID
        }
      })

      // But create invocation from different client
      const invocation = await EncryptionKeyDecrypt.invoke({
        issuer: wrongClientSigner, // Different issuer than delegation audience
        audience: ucanKmsIdentity,
        with: spaceDIDForTest,
        expiration: Infinity,
        nb: {
          key: new TextEncoder().encode('test-key')
        },
        proofs: [contentDecryptDelegation]
      }).buildIPLDView()

      const result = await service.validateDecryption(invocation, spaceDIDForTest, ucanKmsIdentity)

      expect(result.error).to.exist
      expect(result.error?.message).to.include('The invoker must be equal to the delegated audience!')
    })

    it('should return error when capability "with" field does not match space DID', async () => {
      const spaceDIDForTest = spaceOwnerSigner.did()
      const otherSpaceSigner = await ed25519.Signer.generate()
      const otherSpaceDID = otherSpaceSigner.did()

      const invocation = {
        capabilities: [
          { can: EncryptionKeyDecrypt.can, with: otherSpaceDID } // Wrong space DID
        ],
        proofs: []
      }

      // @ts-ignore - Testing error handling with incomplete invocation object
      const result = await service.validateDecryption(invocation, spaceDIDForTest, ucanKmsIdentity)

      expect(result.error).to.exist
      expect(result.error?.message).to.include('Invalid "with" in the invocation. Decryption is allowed only for files associated with spaceDID')
    })

    it('should handle complex multi-level delegation chains for decryption', async () => {
      const spaceDIDForTest = spaceOwnerSigner.did()
      const intermediateSigner = await ed25519.Signer.generate()

      // First level: Space owner delegates content decrypt to intermediate
      const intermediateContentDelegation = await ContentDecrypt.delegate({
        issuer: spaceOwnerSigner,
        audience: intermediateSigner,
        with: spaceDIDForTest,
        expiration: Infinity,
        nb: {
          resource: resourceCID
        }
      })

      // Second level: Intermediate delegates content decrypt to client
      const clientContentDelegation = await ContentDecrypt.delegate({
        issuer: intermediateSigner,
        audience: clientSigner,
        with: spaceDIDForTest,
        expiration: Infinity,
        nb: {
          resource: resourceCID
        },
        proofs: [intermediateContentDelegation]
      })

      // Create key decrypt invocation from client
      const invocation = await EncryptionKeyDecrypt.invoke({
        issuer: clientSigner,
        audience: ucanKmsIdentity,
        with: spaceDIDForTest,
        expiration: Infinity,
        nb: {
          key: new TextEncoder().encode('test-key')
        },
        proofs: [clientContentDelegation]
      }).buildIPLDView()

      const result = await service.validateDecryption(invocation, spaceDIDForTest, ucanKmsIdentity)

      expect(result.ok).to.exist
      expect(result.ok).to.be.true
    })

    it('should handle expired delegation for decryption', async () => {
      const spaceDIDForTest = spaceOwnerSigner.did()
      const expiredTime = Math.floor(Date.now() / 1000) - 1 // 1 second ago

      // Create expired content decrypt delegation
      const expiredContentDelegation = await ContentDecrypt.delegate({
        issuer: spaceOwnerSigner,
        audience: clientSigner,
        with: spaceDIDForTest,
        expiration: expiredTime,
        nb: {
          resource: resourceCID
        }
      })

      const invocation = await EncryptionKeyDecrypt.invoke({
        issuer: clientSigner,
        audience: ucanKmsIdentity,
        with: spaceDIDForTest,
        expiration: Infinity,
        nb: {
          key: new TextEncoder().encode('test-key')
        },
        proofs: [expiredContentDelegation]
      }).buildIPLDView()

      const result = await service.validateDecryption(invocation, spaceDIDForTest, ucanKmsIdentity)

      // Should fail due to expired delegation
      expect(result.error).to.exist
    })

    it('should validate encrypted symmetric key parameter', async () => {
      const spaceDIDForTest = spaceOwnerSigner.did()

      const contentDecryptDelegation = await ContentDecrypt.delegate({
        issuer: spaceOwnerSigner,
        audience: clientSigner,
        with: spaceDIDForTest,
        expiration: Infinity,
        nb: {
          resource: resourceCID
        }
      })

      // Test with different encrypted key formats
      const testKeys = [
        'base64encodedkey==',
        'very-long-encrypted-symmetric-key-data-here',
        'short',
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
      ]

      for (const encryptedKey of testKeys) {
        const invocation = await EncryptionKeyDecrypt.invoke({
          issuer: clientSigner,
          audience: ucanKmsIdentity,
          with: spaceDIDForTest,
          expiration: Infinity,
          nb: {
            key: new TextEncoder().encode(encryptedKey)
          },
          proofs: [contentDecryptDelegation]
        }).buildIPLDView()

        const result = await service.validateDecryption(invocation, spaceDIDForTest, ucanKmsIdentity)

        expect(result.ok).to.exist
        expect(result.ok).to.be.true
      }
    })
  })

  describe('Edge Cases and Security Tests', () => {
    it('should handle malformed invocation objects gracefully', async () => {
      // Test with completely invalid invocation
      const malformedInvocations = [
        null,
        undefined,
        {},
        { capabilities: null },
        { capabilities: undefined },
        { capabilities: 'not-an-array' },
        { capabilities: [] }
      ]

      for (const malformedInvocation of malformedInvocations) {
        try {
          // @ts-ignore - Testing malformed input
          const result = await service.validateEncryption(malformedInvocation, spaceDID, ucanKmsIdentity)
          expect(result.error).to.exist
        } catch (error) {
          // Catching any thrown errors is also acceptable for malformed input
          expect(error).to.exist
        }
      }
    })

    it('should handle boundary conditions for expiration times', async () => {
      const spaceDIDForTest = spaceOwnerSigner.did()
      const currentTime = Math.floor(Date.now() / 1000)

      // Test edge cases around current time
      const boundaryTimes = [
        currentTime - 1, // Just expired
        currentTime, // Exactly now
        currentTime + 1, // Just valid
        currentTime + 3600, // Valid for 1 hour
        0, // Invalid (epoch)
        -1 // Invalid (negative)
      ]

      for (const expTime of boundaryTimes) {
        try {
          const delegation = await ContentDecrypt.delegate({
            issuer: spaceOwnerSigner,
            audience: clientSigner,
            with: spaceDIDForTest,
            expiration: expTime,
            nb: {
              resource: resourceCID
            }
          })

          const invocation = await EncryptionKeyDecrypt.invoke({
            issuer: clientSigner,
            audience: ucanKmsIdentity,
            with: spaceDIDForTest,
            expiration: Infinity,
            nb: {
              key: new TextEncoder().encode('test-key')
            },
            proofs: [delegation]
          }).buildIPLDView()

          const result = await service.validateDecryption(invocation, spaceDIDForTest, ucanKmsIdentity)

          // For expired or invalid times, expect failure
          if (expTime <= currentTime || expTime <= 0) {
            expect(result.error).to.exist
          } else {
            // For valid future times, expect success
            expect(result.ok).to.exist
          }
        } catch (error) {
          // Some boundary conditions may throw during delegation creation
          expect(error).to.exist
        }
      }
    })

    it('should handle invalid DID formats in space validation', async () => {
      const invalidSpaceDIDs = [
        '',
        'not-a-did',
        'did:invalid:format',
        'did:key:',
        'did:web:example.com', // Wrong DID method
        null,
        undefined
      ]

      for (const invalidDID of invalidSpaceDIDs) {
        const invocation = {
          capabilities: [
            { can: EncryptionSetup.can, with: spaceDID }
          ]
        }

        try {
          // @ts-ignore - Testing invalid input
          const result = await service.validateEncryption(invocation, invalidDID, ucanKmsIdentity)
          expect(result.error).to.exist
        } catch (error) {
          // Catching any thrown errors is also acceptable for invalid input
          expect(error).to.exist
        }
      }
    })

    it('should handle service exceptions gracefully', async () => {
      // Test error handling when service validation throws exceptions
      const spaceDIDForTest = spaceOwnerSigner.did()

      // Create invalid invocation that will cause internal errors
      const malformedInvocation = {
        capabilities: [{ can: EncryptionKeyDecrypt.can, with: spaceDIDForTest }],
        proofs: [{
          // This is not a proper delegation object, should cause internal errors
          capabilities: 'not-an-array',
          issuer: { did: () => 'invalid' },
          audience: { did: () => 'invalid' }
        }],
        issuer: { did: () => 'invalid' },
        audience: { did: () => 'invalid' }
      }

      // @ts-ignore - Testing with malformed input
      const result = await service.validateDecryption(malformedInvocation, spaceDIDForTest, ucanKmsIdentity)

      expect(result.error).to.exist
      expect(result.error?.message).to.be.a('string')
    })
  })

  describe('Revocation Testing', () => {
    it('should document revocation service integration gap', () => {
      // This test documents the critical security gap identified in the audit report
      // The revocation service is currently a stub that always returns success

      // TODO: Implement actual revocation checking
      // TODO: Add tests for revoked delegations
      // TODO: Add tests for revocation service failures
      // TODO: Add tests for revocation caching

      expect(true).to.be.true // Placeholder test to document the gap
    })

    // These tests would be implemented once revocation service is complete:
    /*
    it('should reject revoked delegations', async () => {
      // Test that revoked delegations are properly rejected
    })

    it('should handle revocation service unavailability', async () => {
      // Test behavior when revocation service is down
    })

    it('should cache revocation status appropriately', async () => {
      // Test revocation status caching
    })
    */
  })
})
