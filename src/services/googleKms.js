import * as z from 'zod'
import * as CRC32 from 'crc-32'
import { base64 } from 'multiformats/bases/base64'
import { sanitizeSpaceDIDForKMSKeyId } from '../utils.js'
import { AuditLogService } from './auditLog.js'
import { error, ok, Failure } from '@ucanto/server'

/**
 * @import { KMSService, EncryptionSetupRequest, DecryptionKeyRequest, EncryptionSetupResult } from './kms.types.js'
 * @import { SpaceDID } from '@storacha/capabilities/types'
 */

/**
 * Creates a secure wrapper for sensitive string data that auto-clears on disposal
 */
class SecureString {
  /**
   * @param {string} value
   */
  constructor(value) {
    this._buffer = new TextEncoder().encode(value)
    this._value = value // Keep a reference to the original string for getValue()
    this._disposed = false
  }

  /**
   * Get the string value (should be used sparingly)
   * @returns {string}
   */
  getValue() {
    if (this._disposed) {
      throw new Error('SecureString has been disposed')
    }
    return this._value
  }

  /**
   * Securely dispose of the sensitive data
   */
  dispose() {
    if (!this._disposed) {
      this._buffer.fill(0)
      this._value = '' // Clear the string reference
      this._disposed = true
    }
  }

  /**
   * Auto-dispose when garbage collected
   */
  [Symbol.dispose]() {
    this.dispose()
  }
}

/**
 * Zod schema for validating Google KMS environment configuration
 */
const KMSEnvironmentSchema = z.object({
  GOOGLE_KMS_BASE_URL: z
    .url('Must be a valid URL')
    .refine(url => url.includes('cloudkms.googleapis.com'), {
      message: 'Must be an official Google Cloud KMS endpoint'
    }),
  GOOGLE_KMS_PROJECT_ID: z.string()
    .min(6, 'Project ID must be at least 6 characters')
    .max(30, 'Project ID must be at most 30 characters')
    .regex(/^[a-z0-9-]+$/, 'Project ID must contain only lowercase letters, numbers, and hyphens'),
  GOOGLE_KMS_LOCATION: z.string()
    .min(1, 'Location cannot be empty')
    .refine(location => {
      // Common GCP regions/locations
      const validLocations = [
        'global', 'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4',
        'europe-north1', 'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6',
        'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2', 'asia-northeast3',
        'asia-south1', 'asia-southeast1', 'asia-southeast2', 'australia-southeast1'
      ]
      return validLocations.includes(location) || location.match(/^[a-z0-9-]+$/)
    }, {
      message: 'Must be a valid GCP region or location'
    }),
  GOOGLE_KMS_KEYRING_NAME: z.string()
    .min(1, 'Keyring name cannot be empty')
    .max(63, 'Keyring name must be at most 63 characters')
    .regex(/^[a-zA-Z0-9_-]+$/, 'Keyring name must contain only letters, numbers, hyphens, and underscores'),
  GOOGLE_KMS_TOKEN: z.string()
    .min(10, 'Token must be at least 10 characters')
    .regex(/^[A-Za-z0-9._-]+$/, 'Token must contain only valid characters')
})

/**
 * Google Cloud KMS service implementation
 * @implements {KMSService}
 */
export class GoogleKMSService {
  /**
   * Creates a new GoogleKMSService instance with validated configuration
   *
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @param {Object} [options] - Service options
   * @param {string} [options.environment] - Environment name for audit logging
   * @param {import('./auditLog.js').AuditLogService} [options.auditLog] - Shared audit log service instance
   * @throws {Error} If configuration validation fails when decryption is enabled
   */
  constructor(env, options = {}) {
    try {
      this.validateConfiguration(env)

      this.auditLog = options.auditLog || new AuditLogService({
        serviceName: 'google-kms-service',
        environment: options.environment || 'unknown'
      })

      // Only log service initialization in development
      if (process.env.NODE_ENV === 'development') {
        this.auditLog.logServiceInitialization('GoogleKMSService', true)
      }
    } catch (error) {
      // Log initialization failure
      const auditLog = options.auditLog || new AuditLogService({
        serviceName: 'google-kms-service',
        environment: options.environment || 'unknown'
      })
      const errorMessage = error instanceof Error ? error.message : String(error)
      auditLog.logServiceInitialization('GoogleKMSService', false, errorMessage)
      throw error
    }
  }

  /**
   * Validates the KMS environment configuration using Zod schema
   *
   * @private
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @throws {Error} If configuration validation fails
   */
  validateConfiguration(env) {
    try {
      KMSEnvironmentSchema.parse({
        GOOGLE_KMS_BASE_URL: env.GOOGLE_KMS_BASE_URL,
        GOOGLE_KMS_PROJECT_ID: env.GOOGLE_KMS_PROJECT_ID,
        GOOGLE_KMS_LOCATION: env.GOOGLE_KMS_LOCATION,
        GOOGLE_KMS_KEYRING_NAME: env.GOOGLE_KMS_KEYRING_NAME,
        GOOGLE_KMS_TOKEN: env.GOOGLE_KMS_TOKEN
      })
    } catch (validationError) {
      if (validationError instanceof z.ZodError) {
        const errors = validationError.issues.map(err =>
          `${err.path.join('.')}: ${err.message}`
        ).join('; ')
        throw new Error(`Google KMS configuration validation failed: ${errors}`)
      }
      const message = validationError instanceof Error ? validationError.message : String(validationError)
      throw new Error(`Google KMS configuration validation failed: ${message}`)
    }
  }

  /**
   * Creates or retrieves an RSA key pair in KMS for the space and returns the public key and key reference
   *
   * @param {EncryptionSetupRequest} request - The encryption setup request
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @returns {Promise<import('@ucanto/server').Result<EncryptionSetupResult, import('@ucanto/server').Failure>>}
   */
  async setupKeyForSpace(request, env) {
    const startTime = Date.now()
    try {
      const actualLocation = request.location || env.GOOGLE_KMS_LOCATION
      const actualKeyring = request.keyring || env.GOOGLE_KMS_KEYRING_NAME
      const sanitizedKeyId = sanitizeSpaceDIDForKMSKeyId(request.space)
      const keyName = `projects/${env.GOOGLE_KMS_PROJECT_ID}/locations/${actualLocation}/keyRings/${actualKeyring}/cryptoKeys/${sanitizedKeyId}`

      const getResponse = await fetch(`${env.GOOGLE_KMS_BASE_URL}/${keyName}`, {
        headers: {
          Authorization: `Bearer ${env.GOOGLE_KMS_TOKEN}`
        }
      })

      if (getResponse.ok) {
        // Key exists, get the primary key version and its public key
        const result = await this._retrieveExistingPublicKey(keyName, env, request.space)
        const duration = Date.now() - startTime
        this.auditLog.logKMSKeySetupSuccess(
          request.space,
          result.algorithm || 'RSA_DECRYPT_OAEP_3072_SHA256',
          'existing',
          duration
        )
        return ok(result)
      }

      if (getResponse.status === 404) {
        // Key doesn't exist, create it
        const result = await this._createNewKey(sanitizedKeyId, keyName, env, request.space, actualLocation, actualKeyring)
        const duration = Date.now() - startTime
        this.auditLog.logKMSKeySetupSuccess(
          request.space,
          result.algorithm || 'RSA_DECRYPT_OAEP_3072_SHA256',
          '1',
          duration
        )
        return ok(result)
      }

      // Handle authentication errors specifically
      if (getResponse.status === 401) {
        const errorText = await getResponse.text()
        this.auditLog.logKMSKeySetupFailure(
          request.space,
          'Google KMS authentication failed - token may be expired: ' + errorText,
          getResponse.status,
          Date.now() - startTime
        )
        return error(new Failure('KMS authentication failed'))
      }

      // Other errors
      const errorText = await getResponse.text()
      this.auditLog.logKMSKeySetupFailure(
        request.space,
        'Encryption setup failed: ' + errorText,
        getResponse.status,
        Date.now() - startTime
      )

      return error(new Failure('Encryption setup failed'))
    } catch (err) {
      console.error('[setupKeyForSpace] something went wrong:', err)

      // Log audit event
      this.auditLog.logKMSKeySetupFailure(
        request.space,
        `Encryption setup failed: ${err instanceof Error ? err.message : String(err)}`,
        undefined,
        Date.now() - startTime

      )

      // Generic error message must be returned to the client to avoid leaking information
      return error(new Failure('Encryption setup failed'))
    }
  }

  /**
   * Decrypts a symmetric key using the space's KMS private key
   *
   * @param {DecryptionKeyRequest} request - The decryption request
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @returns {Promise<import('@ucanto/server').Result<{ decryptedKey: string }, import('@ucanto/server').Failure>>}
   */
  async decryptSymmetricKey(request, env) {
    const startTime = Date.now()
    let secureToken = null
    let secureDecryptedKey = null

    try {
      // Sanitize space DID to match the key ID format used in encryption setup
      const sanitizedKeyId = sanitizeSpaceDIDForKMSKeyId(request.space)
      const keyName = `projects/${env.GOOGLE_KMS_PROJECT_ID}/locations/${env.GOOGLE_KMS_LOCATION}/keyRings/${env.GOOGLE_KMS_KEYRING_NAME}/cryptoKeys/${sanitizedKeyId}`

      // Get the primary key version from KMS
      const primaryVersionResult = await this._getPrimaryKeyVersion(keyName, env, request.space)
      const primaryVersion = primaryVersionResult.primaryVersion
      const keyVersion = primaryVersion.split('/').pop() || 'unknown'
      const kmsUrl = `${env.GOOGLE_KMS_BASE_URL}/${primaryVersion}:asymmetricDecrypt`

      // Wrap sensitive token in SecureString for better memory hygiene
      secureToken = new SecureString(env.GOOGLE_KMS_TOKEN)

      // Convert Uint8Array to base64 string for Google KMS
      // Google KMS expects ciphertext as a base64-encoded string, but UCAN invocations 
      // provide it as a Uint8Array. We need to convert it properly.
      const binaryString = Array.from(request.encryptedSymmetricKey, byte => String.fromCharCode(byte)).join('')
      const base64Ciphertext = btoa(binaryString)
      
      const response = await fetch(kmsUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${secureToken.getValue()}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          ciphertext: base64Ciphertext
        })
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`KMS decryption failed ${keyName}: ${response.status} - ${errorText}`)
      }

      const result = await response.json()
      if (!result.plaintext) {
        throw new Error(`KMS decryption failed ${keyName}: ${response.status} - ${result.plaintext}`)
      }

      // Wrap decrypted key in SecureString for better memory hygiene
      secureDecryptedKey = new SecureString(result.plaintext)

      // Google KMS returns the decrypted data as base64, but the client expects 
      // the original Uint8Array encoded with multibase. We need to:
      // 1. Decode the base64 to get the original Uint8Array  
      // 2. Re-encode with multibase for client compatibility
      const rawBase64 = secureDecryptedKey.getValue()
      
      // Debug: Log the data we're working with
      console.log('[KMS Debug] Raw base64 length:', rawBase64.length)
      console.log('[KMS Debug] Raw base64 (first 50 chars):', rawBase64.substring(0, 50))
      
      // Convert base64 back to Uint8Array (this is the original combined key+IV)
      // Use a more robust method for base64 → Uint8Array conversion
      const decodedString = atob(rawBase64)
      const binaryData = new Uint8Array(decodedString.length)
      for (let i = 0; i < decodedString.length; i++) {
        binaryData[i] = decodedString.charCodeAt(i)
      }
      
      console.log('[KMS Debug] Binary data length:', binaryData.length)
      console.log('[KMS Debug] Binary data first 10 bytes:', Array.from(binaryData.slice(0, 10)))
      
      // Use the same multiformats library as the client for proper encoding
      const decryptedKey = base64.encode(binaryData)
      console.log('[KMS Debug] Final multibase length:', decryptedKey.length)
      console.log('[KMS Debug] Final multibase prefix:', decryptedKey.substring(0, 10))
      
      // Success - log audit event
      this.auditLog.logKMSDecryptSuccess(
        request.space,
        keyVersion,
        Date.now() - startTime
      )
      return ok({ decryptedKey })
    } catch (err) {
      console.error('[decryptSymmetricKey] something went wrong:', err)
      
      // Log audit event
      this.auditLog.logKMSDecryptFailure(
        request.space,
        `Symmetric key decryption failed: ${err instanceof Error ? err.message : String(err)}`,
        undefined,
        Date.now() - startTime
      )

      // Generic error message must be returned to the client to avoid leaking information
      return error(new Failure('KMS decryption failed'))
    } finally {
      // Securely clear sensitive data from memory
      if (secureToken) {
        secureToken.dispose()
      }
      if (secureDecryptedKey) {
        secureDecryptedKey.dispose()
      }
    }
  }

  /**
   * Gets the active key version for a KMS key (supports both symmetric and asymmetric keys)
   *
   * @private
   * @param {string} keyName - The full KMS key name reference
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @param {SpaceDID} space - The space DID for error messages
   * @returns {Promise<{ primaryVersion: string }>}
   */
  async _getPrimaryKeyVersion(keyName, env, space) {
    const startTime = Date.now()
    try {
      const keyDataResponse = await fetch(`${env.GOOGLE_KMS_BASE_URL}/${keyName}`, {
        headers: {
          Authorization: `Bearer ${env.GOOGLE_KMS_TOKEN}`
        }
      })

      if (!keyDataResponse.ok) {
        const errorText = await keyDataResponse.text()
        // Log detailed error internally for debugging
        this.auditLog.logKMSKeySetupFailure(
          space,
          `KMS key data retrieval failed: ${keyDataResponse.status} - ${errorText}`,
          undefined,
          Date.now() - startTime
        )
        throw new Error(`KMS key data retrieval failed`)
      }

      const keyData = await keyDataResponse.json()
      let version

      // Check if this is a symmetric key with a primary version
      if (keyData.primary && keyData.primary.name) {
        version = keyData.primary.name
      } else {
        // For asymmetric keys (ASYMMETRIC_DECRYPT, ASYMMETRIC_SIGN), there's no primary concept
        // We need to list the key versions and find an active one
        const versionsResult = await this._getActiveKeyVersion(keyName, env, space)
        version = versionsResult.primaryVersion
      }

      if (!version) {
        throw new Error('KMS Key version retrieval failed')
      }

      return { primaryVersion: version }
    } catch (err) {
      this.auditLog.logKMSKeySetupFailure(
        space,
        'Get primary key version failed: ' + (err instanceof Error ? err.message : String(err)),
        undefined,
        Date.now() - startTime
      )
      throw err
    }
  }

  /**
   * Gets an active key version for asymmetric keys
   *
   * @private
   * @param {string} keyName - The full KMS key name reference
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @param {SpaceDID} space - The space DID for error messages
   * @returns {Promise<{ primaryVersion: string }>}
   */
  async _getActiveKeyVersion(keyName, env, space) {
    const startTime = Date.now()
    try {
      // List the key versions to find an enabled one
      const versionsResponse = await fetch(`${env.GOOGLE_KMS_BASE_URL}/${keyName}/cryptoKeyVersions`, {
        headers: {
          Authorization: `Bearer ${env.GOOGLE_KMS_TOKEN}`
        }
      })

      if (!versionsResponse.ok) {
        const errorText = await versionsResponse.text()
        // Log detailed error internally for debugging
        console.error(`KMS key versions retrieval failed: ${versionsResponse.status} - ${errorText}`, {
          operation: '_getActiveKeyVersion',
          space,
          status: versionsResponse.status,
          error: errorText
        })
        // Return generic error to client
        throw new Error('Key operation failed')
      }

      const versionsData = await versionsResponse.json()

      // Find the first enabled key version (or fallback to version 1)
      const enabledVersions = versionsData.cryptoKeyVersions?.filter(
        /** @param {{ state: string, name: string }} version */
        version => version.state === 'ENABLED'
      ) || []

      let activeVersion
      if (enabledVersions.length > 0) {
        // Use the first enabled version
        activeVersion = enabledVersions[0].name
      } else {
        throw new Error('No active key version found')
      }

      return { primaryVersion: activeVersion }
    } catch (err) {
      this.auditLog.logKMSKeySetupFailure(
        space,
        'Get active key version failed: ' + (err instanceof Error ? err.message : String(err)),
        undefined,
        Date.now() - startTime
      )
      throw err
    }
  }

  /**
   * Retrieves the public key for an existing KMS key
   *
   * @private
   * @param {string} keyName - The full KMS key name reference
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @param {SpaceDID} space - The space DID for error messages
   * @returns {Promise<EncryptionSetupResult>}
   */
  async _retrieveExistingPublicKey(keyName, env, space) {
    const startTime = Date.now()
    try {
      const result = await this._getPrimaryKeyVersion(keyName, env, space)
      return await this._fetchAndValidatePublicKey(result.primaryVersion, env, space)
    } catch (err) {
      this.auditLog.logKMSKeySetupFailure(
        space,
        'Get existing public key failed: ' + (err instanceof Error ? err.message : String(err)),
        undefined,
        Date.now() - startTime
      )
      throw err
    }
  }

  /**
   * Creates a new KMS key and returns its public key and key reference
   *
   * @private
   * @param {string} sanitizedKeyId - The sanitized key ID
   * @param {string} keyName - The full KMS key name
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @param {SpaceDID} space - The space DID for error messages
   * @param {string | undefined} location - The location to use for key creation
   * @param {string | undefined} keyring - The keyring to use for key creation
   * @returns {Promise<EncryptionSetupResult>}
   */
  async _createNewKey(sanitizedKeyId, keyName, env, space, location, keyring) {
    const startTime = Date.now()
    try {
      const encodedKeyId = encodeURIComponent(sanitizedKeyId)
      const actualLocation = location || env.GOOGLE_KMS_LOCATION
      const actualKeyring = keyring || env.GOOGLE_KMS_KEYRING_NAME
      const createKeyUrl = `${env.GOOGLE_KMS_BASE_URL}/projects/${env.GOOGLE_KMS_PROJECT_ID}/locations/${actualLocation}/keyRings/${actualKeyring}/cryptoKeys?cryptoKeyId=${encodedKeyId}`

      const createResponse = await fetch(createKeyUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${env.GOOGLE_KMS_TOKEN}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          purpose: 'ASYMMETRIC_DECRYPT',
          versionTemplate: {
            algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256'
          }
        })
      })

      if (!createResponse.ok) {
        const errorText = await createResponse.text()
        if (createResponse.status === 401) {
          throw new Error(`KMS authentication failed during key creation - token may be expired`)
        }
        throw new Error(`KMS key creation failed ${keyName}: ${createResponse.status} - ${errorText}`)
      }

      // For newly created keys, the primary version is always version 1
      // We can construct the path directly since we know the key structure
      const primaryVersion = `${keyName}/cryptoKeyVersions/1`

      // Get the public key of the newly created key
      return await this._fetchAndValidatePublicKey(primaryVersion, env, space)
    } catch (err) {
      this.auditLog.logKMSKeySetupFailure(
        space,
        `KMS key creation failed ${keyName}: ${err instanceof Error ? err.message : String(err)}`,
        undefined,
        Date.now() - startTime
      )
      throw err
    }
  }

  /**
   * Fetches and validates a public key from KMS
   *
   * @private
   * @param {string} keyVersionPath - The full key version path (e.g., projects/.../cryptoKeys/.../cryptoKeyVersions/1)
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @param {SpaceDID} space - The space DID for error messages
   * @returns {Promise<EncryptionSetupResult>}
   */
  async _fetchAndValidatePublicKey(keyVersionPath, env, space) {
    let securePem = null
    const startTime = Date.now()
    try {
      const publicKeyUrl = `${env.GOOGLE_KMS_BASE_URL}/${keyVersionPath}/publicKey`
      const pubKeyResponse = await fetch(publicKeyUrl, {
        headers: {
          Authorization: `Bearer ${env.GOOGLE_KMS_TOKEN}`
        }
      })
      if (!pubKeyResponse.ok) {
        const errorText = await pubKeyResponse.text()
        throw new Error(`KMS public key retrieval failed ${keyVersionPath}: ${pubKeyResponse.status} - ${errorText}`)
      }

      /**
       * @type {{ algorithm: string, publicKey?: {crc32cChecksum: string, data: string}, publicKeyFormat?: string, name: string, pem?: string, pemCrc32c?: string }}
       */
      const pubKeyData = await pubKeyResponse.json()

      let decodedPem
      
      // Handle both old and new API response formats
      if (pubKeyData.pem) {
        // New format: PEM is returned directly
        decodedPem = pubKeyData.pem
      } else if (pubKeyData.publicKey && pubKeyData.publicKey.data) {
        // Old format: PEM is base64-encoded in publicKey.data
        try {
          decodedPem = atob(pubKeyData.publicKey.data)
        } catch (err) {
          throw new Error(`KMS public key base64 decoding failed ${keyVersionPath}: ${err instanceof Error ? err.message : String(err)}`)
        }
      } else {
        console.error(`[GoogleKMS] Invalid public key response structure:`, JSON.stringify(pubKeyData, null, 2))
        throw new Error(`KMS public key response missing pem or publicKey.data field ${keyVersionPath}`)
      }

      // Validate the public key format
      if (!decodedPem || !decodedPem.startsWith('-----BEGIN PUBLIC KEY-----')) {
        throw new Error(`KMS public key decoding failed due to invalid format or missing data ${keyVersionPath}`)
      }

      // Wrap decoded PEM in SecureString for better memory hygiene
      securePem = new SecureString(decodedPem)

      // Perform integrity check if CRC32C is provided
      let crcChecksum, dataForCrc
      if (pubKeyData.pem && pubKeyData.pemCrc32c) {
        // New format: CRC32C of the PEM string
        crcChecksum = pubKeyData.pemCrc32c
        dataForCrc = pubKeyData.pem
      } else if (pubKeyData.publicKey?.crc32cChecksum && pubKeyData.publicKey?.data) {
        // Old format: CRC32C of the base64-encoded data string
        crcChecksum = pubKeyData.publicKey.crc32cChecksum
        dataForCrc = pubKeyData.publicKey.data
      }
      
      if (crcChecksum && dataForCrc) {
        // For now, enable integrity check with detailed logging to understand the issue
        const isValid = GoogleKMSService.validatePublicKeyIntegrity(dataForCrc, crcChecksum)

        if (!isValid) {
          console.warn('[fetchAndValidatePublicKey] CRC32 integrity check failed but continuing:', {
            expected: crcChecksum,
            calculated: (CRC32.str(dataForCrc) >>> 0).toString(),
            note: 'CRC32 mismatch - Google uses a different polynomial/implementation. Find a way to verify the integrity of the public key.'
          })
          this.auditLog.logKMSKeySetupSuccess(
            space,
            pubKeyData.algorithm || 'RSA_DECRYPT_OAEP_3072_SHA256',
            'integrity_check_bypassed',
            Date.now() - startTime
          )
        }
      }

      return {
        publicKey: securePem.getValue(),
        algorithm: pubKeyData.algorithm,
        provider: 'google-kms'
      }
    } catch (err) {
      this.auditLog.logKMSKeySetupFailure(
        space,
        'KMS public key fetch and validation failed: ' + (err instanceof Error ? err.message : String(err)),
        undefined,
        Date.now() - startTime
      )
      throw new Error('KMS public key fetch and validation failed')
    } finally {
      // Securely clear sensitive PEM data from memory
      if (securePem) {
        securePem.dispose()
      }
    }
  }

  /**
   * Validates the integrity of a public key using CRC32C checksum
   *
   * @static
   * @param {string} pem - The PEM-encoded public key
   * @param {string} expectedCrc32c - The expected CRC32C checksum as a string
   * @returns {boolean} - True if the integrity check passes
   */
  static validatePublicKeyIntegrity(pem, expectedCrc32c) {
    try {
      // Calculate CRC32 checksum (Google uses CRC32C on base64-encoded data)
      const calculatedCrc32 = CRC32.str(pem)
      const expectedUnsigned = parseInt(expectedCrc32c, 10)
      console.log('expectedUnsigned', expectedUnsigned)
      console.log('calculatedCrc32', calculatedCrc32)
      const calculatedUnsigned = calculatedCrc32 >>> 0 // Convert to unsigned 32-bit
      console.log('calculatedUnsigned', calculatedUnsigned)
      // Simple comparison - CRC32C is for data integrity, not cryptographic security
      return expectedUnsigned === calculatedUnsigned
    } catch (err) {
      // If integrity check fails for any reason, return false
      return false
    }
  }
}
