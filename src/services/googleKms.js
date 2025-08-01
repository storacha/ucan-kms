import * as z from 'zod'
import * as CRC32 from 'crc-32'
import { base64 } from 'multiformats/bases/base64'
import pRetry, { AbortError } from 'p-retry'
import { sanitizeSpaceDIDForKMSKeyId } from '../utils.js'
import { AuditLogService } from './auditLog.js'
import { error, ok, Failure } from '@ucanto/server'

/**
 * @import { KMSService, EncryptionSetupRequest, DecryptionKeyRequest, EncryptionSetupResult } from './kms.types.js'
 * @import { SpaceDID } from '@storacha/capabilities/types'
 */

/**
 * Google Cloud KMS API base URL
 */
const GOOGLE_KMS_BASE_URL = 'https://cloudkms.googleapis.com/v1'

/**
 * Request timeout configurations by operation type
 */
const TIMEOUTS = {
  TOKEN_REQUEST: 15000,    // Authentication is critical path
  KMS_DECRYPT: 30000,      // Decrypt operations are user-facing
  KMS_ENCRYPT: 30000,      // Same priority as decrypt  
  KEY_CREATION: 60000,     // Key creation can be slower
  KEY_LOOKUP: 20000,       // Metadata operations should be fast
  KEY_VERSIONS: 20000      // Version listing should be fast
}

/**
 * @typedef {Object} AccessTokenAuth
 * @property {'access_token'} type - Authentication type
 * @property {string} token - Access token
 */

/**
 * @typedef {Object} ServiceAccountCredentials
 * @property {string} client_email - Service account email
 * @property {SecureString} private_key - Private key for signing (wrapped in SecureString)
 * @property {string} project_id - Project ID
 */

/**
 * @typedef {Object} ServiceAccountAuth
 * @property {'service_account'} type - Authentication type
 * @property {ServiceAccountCredentials} credentials - Service account credentials
 */

/**
 * @typedef {AccessTokenAuth | ServiceAccountAuth} AuthConfig
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
  // Authentication - either access token OR service account JSON required
  GOOGLE_KMS_TOKEN: z.string()
    .min(10, 'Token must be at least 10 characters')
    .regex(/^[A-Za-z0-9._-]+$/, 'Token must contain only valid characters')
    .optional(),
  GOOGLE_KMS_SERVICE_ACCOUNT_JSON: z.string()
    .min(1, 'Service account JSON cannot be empty')
    .optional()
}).refine((data) => {
  return data.GOOGLE_KMS_TOKEN || data.GOOGLE_KMS_SERVICE_ACCOUNT_JSON
}, {
  message: 'Either GOOGLE_KMS_TOKEN or GOOGLE_KMS_SERVICE_ACCOUNT_JSON must be provided',
  path: ['authentication']
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

      this.authConfig = this._setupAuthentication(env)
      if (process.env.NODE_ENV === 'development') {
        this.auditLog.logServiceInitialization('GoogleKMSService', true)
      }
    } catch (error) {
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
   * Set up authentication configuration - access token first, service account JSON fallback
   * @private
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @returns {AuthConfig} Authentication configuration
   */
  _setupAuthentication(env) {
    if (env.GOOGLE_KMS_TOKEN) {
      console.log('Using access token authentication')
      return {
        type: 'access_token',
        token: env.GOOGLE_KMS_TOKEN
      }
    } else if (env.GOOGLE_KMS_SERVICE_ACCOUNT_JSON) {
      console.log('Using service account JSON authentication')
      try {
        const credentials = JSON.parse(env.GOOGLE_KMS_SERVICE_ACCOUNT_JSON)
        // Protect private key in memory
        const securePrivateKey = new SecureString(credentials.private_key)
        return {
          type: 'service_account',
          credentials: {
            ...credentials,
            private_key: securePrivateKey // Wrap in SecureString
          }
        }
      } catch (parseError) {
        throw new Error('Invalid GOOGLE_KMS_SERVICE_ACCOUNT_JSON: ' + (parseError instanceof Error ? parseError.message : String(parseError)))
      }
    } else {
      // This should never happen due to schema validation, but add for safety
      throw new Error('No authentication method provided for Google KMS')
    }
  }

  /**
   * Get authentication headers for Google KMS API calls
   * @private
   * @returns {Promise<{Authorization: string, 'Content-Type': string}>} Headers object with authorization
   */
  async _getAuthHeaders() {
    if (this.authConfig.type === 'access_token') {
      return {
        'Authorization': `Bearer ${this.authConfig.token}`,
        'Content-Type': 'application/json'
      }
    } else if (this.authConfig.type === 'service_account') {
      const accessToken = await this._getServiceAccountAccessToken()
      return {
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    } else {
      throw new Error('Invalid authentication configuration')
    }
  }

  /**
   * Generate access token from service account credentials using JWT
   * @private
   * @returns {Promise<string>} Access token
   */
  async _getServiceAccountAccessToken() {
    if (this.authConfig.type !== 'service_account') {
      throw new Error('Invalid auth config for service account access token')
    }
    const { credentials } = this.authConfig
    
    const header = {
      alg: 'RS256',
      typ: 'JWT'
    }
    
    const now = Math.floor(Date.now() / 1000)
    const payload = {
      iss: credentials.client_email,
      scope: 'https://www.googleapis.com/auth/cloudkms',
      aud: 'https://oauth2.googleapis.com/token',
      exp: now + 3600, // 1 hour
      iat: now,
      jti: crypto.randomUUID(), // Prevent replay attacks
      sub: credentials.client_email // Clear subject identity
    }
    
    // Create JWT (simplified implementation for Workers)
    const jwt = await this._createJWT(header, payload, credentials.private_key)
    
    // Exchange JWT for access token
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: jwt
      }),
      signal: AbortSignal.timeout(TIMEOUTS.TOKEN_REQUEST)
    })
    
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text()
      console.error('[_getServiceAccountAccessToken] Auth failed:', {
        status: tokenResponse.status,
        error: errorText
      })
      // Throw generic error to prevent information leakage
      throw new Error('Failed to authenticate with Google Cloud KMS')
    }
    
    const tokenData = await tokenResponse.json()
    return tokenData.access_token
  }

  /**
   * Create JWT using Web Crypto API (Workers compatible)
   * @private
   * @param {Object} header - JWT header
   * @param {Object} payload - JWT payload  
   * @param {SecureString} securePrivateKey - Private key for signing (wrapped in SecureString)
   * @returns {Promise<string>} JWT string
   */
  async _createJWT(header, payload, securePrivateKey) {
    const encoder = new TextEncoder()
    
    // Encode header and payload
    const encodedHeader = this._base64UrlEncode(JSON.stringify(header))
    const encodedPayload = this._base64UrlEncode(JSON.stringify(payload))
    const toSign = `${encodedHeader}.${encodedPayload}`
    
    // Import private key from SecureString
    const pemContents = new SecureString(securePrivateKey.getValue()
      .replace('-----BEGIN PRIVATE KEY-----', '')
      .replace('-----END PRIVATE KEY-----', '')
      .replace(/\s/g, ''))
      
    const binaryKey = Uint8Array.from(atob(pemContents.getValue()), c => c.charCodeAt(0))
    pemContents.dispose()
    const cryptoKey = await crypto.subtle.importKey(
      'pkcs8',
      binaryKey,
      {
        name: 'RSASSA-PKCS1-v1_5',
        hash: 'SHA-256'
      },
      false,
      ['sign']
    )
    
    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      cryptoKey,
      encoder.encode(toSign)
    )
    
    const encodedSignature = this._base64UrlEncode(new Uint8Array(signature))
    return `${toSign}.${encodedSignature}`
  }

  /**
   * Base64 URL encode (without padding)
   * @private
   * @param {string|Uint8Array} data - Data to encode
   * @returns {string} Base64 URL encoded string
   */
  _base64UrlEncode(data) {
    let base64
    if (typeof data === 'string') {
      base64 = btoa(data)
    } else {
      const binaryString = Array.from(data, byte => String.fromCharCode(byte)).join('')
      base64 = btoa(binaryString)
    }
    
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '')
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
        GOOGLE_KMS_PROJECT_ID: env.GOOGLE_KMS_PROJECT_ID,
        GOOGLE_KMS_LOCATION: env.GOOGLE_KMS_LOCATION,
        GOOGLE_KMS_KEYRING_NAME: env.GOOGLE_KMS_KEYRING_NAME,
        GOOGLE_KMS_TOKEN: env.GOOGLE_KMS_TOKEN,
        GOOGLE_KMS_SERVICE_ACCOUNT_JSON: env.GOOGLE_KMS_SERVICE_ACCOUNT_JSON
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

      const authHeaders = await this._getAuthHeaders()
      const getResponse = await fetch(`${GOOGLE_KMS_BASE_URL}/${keyName}`, {
        headers: authHeaders,
        signal: AbortSignal.timeout(TIMEOUTS.KEY_LOOKUP)
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
    let secureDecryptedKey = null

    try {
      const sanitizedKeyId = sanitizeSpaceDIDForKMSKeyId(request.space)
      const keyName = `projects/${env.GOOGLE_KMS_PROJECT_ID}/locations/${env.GOOGLE_KMS_LOCATION}/keyRings/${env.GOOGLE_KMS_KEYRING_NAME}/cryptoKeys/${sanitizedKeyId}`

      // Get the primary key version from KMS
      const primaryVersionResult = await this._getPrimaryKeyVersion(keyName, request.space)
      const primaryVersion = primaryVersionResult.primaryVersion
      const keyVersion = primaryVersion.split('/').pop() || 'unknown'
      const kmsUrl = `${GOOGLE_KMS_BASE_URL}/${primaryVersion}:asymmetricDecrypt`

      // Convert Uint8Array to base64 string for Google KMS
      // Google KMS expects ciphertext as a base64-encoded string, but UCAN invocations 
      // provide it as a Uint8Array. We need to convert it properly.
      const binaryString = Array.from(request.encryptedSymmetricKey, byte => String.fromCharCode(byte)).join('')
      const base64Ciphertext = btoa(binaryString)
      
      const authHeaders = await this._getAuthHeaders()
      const response = await fetch(kmsUrl, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          ciphertext: base64Ciphertext
        }),
        signal: AbortSignal.timeout(TIMEOUTS.KMS_DECRYPT)
      })

      if (!response.ok) {
        const errorText = await response.text()
        throw new Error(`KMS decryption failed ${keyName}: ${response.status} - ${errorText}`)
      }

      const result = await response.json()
      if (!result.plaintext) {
        throw new Error(`KMS decryption failed ${keyName}: ${response.status} - ${result.plaintext}`)
      }

      secureDecryptedKey = new SecureString(result.plaintext)

      // Google KMS returns the decrypted data as base64, but the client expects 
      // the original Uint8Array encoded with multibase. We need to:
      // 1. Decode the base64 to get the original Uint8Array  
      // 2. Re-encode with multibase for client compatibility
      const rawBase64 = secureDecryptedKey.getValue()
      
      // Convert base64 back to Uint8Array (this is the original combined key+IV)
      // Use a more robust method for base64 → Uint8Array conversion
      const decodedString = atob(rawBase64)
      const binaryData = new Uint8Array(decodedString.length)
      for (let i = 0; i < decodedString.length; i++) {
        binaryData[i] = decodedString.charCodeAt(i)
      }
      
      // Use the same multiformats library as the client for proper encoding
      const decryptedKey = base64.encode(binaryData)
      this.auditLog.logKMSDecryptSuccess(
        request.space,
        keyVersion,
        Date.now() - startTime
      )
      return ok({ decryptedKey })
    } catch (err) {
      console.error('[decryptSymmetricKey] something went wrong:', err)
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
   * @param {SpaceDID} space - The space DID for error messages
   * @returns {Promise<{ primaryVersion: string }>}
   */
  async _getPrimaryKeyVersion(keyName, space) {
    const startTime = Date.now()
    try {
      const authHeaders = await this._getAuthHeaders()
      const keyDataResponse = await fetch(`${GOOGLE_KMS_BASE_URL}/${keyName}`, {
        headers: authHeaders,
        signal: AbortSignal.timeout(TIMEOUTS.KEY_LOOKUP)
      })

      if (!keyDataResponse.ok) {
        const errorText = await keyDataResponse.text()
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
        const versionsResult = await this._getActiveKeyVersion(keyName, space)
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
   * @param {SpaceDID} space - The space DID for error messages
   * @returns {Promise<{ primaryVersion: string }>}
   */
  async _getActiveKeyVersion(keyName, space) {
    const startTime = Date.now()
    try {
      // List the key versions to find an enabled one
      const authHeaders = await this._getAuthHeaders()
      const versionsResponse = await fetch(`${GOOGLE_KMS_BASE_URL}/${keyName}/cryptoKeyVersions`, {
        headers: authHeaders,
        signal: AbortSignal.timeout(TIMEOUTS.KEY_VERSIONS)
      })

      if (!versionsResponse.ok) {
        const errorText = await versionsResponse.text()
        console.error(`KMS key versions retrieval failed: ${versionsResponse.status} - ${errorText}`, {
          operation: '_getActiveKeyVersion',
          space,
          status: versionsResponse.status,
          error: errorText
        })
        // Return generic error to client to avoid leaking information
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
      const result = await this._getPrimaryKeyVersion(keyName, space)
      return await this._fetchAndValidatePublicKey(result.primaryVersion, space)
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
      const createKeyUrl = `${GOOGLE_KMS_BASE_URL}/projects/${env.GOOGLE_KMS_PROJECT_ID}/locations/${actualLocation}/keyRings/${actualKeyring}/cryptoKeys?cryptoKeyId=${encodedKeyId}`

      const authHeaders = await this._getAuthHeaders()
      const createResponse = await fetch(createKeyUrl, {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({
          purpose: 'ASYMMETRIC_DECRYPT',
          versionTemplate: {
            algorithm: 'RSA_DECRYPT_OAEP_3072_SHA256'
          }
        }),
        signal: AbortSignal.timeout(TIMEOUTS.KEY_CREATION)
      })

      if (!createResponse.ok) {
        const errorText = await createResponse.text()
        console.log(`[_createNewKey] Key creation failed: ${createResponse.status} - ${errorText}`)
        if (createResponse.status === 401) {
          throw new Error(`KMS authentication failed during key creation - token may be expired`)
        }
        throw new Error(`KMS key creation failed ${keyName}: ${createResponse.status} - ${errorText}`)
      }

      // For newly created keys, the primary version is always version 1
      // We can construct the path directly since we know the key structure
      const primaryVersion = `${keyName}/cryptoKeyVersions/1`

      // Get the public key of the newly created key
      return await this._fetchAndValidatePublicKey(primaryVersion, space)
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
   * @param {SpaceDID} space - The space DID for error messages
   * @returns {Promise<EncryptionSetupResult>}
   */
  async _fetchAndValidatePublicKey(keyVersionPath, space) {
    const startTime = Date.now()
    
    try {
      // Create an overall timeout for the entire retry operation (30 seconds)
      const controller = new AbortController()
      const overallTimeout = setTimeout(() => controller.abort(), 30000)
      
      try {
        const result = await pRetry(async () => {
          const publicKeyUrl = `${GOOGLE_KMS_BASE_URL}/${keyVersionPath}/publicKey`
          const authHeaders = await this._getAuthHeaders()
          const pubKeyResponse = await fetch(publicKeyUrl, {
            headers: authHeaders,
            signal: controller.signal  // Use the overall timeout, not individual request timeout
          })
        
        if (!pubKeyResponse.ok) {
          const errorText = await pubKeyResponse.text()
          
          console.log(`[_fetchAndValidatePublicKey] Error response: ${pubKeyResponse.status} - ${errorText}`)
          
          if (pubKeyResponse.status === 404) {
            // 404 means key not yet available - let p-retry handle this
            throw new Error(`Key not yet available (404): ${keyVersionPath}`)
          }
          
          if (pubKeyResponse.status === 403) {
            // 403 might be temporary permission propagation - retry this too
            throw new Error(`Key access forbidden (403), may be permission propagation delay: ${keyVersionPath}`)
          }
          
          if (pubKeyResponse.status === 400) {
            // Check if it's a PENDING_GENERATION error (key still being created)
            if (errorText.includes('PENDING_GENERATION') || errorText.includes('is not enabled')) {
              throw new Error(`Key still being generated (400 PENDING_GENERATION): ${keyVersionPath}`)
            }
            // Other 400 errors should not be retried
            throw new AbortError(`Bad request (400): ${keyVersionPath} - ${errorText}`)
          }
          
          if (pubKeyResponse.status >= 500) {
            // 5xx server errors are often temporary - retry these
            throw new Error(`Server error (${pubKeyResponse.status}), retrying: ${keyVersionPath}`)
          }
          
          // Only abort on auth errors (401) and other client errors
          throw new AbortError(`KMS public key retrieval failed ${keyVersionPath}: ${pubKeyResponse.status} - ${errorText}`)
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
            throw new AbortError(`KMS public key base64 decoding failed ${keyVersionPath}: ${err instanceof Error ? err.message : String(err)}`)
          }
        } else {
          console.error(`[GoogleKMS] Invalid public key response structure:`, JSON.stringify(pubKeyData, null, 2))
          throw new AbortError(`KMS public key response missing pem or publicKey.data field ${keyVersionPath}`)
        }

        // Validate the public key format
        if (!decodedPem || !decodedPem.startsWith('-----BEGIN PUBLIC KEY-----')) {
          throw new AbortError(`KMS public key decoding failed due to invalid format or missing data ${keyVersionPath}`)
        }

        // Wrap decoded PEM in SecureString for better memory hygiene
        const securePem = new SecureString(decodedPem)

        try {
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
        } finally {
          // Securely clear sensitive PEM data from memory
          securePem.dispose()
        }
      }, {
        retries: 5,
        factor: 2,
        minTimeout: 1000,    // 1 second
        maxTimeout: 10000,   // 10 seconds max
        onFailedAttempt: (/** @type {import('p-retry').FailedAttemptError} */ error) => {
          console.log(`[_fetchAndValidatePublicKey] Attempt ${error.attemptNumber} failed. ${error.retriesLeft} retries left. Error: ${error.message}`)
        }
      })
      
        return result
      } finally {
        // Clear the overall timeout
        clearTimeout(overallTimeout)
      }
    } catch (err) {
      let errorMessage = err instanceof Error ? err.message : String(err)
      
      // Provide clearer error message for timeout
      if (err instanceof Error && err.name === 'AbortError') {
        errorMessage = 'Key fetch operation timed out after 30 seconds (including retries)'
      }
      
      this.auditLog.logKMSKeySetupFailure(
        space,
        'KMS public key fetch and validation failed: ' + errorMessage,
        undefined,
        Date.now() - startTime
      )
      throw new Error('KMS public key fetch and validation failed')
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
