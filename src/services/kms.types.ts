import { Result } from '@ucanto/client'
import { SpaceDID } from '@storacha/capabilities/types'
import { Env } from '../types/env.js'

export interface EncryptionSetupResult {
  /** The public key for the space in PEM format */
  publicKey: string
  /** The algorithm used to encrypt the symmetric key */
  algorithm: string
  /** The provider of the KMS key */
  provider: string
}

export interface EncryptionSetupRequest {
  /** The space DID to create/retrieve key for */
  space: SpaceDID
  /** Optional location override (falls back to env.GOOGLE_KMS_LOCATION) */
  location?: string
  /** Optional keyring override (falls back to env.GOOGLE_KMS_KEYRING_NAME) */
  keyring?: string
}

export interface DecryptionKeyRequest {
  /** Uint8Array encrypted symmetric key */
  encryptedSymmetricKey: Uint8Array
  /** The space DID that owns the key */
  space: SpaceDID
}

export interface KMSService {
  /**
   * Creates or retrieves an RSA key pair in KMS for the space and returns the public key and key reference
   */
  setupKeyForSpace(
    request: EncryptionSetupRequest,
    env: Env
  ): Promise<Result<EncryptionSetupResult, Error>>

  /**
   * Decrypts a symmetric key using the space's KMS private key
   */
  decryptSymmetricKey(
    request: DecryptionKeyRequest,
    env: Env
  ): Promise<Result<{ decryptedKey: string }, Error>>
}
