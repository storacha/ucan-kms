import { Result } from "@ucanto/server";
import { AccountDID, SpaceDID } from "@storacha/capabilities/types";
import { Env } from "../types/env.js";
import { Delegation } from "@ucanto/interface";

export interface EncryptionSetupResult {
  /** The public key for the space in PEM format */
  publicKey: string;
  /** The algorithm used to encrypt the symmetric key */
  algorithm: string;
  /** The provider of the KMS key */
  provider: string;
}

export interface EncryptionSetupRequest {
  /** The space DID to create/retrieve key for */
  space: SpaceDID;
  /** Optional location override (falls back to env.GOOGLE_KMS_LOCATION) */
  location?: string;
  /** Optional keyring override (falls back to env.GOOGLE_KMS_KEYRING_NAME) */
  keyring?: string;
}

export interface DecryptionKeyRequest {
  /** Uint8Array encrypted symmetric key */
  encryptedSymmetricKey: Uint8Array;
  /** The space DID that owns the key */
  space: SpaceDID;
}

export interface KMSService {
  /**
   * Creates or retrieves an RSA key pair in KMS for the space and returns the public key and key reference
   */
  setupKeyForSpace(
    request: EncryptionSetupRequest,
    env: Env,
  ): Promise<Result<EncryptionSetupResult, import("@ucanto/server").Failure>>;

  /**
   * Decrypts a symmetric key using the space's KMS private key
   * @returns The decrypted key encoded using multiformats/bases/base64
   */
  decryptSymmetricKey(
    request: DecryptionKeyRequest,
    env: Env,
  ): Promise<Result<{ decryptedKey: string }, import("@ucanto/server").Failure>>;
}
