/// <reference types="@cloudflare/workers-types" />

import { KVNamespace } from '@cloudflare/workers-types'

export interface Env {
  /**
   * Environment name: development, staging, production, etc
   */
  ENVIRONMENT?: string;

  /**
   * UCAN KMS signer key
   */
  UCAN_KMS_PRINCIPAL_KEY: string

  /**
   * UCAN KMS service DID
   */
  UCAN_KMS_SERVICE_DID: string


  /**
   * Feature flag for enabling decryption of symmetric keys using KMS asymmetric Space key.
   */
  FF_DECRYPTION_ENABLED: string

  // Google KMS
  /**
   * Google KMS base URL
   */
  GOOGLE_KMS_BASE_URL: string

  /**
   * Google KMS project ID
   */
  GOOGLE_KMS_PROJECT_ID: string

  /**
   * Google KMS location
   */
  GOOGLE_KMS_LOCATION: string

  /**
   * Google KMS keyring name
   */
  GOOGLE_KMS_KEYRING_NAME: string

  /**
   * Google KMS token
   */
  GOOGLE_KMS_TOKEN: string

  // Revocation status service
  /**
   * URL of the revocation status service to check UCAN delegations
   */
  REVOCATION_STATUS_SERVICE_URL?: string

  // Subscription plan service
  /**
   * URL of the subscription plan service to check if a space has a paid plan
   */
  SUBSCRIPTION_PLAN_SERVICE_URL?: string
  
  // Rate limiting service
  /**
   * Feature flag to enable/disable KMS rate limiting
   */
  FF_KMS_RATE_LIMITER_ENABLED: string

  /**
   * Cloudflare KV namespace for storing rate limit counters
   */
  KMS_RATE_LIMIT_KV?: KVNamespace
}
