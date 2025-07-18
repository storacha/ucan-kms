import * as Server from "@ucanto/server";
import { ServiceMethod, Signer } from "@ucanto/interface";
import { Failure } from "@ucanto/interface";
import {
  SpaceEncryptionSetup,
  SpaceEncryptionKeyDecrypt,
} from "@storacha/capabilities/types";
import { RevocationStatusService } from "./services/revocation.types.js";
import { KMSService } from "./services/kms.types.js";
import { SubscriptionStatusService } from "./services/subscription.types.js";
import { UcanPrivacyValidationService } from "./services/ucanValidation.types.js";
import { KmsRateLimiter } from "./services/kmsRateLimiter.js";

export type EncryptionSetupResult = { publicKey: string };
export type KeyDecryptResult = { decryptedSymmetricKey: string };

export interface Service {
  space: {
    encryption: {
      setup: ServiceMethod<
        SpaceEncryptionSetup,
        EncryptionSetupResult,
        Failure
      >;
      key: {
        decrypt: ServiceMethod<
          SpaceEncryptionKeyDecrypt,
          KeyDecryptResult,
          Failure
        >;
      };
    };
  };
}

export interface Context<T = unknown, U = unknown> {
  /**
   * UCAN KMS signer
   */
  ucanKmsSigner: Signer;

  /**
   * UCAN KMS identity
   */
  ucanKmsIdentity: Server.Verifier;

  /**
   * KMS service for encryption/decryption operations
   */
  kms?: KMSService;

  /**
   * Revocation status service for UCAN delegation revocation checking
   */
  revocationStatusService?: RevocationStatusService;

  /**
   * Subscription status service for space plan validation
   */
  subscriptionStatusService?: SubscriptionStatusService;

  /**
   * UCAN privacy validation service for validating delegations
   */
  ucanPrivacyValidationService?: UcanPrivacyValidationService;

  /**
   * KMS rate limiter for controlling KMS operation frequency
   */
  kmsRateLimiter?: KmsRateLimiter;

  /**
   * This is optional because the handler is responsible for creating the service if it is not provided.
   *
   * @type {Service}
   */
  service?: Service;

  /**
   * This is optional because the handler is responsible for creating the server if it is not provided.
   *
   * @type {Server.ServerView<Service>}
   */
  server?: Server.ServerView<Service>;

  /**
   * This is optional because the handler is responsible for creating the server if it is not provided.
   *
   * @type {Server.ServerView<Service>}
   */
  waitUntil(promise: Promise<void>): void;
}
