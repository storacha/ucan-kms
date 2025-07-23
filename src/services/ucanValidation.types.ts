import { Result } from "@ucanto/server";

export interface UcanPrivacyValidationService {
  /**
   * Validates an encryption setup invocation.
   * The invocation should have space/encryption/setup capability.
   *
   * @param invocation - The UCAN invocation to validate
   * @param spaceDID - The space DID that should match the invocation
   * @returns Promise with the validation result
   */
  validateEncryption(
    invocation: import("@ucanto/interface").Invocation,
    spaceDID: import("@storacha/capabilities/types").SpaceDID,
  ): Promise<Result<boolean, import("@ucanto/server").Failure>>;

  /**
   * Validates a decrypt invocation and its proofs.
   * The invocation should have space/encryption/key/decrypt capability.
   * The proofs should contain space/content/decrypt capability.
   * The issuer of the invocation must be in the audience of the proofs.
   * The provided space must be the same as the space in the proofs.
   *
   * @param invocation - The UCAN invocation to validate
   * @param spaceDID - The space DID that should match the invocation
   * @param ucanKmsIdentity - The ucanKms identity for authorization
   * @returns Promise with the validation result
   */
  validateDecryption(
    invocation: import("@ucanto/interface").Invocation,
    spaceDID: import("@storacha/capabilities/types").SpaceDID,
    ucanKmsIdentity: import("@ucanto/interface").Verifier,
  ): Promise<Result<boolean, import("@ucanto/server").Failure>>;
}
