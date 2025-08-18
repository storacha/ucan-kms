import { Proof, Result } from "@ucanto/server";

export interface SubscriptionStatusService {
  /**
   * Validates that a space has a paid plan by checking for plan/get delegation proofs.
   *
   * @param space - The space DID to check
   * @param proofs - UCAN proofs to validate for plan/get capability
   * @returns Promise with the validation result
   */
  isProvisioned(
    space: import("@storacha/capabilities/types").SpaceDID,
    proofs: Proof[],
    ctx: import("../api.types.js").Context,
  ): Promise<
    Result<{ isProvisioned: boolean }, import("@ucanto/server").Failure>
  >;
}
