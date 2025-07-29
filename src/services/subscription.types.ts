import { InferInvokedCapability, Result } from "@ucanto/server";
import { Env } from "../types/env.js";
import { EncryptionSetup } from '@storacha/capabilities/space';
export interface SubscriptionStatusService {
  /**
   * Validates that a space has a paid plan using delegation proofs.
   *
   * @param invocation - The UCAN invocation
   * @param space - The space DID to check
   * @param env - Environment configuration
   * @returns Promise with the validation result
   */
  isProvisioned(
    invocation: import("@ucanto/interface").Invocation<InferInvokedCapability<typeof EncryptionSetup>>,
    space: import("@storacha/capabilities/types").SpaceDID,
    env: Env,
  ): Promise<Result<{ provisioned: boolean }, import("@ucanto/server").Failure>>;
}

