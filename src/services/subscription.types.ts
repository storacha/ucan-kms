import { Result } from "@ucanto/client";
import { Env } from "../types/env.js";

export interface SubscriptionStatusService {
  /**
   * Validates that a space has a paid plan.
   *
   * @param space - The space DID to check
   * @param env - Environment configuration
   * @returns Promise with the validation result or error
   */
  isProvisioned(
    space: import("@storacha/capabilities/types").SpaceDID,
    env: Env,
  ): Promise<Result<{ ok: boolean }, Error>>;
}
