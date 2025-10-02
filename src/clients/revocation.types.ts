import { Result } from "@ucanto/server";
import * as Ucanto from "@ucanto/interface";
import { Env } from "../types/env.js";

export interface RevocationStatusClient {
  /**
   * Checks revocation status of UCAN delegations
   *
   * @param proofs - Array of UCAN proofs to check
   * @param spaceDID - Space DID to validate delegation context
   * @param env - Environment configuration
   * @returns Promise with the check result
   */
  checkStatus(
    proofs: Ucanto.Proof[],
    spaceDID: string,
    env: Env,
  ): Promise<Result<boolean, import("@ucanto/server").Failure>>;
}
