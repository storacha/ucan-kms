import { AuditLogService } from '../services/auditLog.js'
import { error, ok, Failure, isDelegation } from '@ucanto/server'
import PQueue from 'p-queue'

/**
 * @import { RevocationStatusClient } from './revocation.types.js'
 * @import * as Ucanto from '@ucanto/interface'
 */

/**
 * Revocation status client implementation
 * @implements {RevocationStatusClient}
 */
export class RevocationStatusClientImpl {
  /**
   * Creates a new revocation status client
   * @param {Object} [options] - Client options
   * @param {AuditLogService} [options.auditLog] - Audit log service instance
   * @param {string} [options.environment] - Environment name for audit logging
   */
  constructor (options = {}) {
    this.auditLog = options.auditLog || new AuditLogService({
      serviceName: 'revocation-status-service',
      environment: options.environment || 'unknown'
    })
    // Only log service initialization in development
    if (process.env.NODE_ENV === 'development') {
      this.auditLog.logServiceInitialization('RevocationStatusClient', true)
    }
  }

  /**
   * Checks revocation status of UCAN delegations and invocation via Storage UCAN Service
   *
   * @param {Ucanto.Proof[]} proofs - Array of UCAN proofs to check
   * @param {string} spaceDID - Space DID to validate delegation context
   * @param {import('../types/env.js').Env} env - Environment configuration
   * @returns {Promise<import('@ucanto/server').Result<boolean, import('@ucanto/server').Failure>>}
   */
  async checkStatus (proofs, spaceDID, env) {
    try {
      const result = await verifyDelegationChain(proofs, spaceDID, env.UPLOAD_SERVICE_URL)
      if (result.isValid) {
        this.auditLog.logSecurityEvent('revocation_check_success', {
          operation: 'revocation_check',
          status: 'success',
          metadata: {
            proofsCount: (proofs || []).length,
            spaceDID,
            result: 'no_revocations_found'
          }
        })
        return ok(true)
      }

      const errorMsg = result.reason || 'Unable to check revocation status'
      this.auditLog.logSecurityEvent('revocation_check_failure', {
        operation: 'revocation_check',
        status: 'failure',
        error: errorMsg,
        metadata: {
          proofsCount: (proofs || []).length,
          revokedDelegation: result,
          spaceDID
        }
      })
      return error(new Failure(errorMsg))
    } catch (err) {
      console.error('[checkStatus] something went wrong:', err)
      this.auditLog.logSecurityEvent('revocation_check_failure', {
        operation: 'revocation_check',
        status: 'failure',
        error: err instanceof Error ? err.message : String(err),
        metadata: {
          proofsCount: (proofs || []).length,
          spaceDID
        }
      })

      // Generic error message must be returned to the client to avoid leaking information
      return error(new Failure('Revocation status check failed'))
    }
  }
}

/**
 * Client-side proof chain verification utility
 * Finds decrypt delegation and checks its entire proof chain for revocations.
 *
 * @param {import('@ucanto/interface').Proof[]} proofs - The proofs to verify
 * @param {string} spaceDID - Space DID where the encrypted content is stored
 * @param {string} uploadServiceUrl - Upload service URL
 * @returns {Promise<{isValid: boolean, revokedDelegation?: string, reason?: string}>}
 */
async function verifyDelegationChain (proofs, spaceDID, uploadServiceUrl) {
  // Find the specific delegation that grants the decrypt capability for the space that we are decrypting for
  // Otherwise we would have to check all delegations, an any revocation would break the decryption process
  const decryptDelegations = (proofs || [])
    .filter(isDelegation)
    .filter(d => {
      return d.capabilities && d.capabilities.some(cap => {
        return cap.can === 'space/content/decrypt' && cap.with === spaceDID
      })
    })

  if (decryptDelegations.length === 0) {
    return {
      isValid: false,
      reason: `No valid delegations found for space ${spaceDID}`
    }
  }

  if (!uploadServiceUrl) {
    return {
      isValid: false,
      reason: 'No revocation service URL configured - cannot validate delegation status'
    }
  }

  const visited = new Set()

  // Leaf-first traversal: collect all CIDs first, then sort by "leaf-ness"
  /** @type {import('@ucanto/interface').Delegation[]} */
  const allDelegations = []
  /** @type {import('@ucanto/interface').Delegation[]} */
  const queue = [...decryptDelegations]

  // First pass: collect all delegations in the chain
  while (queue.length > 0) {
    const current = queue.shift()
    if (!current) continue
    const cidStr = current.cid.toString()
    if (visited.has(cidStr)) continue
    visited.add(cidStr)
    allDelegations.push(current)

    if (current.proofs) {
      const nextProofs = current.proofs.filter(isDelegation)
      queue.push(...nextProofs)
    }
  }

  const abortController = new AbortController()
  const revocationQueue = new PQueue({ concurrency: 5 })

  /**
   * Checks if a delegation CID has been explicitly revoked
   * @param {string} cid - The CID of the delegation to check
   * @returns {Promise<{isValid: boolean, revokedDelegation?: string, reason?: string} | null>}
   */
  const checkCID = async (cid) => {
    try {
      const response = await fetch(`${uploadServiceUrl}/revocations/${cid}`, {
        signal: abortController.signal
      })

      if (response.status === 200) {
        // Abort all other requests immediately
        abortController.abort()
        revocationQueue.clear()
        return {
          isValid: false,
          revokedDelegation: cid,
          reason: 'Delegation explicitly revoked'
        }
      }

      return null
    } catch (/** @type {any} */ error) {
      if (error?.name === 'AbortError') {
        // Request was cancelled - this is expected
        return null
      }
      // Log network errors for debugging
      console.error(`[verifyDelegationChain] Network error checking revocation for ${cid}:`, error)
      return {
        isValid: false,
        reason: 'Revocation check failed'
      }
    }
  }

  // Race all checks - return immediately on first revocation
  try {
    // Create a promise that resolves when ANY revocation is found
    const racePromise = new Promise((resolve) => {
      let completed = 0
      const total = allDelegations.length

      allDelegations.forEach(delegation => {
        revocationQueue.add(async () => {
          const result = await checkCID(delegation.cid.toString())
          if (result && !result.isValid) {
            // Found revocation - resolve immediately
            resolve(result)
          } else {
            completed++
            if (completed === total) {
              // All checks done, no revocation found
              resolve({ isValid: true })
            }
          }
        })
      })
    })

    return await racePromise
  } catch (error) {
    console.error('[verifyDelegationChain] Error during revocation check:', error)
    return {
      isValid: false,
      reason: 'Revocation check failed'
    }
  } finally {
    revocationQueue.clear()
  }
}
