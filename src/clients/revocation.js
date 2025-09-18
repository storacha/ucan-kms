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
            spaceDID
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
 * Collects all CIDs in proof chain and checks them in parallel with cancellation
 *
 * @param {import('@ucanto/interface').Proof[]} proofs - The proofs to verify
 * @param {string} spaceDID - Space DID where the encrypted content is stored
 * @param {string} uploadServiceUrl - Upload service URL
 * @param {number} concurrencyLimit - Max parallel requests (default: 5)
 * @returns {Promise<{isValid: boolean, revokedDelegation?: string, reason?: string}>}
 */
async function verifyDelegationChain (proofs, spaceDID, uploadServiceUrl, concurrencyLimit = 5) {
  // Filter delegations that are for the expected space
  const validDelegations = (proofs || [])
    .filter(isDelegation)
    .filter(d => {
      return d.capabilities && d.capabilities.some(cap => {
        // TODO test it without the space filter - I think we may want to find only the decrypt delegation
        return cap.with && cap.with === spaceDID
      })
    })
  if (validDelegations.length === 0) {
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

  // Collect CIDs only from space-valid delegations (breadth-first)
  /** @type {string[]} */
  const cidsToCheck = []
  /** @type {import('@ucanto/interface').Delegation[]} */
  const queue = [...validDelegations] // Only start with space-valid delegations
  const visited = new Set()

  while (queue.length > 0) {
    const current = queue.shift()
    if (!current) continue
    const cidStr = current.cid.toString()
    if (visited.has(cidStr)) continue
    visited.add(cidStr)
    cidsToCheck.push(cidStr)

    // Add proofs to queue for traversal, but only if they're for the same space
    if (current.proofs) {
      const spaceValidProofs = current.proofs
        .filter(isDelegation)
        .filter(d => d.capabilities.some(cap => cap.with === spaceDID))
      queue.push(...spaceValidProofs)
    }
  }

  // Check all CIDs for explicit revocations using p-queue for concurrency control
  const abortController = new AbortController()
  const revocationQueue = new PQueue({ concurrency: concurrencyLimit })

  /**
   * Checks if a delegation CID has been explicitly revoked
   * @param {string} cid - The CID of the delegation to check
   * @returns {Promise<{isValid: boolean, revokedDelegation?: string, reason?: string} | null>}
   */
  const checkCID = async (cid) => {
    if (abortController.signal.aborted) return null

    try {
      const response = await fetch(`${uploadServiceUrl}/revocations/${cid}`, {
        signal: abortController.signal
      })
      if (response.status === 200) {
        // According to W3 revocations-check spec, 200 response means delegation is revoked
        // We don't need to parse the CAR file, just trust the 200 status
        const revocation = {
          isValid: false,
          revokedDelegation: cid,
          reason: 'Delegation explicitly revoked'
        }
        abortController.abort() // Cancel remaining requests
        revocationQueue.clear() // Clear remaining queued tasks
        return revocation
      }

      return null
    } catch (/** @type {any} */ error) {
      // Handle native fetch AbortError
      if (error?.name === 'AbortError') {
        // Request was cancelled, because revocation was found. This is expected behavior.
        return null
      }
      console.error(`Assuming delegation is revoked due to network error while checking revocation for CID ${cid}:`, error)
      return {
        isValid: false,
        reason: 'Revocation check failed'
      }
    }
  }

  // Add all CID checks to the queue
  const promises = cidsToCheck.map(cid =>
    revocationQueue.add(() => checkCID(cid), { priority: 0 })
  )

  // Wait for all checks to complete or first revocation to be found
  try {
    const results = await Promise.allSettled(promises)

    // Check results for any revocations
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value && !result.value.isValid) {
        return result.value
      }
    }

    return { isValid: true }
  } finally {
    // Ensure queue is properly cleaned up
    revocationQueue.clear()
  }
}
