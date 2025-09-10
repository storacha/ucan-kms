import { AuditLogService } from './auditLog.js'
import { error, ok, Failure } from '@ucanto/server'

/**
 * @import { RevocationStatusService } from './revocation.types.js'
 * @import * as Ucanto from '@ucanto/interface'
 */

/**
 * Revocation status service implementation
 * @implements {RevocationStatusService}
 */
export class RevocationStatusServiceImpl {
  /**
   * Creates a new revocation status service
   * @param {Object} [options] - Service options
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
      this.auditLog.logServiceInitialization('RevocationStatusService', true)
    }
  }

  /**
   * Checks revocation status of UCAN delegations via Storage UCAN Service
   *
   * @param {Ucanto.Proof[]} proofs - Array of UCAN proofs to check
   * @param {import('../types/env.js').Env} env - Environment configuration
   * @returns {Promise<import('@ucanto/server').Result<boolean, import('@ucanto/server').Failure>>}
   */
  async checkStatus (proofs, env) {
    const delegations = (proofs || []).map(p => /** @type {import('@ucanto/interface').Delegation} */ (p))
    if (delegations.length === 0) {
      this.auditLog.logSecurityEvent('revocation_check_success', {
        operation: 'revocation_check',
        status: 'success',
        metadata: {
          proofsCount: delegations.length,
        }
      })
      return ok(true)
    }
    try {
      const result = await hasValidDelegationChain(delegations, env)
      if (result.isValid) {
        this.auditLog.logSecurityEvent('revocation_check_success', {
          operation: 'revocation_check',
          status: 'success',
          metadata: {
            proofsCount: delegations.length,
          }
        })
        return ok(true)
      }

      this.auditLog.logSecurityEvent('revocation_check_failure', {
        operation: 'revocation_check',
        status: 'failure',
        error: 'Delegation revoked',
        metadata: { proofsCount: delegations.length, revokedDelegation: result }
      })
      return error(new Failure('Delegation revoked'))
    } catch (err) {
      console.error('[checkStatus] something went wrong:', err)

      // Log revocation check failure
      this.auditLog.logSecurityEvent('revocation_check_failure', {
        operation: 'revocation_check',
        status: 'failure',
        error: err instanceof Error ? err.message : String(err),
        metadata: { proofsCount: delegations.length }
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
 * @param {import('@ucanto/interface').Delegation[]} delegations - The delegations to verify
 * @param {import('../types/env.js').Env} env - Environment configuration
 * @param {number} concurrencyLimit - Max parallel requests (default: 5)
 * @returns {Promise<{isValid: boolean, revokedDelegation?: string, reason?: string}>}
 */
async function hasValidDelegationChain(delegations, env, concurrencyLimit = 5) {
  // Collect all CIDs in the proof chain (breadth-first)
  /** @type {string[]} */
  const cidsToCheck = []
  /** @type {import('@ucanto/interface').Delegation[]} */
  const queue = [...delegations]
  const visited = new Set()
  
  while (queue.length > 0) {
    const current = queue.shift()
    if (!current) continue
    const cidStr = current.cid.toString()
    if (visited.has(cidStr)) continue
    visited.add(cidStr)
    cidsToCheck.push(cidStr)
    
    // Add proofs to queue for traversal
    if (current.proofs) {
      queue.push(...current.proofs.map(p => /** @type {import('@ucanto/interface').Delegation} */ (p)))
    }
  }
  
  // Check all CIDs in parallel with concurrency limit and cancellation
  const abortController = new AbortController()
  let foundRevocation = null
  
  /**
   * Checks if a delegation is revoked
   * @param {string} cid - The CID of the delegation to check
   * @returns {Promise<{isValid: boolean, revokedDelegation?: string, reason?: string, revocationData?: any} | null>}
   */
  const checkCID = async (cid) => {
    if (abortController.signal.aborted) return null
    const response = await fetch(`${env.UPLOAD_SERVICE_URL}/revocations/${cid}`)
    if (response.status === 200) {
      // According to W3 revocations-check spec, 200 response means delegation is revoked
      // We don't need to parse the CAR file, just trust the 200 status
      foundRevocation = {
        isValid: false,
        revokedDelegation: cid,
        reason: 'Delegation explicitly revoked'
      }
      abortController.abort() // Cancel remaining requests
      return foundRevocation
    }
    
    return null
  }
  
  // Start all checks with concurrency limit and return immediately on first revocation
  return new Promise(async (resolve) => {
    let activePromises = 0
    let completedChecks = 0
    let cidIndex = 0
    
    const startNextCheck = async () => {
      if (cidIndex >= cidsToCheck.length || abortController.signal.aborted) {
        return
      }
      
      const cid = cidsToCheck[cidIndex++]
      activePromises++
      
      try {
        const result = await checkCID(cid)
        if (result && !result.isValid) {
          // Found revocation - resolve immediately
          resolve(result)
          return
        }
      } catch (error) {
        console.error('Error checking CID:', cid, error)
      }
      
      activePromises--
      completedChecks++
      
      // Check if we're done
      if (completedChecks >= cidsToCheck.length) {
        resolve({ isValid: true })
        return
      }
      
      // Start next check if we have capacity
      if (activePromises < concurrencyLimit) {
        startNextCheck()
      }
    }
    
    // Start initial batch of checks
    const initialBatch = Math.min(concurrencyLimit, cidsToCheck.length)
    for (let i = 0; i < initialBatch; i++) {
      startNextCheck()
    }
  })
}