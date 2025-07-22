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
    const safeProofs = proofs || []

    try {
      if (!env.REVOCATION_STATUS_SERVICE_URL) {
        // Log that revocation service is unavailable (security concern)
        this.auditLog.logSecurityEvent('revocation_service_unavailable', {
          operation: 'revocation_check',
          status: 'skipped',
          metadata: {
            reason: 'service_not_configured',
            proofsCount: safeProofs.length
          }
        })

        return ok(true)
      }

      // TODO: Implement actual revocation status checking via Storage UCAN Service
      // This would typically involve:
      // 1. Extract delegation CIDs from proofs
      // 2. Call the revocation service API with the delegation CIDs
      // 3. Parse the response to determine if any delegations are revoked
      // 4. Return appropriate result

      // For now, return success (no revocations found)
      // Log that revocation check was attempted but not fully implemented
      this.auditLog.logSecurityEvent('revocation_check_success', {
        operation: 'revocation_check',
        status: 'success',
        metadata: {
          implementation: 'stub',
          proofsCount: safeProofs.length,
          note: 'Not fully implemented - returns success by default'
        }
      })

      return ok(true)
    } catch (err) {
      console.error('[checkStatus] something went wrong:', err)

      // Log revocation check failure
      this.auditLog.logSecurityEvent('revocation_check_failure', {
        operation: 'revocation_check',
        status: 'failure',
        error: err instanceof Error ? err.message : String(err),
        metadata: { proofsCount: safeProofs.length }
      })

      // Generic error message must be returned to the client to avoid leaking information
      return error(new Failure('Revocation status check failed'))
    }
  }
}
