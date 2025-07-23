import { AuditLogService } from './auditLog.js'
import { error, ok, Failure } from '@ucanto/server'

/**
 * @import { SubscriptionStatusService } from './subscription.types.js'
 */

/**
 * Plan service subscription status implementation
 * @implements {SubscriptionStatusService}
 */
export class PlanSubscriptionServiceImpl {
  /**
   * Creates a new subscription service
   * @param {Object} [options] - Service options
   * @param {AuditLogService} [options.auditLog] - Audit log service instance
   * @param {string} [options.environment] - Environment name for audit logging
   */
  constructor (options = {}) {
    this.auditLog = options.auditLog || new AuditLogService({
      serviceName: 'subscription-service',
      environment: options.environment || 'unknown'
    })
    // Only log service initialization in development
    if (process.env.NODE_ENV === 'development') {
      this.auditLog.logServiceInitialization('PlanSubscriptionService', true)
    }
  }

  /**
   * Validates that a space has a paid plan.
   *
   * @param {import('@storacha/capabilities/types').SpaceDID} space - The space DID to check
   * @param {import('../types/env.js').Env } env - Environment configuration
   * @returns {Promise<import('@ucanto/server').Result<{ ok: boolean }, import('@ucanto/server').Failure>>}
   */
  async isProvisioned (space, env) {
    try {
      if (!env.SUBSCRIPTION_PLAN_SERVICE_URL) {
        // If no plan service configured, allow all spaces (dev mode)
        this.auditLog.logSecurityEvent('subscription_plan_service_unavailable', {
          operation: 'subscription_check',
          status: 'skipped',
          metadata: {
            reason: 'service_not_configured'
          }
        })
        return ok({ ok: true })
      }

      // TODO: Query plan service to check if space is provisioned (it means it has a paid plan)
      // This would typically involve:
      // 1. Call the subscription plan service API with the space DID
      // 2. Parse the response to determine if the space has a paid plan
      // 3. Return appropriate result based on plan status
      // For now, return success (allow all spaces)
      this.auditLog.logSecurityEvent('subscription_plan_service_available', {
        operation: 'subscription_check',
        status: 'success',
        metadata: {
          implementation: 'stub',
          note: 'Not fully implemented - returns success by default'
        }
      })
      return ok({ ok: true })
    } catch (err) {
      console.error('[isProvisioned] something went wrong:', err)

      this.auditLog.logSecurityEvent('subscription_plan_service_failure', {
        operation: 'subscription_check',
        status: 'failure',
        error: err instanceof Error ? err.message : String(err) 
      })
      // Generic error message must be returned to the client to avoid leaking information
      return error(new Failure('Subscription validation failed'))
    }
  }
}
