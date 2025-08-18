import { AuditLogService } from './auditLog.js'
import { error, ok, Failure } from '@ucanto/server'
import { Plan } from '@storacha/capabilities'
import { StorachaStorageService } from './storacha-storage.js'
import { DID } from '@ucanto/validator'

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
   * @param {import('../types/env.d.ts').Env} env - Environment configuration
   * @param {Object} [options] - Service options
   * @param {AuditLogService} [options.auditLog] - Audit log service instance
   * @param {string} [options.environment] - Environment name for audit logging
   * @param {StorachaStorageService} [options.storachaStorage] - Storacha storage service instance
   */
  constructor (env, options = {}) {
    this.auditLog = options.auditLog || new AuditLogService({
      serviceName: 'subscription-service',
      environment: env.ENVIRONMENT || 'unknown'
    })
    this.storachaStorage = options.storachaStorage
    this.env = env
    // Only log service initialization in development
    if (process.env.NODE_ENV === 'development') {
      this.auditLog.logServiceInitialization('PlanSubscriptionService', true)
    }
  }

  /**
   * Validates that a space has a paid plan by checking for plan/get delegation proofs.
   *
   * @param {import('@storacha/capabilities/types').SpaceDID} space - The space DID to check
   * @param {import('@ucanto/interface').Proof[]} proofs - UCAN proofs to validate for plan/get capability
   * @param {import('../api.types.js').Context } ctx - Context object containing environment configuration
   * @returns {Promise<import('@ucanto/server').Result<{ isProvisioned: boolean }, import('@ucanto/server').Failure>>}
   */
  async isProvisioned (space, proofs, ctx) {
    try {
      if (proofs.length === 0) {
        this.auditLog.logSecurityEvent('subscription_plan_delegation_missing', {
          operation: 'subscription_check',
          status: 'denied',
          metadata: {
            space,
            reason: 'no_plan_get_delegation_provided',
            proofsCount: proofs.length
          }
        })
        return error(new Failure('No Plan/Get Delegation proofs provided'))
      }
      
      const planGetDelegation = proofs
      .map(p => /** @type {import('@ucanto/interface').Delegation} */(p))
      .find(d => d.capabilities.some(cap => cap.can === Plan.get.can))
      if (!planGetDelegation) {
        this.auditLog.logSecurityEvent('subscription_plan_delegation_missing', {
          operation: 'subscription_check',
          status: 'denied',
          metadata: {
            space,
            reason: 'no_plan_get_delegation_in_proofs',
            proofsCount: proofs.length
          }
        })
        return error(new Failure('No Plan/Get Delegation proofs found'))
      }
      
      const storageService = this.storachaStorage || new StorachaStorageService({
        uploadServiceURL: new URL(this.env.UPLOAD_SERVICE_URL),
        uploadServiceDID: DID.from(this.env.UPLOAD_SERVICE_DID),
      })
      const { plan, accountDID } = await storageService.getPlan(planGetDelegation, ctx.ucanKmsSigner)
      if (!storageService.isPaidPlan(plan.product)) {
        this.auditLog.logSecurityEvent('subscription_plan_invalid', {
          operation: 'subscription_check',
          status: 'denied',
          metadata: {
            space,
            accountDID,
            reason: 'not_paid_plan',
            proofsCount: proofs.length,
            planProduct: plan.product
          }
        })
        return error(new Failure('User is not subscribed to a paid plan'))
      }
      
      this.auditLog.logSecurityEvent('subscription_plan_validated', {
        operation: 'subscription_check',
        status: 'success',
        metadata: {
          space,
          accountDID,
          planProofsFound: proofs.length,
          validationMethod: 'delegation_presence'
        }
      })

      return ok({ isProvisioned: true })
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
