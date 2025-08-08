import { AuditLogService } from './auditLog.js'
import { error, ok, Failure } from '@ucanto/server'
import { Plan } from '@storacha/capabilities'
import { create as createClient } from '@storacha/client'
import { StoreMemory } from '@storacha/client/stores'

/**
 * @import { SubscriptionStatusService } from './subscription.types.js'
 */

/**
 * Paid plans available for subscription
 */
const PAID_PLANS = [
  'did:web:lite.web3.storage',
  'did:web:business.web3.storage',
]

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
      const client = await createClient({
        principal: ctx.ucanKmsSigner,
        store: new StoreMemory(),
      })
      await client.addProof(planGetDelegation)
      const [capability] = planGetDelegation.capabilities
      const accountDID = capability.with
      const clientProofs = client.proofs([{
        can: Plan.get.can,
        with: accountDID,
      }])

      const receipt = await client.agent.invokeAndExecute(Plan.get, {
        with: accountDID,
        proofs: clientProofs
      })
      const result = receipt.out
      if (!result.ok) {
        this.auditLog.logSecurityEvent('subscription_plan_delegation_invalid', {
          operation: 'subscription_check',
          status: 'denied',
          metadata: {
            space,
            accountDID,
            reason: 'plan_get_delegation_invalid',
            proofsCount: proofs.length
          }
        })
        return error(new Failure('Plan/Get Delegation proofs are invalid'))
      }

      const plan = result.ok
      if (!PAID_PLANS.includes(plan.product)) {
        this.auditLog.logSecurityEvent('subscription_plan_invalid', {
          operation: 'subscription_check',
          status: 'denied',
          metadata: {
              space,
              accountDID,
              reason: 'not_paid_plan',
              proofsCount: proofs.length
            }
          })
          return error(new Failure('Not a paid plan'))
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
