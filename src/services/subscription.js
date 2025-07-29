import { AuditLogService } from './auditLog.js'
import { error, ok, Failure } from '@ucanto/server'
import * as PlanCapabilities from '@storacha/capabilities/plan'
import { create as createClient } from '@storacha/client'
import { StoreMemory } from '@storacha/client/stores/memory'
import { EncryptionSetup } from '@storacha/capabilities/space'
import { from } from 'multiformats/hashes/hasher'

/**
 * @import { SubscriptionStatusService } from './subscription.types.js'
 */

/**
 * Plan service subscription status implementation
 * @implements {SubscriptionStatusService}
 */
export class PlanSubscriptionServiceImpl {

  /** @type {import('@ucanto/principal/ed25519').Signer} */
  signer

  /** @type {import('@ucanto/interface').DID} */
  serviceID

  /**
   * Creates a new subscription service
   * @param {import('@ucanto/interface').Signer} signer - Signer for storacha client
   * @param {import('@ucanto/interface').DID} serviceID - Service ID for storacha client
   * @param {Object} [options] - Service options
   * @param {AuditLogService} [options.auditLog] - Audit log service instance
   * @param {string} [options.environment] - Environment name for audit logging
   */
  constructor(signer, serviceID, options = {}) {
    this.auditLog = options.auditLog || new AuditLogService({
      serviceName: 'subscription-service',
      environment: options.environment || 'unknown'
    })
    // Only log service initialization in development
    if (process.env.NODE_ENV === 'development') {
      this.auditLog.logServiceInitialization('PlanSubscriptionService', true)
    }

    if (!signer || !serviceID) {
      this.auditLog.logSecurityEvent('subscription_plan_service_configuration_missing', {
        operation: 'subscription_check',
        status: 'failure',
        metadata: {
          reason: 'missing_signer_or_service_id'
        }
      })
      throw new Error('Subscription service not properly configured')
    }
    this.signer = signer
    this.serviceID = serviceID
  }

  /**
   * Validates that a space has a paid plan using storacha client.
   *
   * @param {import("@ucanto/interface").Invocation<import('@ucanto/interface').InferInvokedCapability<typeof import("@storacha/capabilities/space").EncryptionSetup>>} invocation
   * @param {import('@storacha/capabilities/types').SpaceDID} space - The space DID to check
   * @param {import('../types/env.js').Env } env - Environment configuration
   * @returns {Promise<import('@ucanto/server').Result<{ provisioned: boolean }, import("@ucanto/server").Failure>>}
   */
  async isProvisioned(invocation, space, env) {
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
        return ok({ provisioned: true})
      }

      // Validate we have the necessary configuration for storacha client
      if (!invocation || !invocation.proofs || invocation.proofs.length === 0) {
        this.auditLog.logSecurityEvent('subscription_plan_service_no_proofs', {
          operation: 'subscription_check',
          status: 'failure',
          metadata: {
            reason: 'no_delegation_proofs_provided'
          }
        })
        return error(new Failure('No delegation proofs provided for subscription check'))
      }
      
      // TODO: file `plan/get` proof otherwise return error

      try {
        // Create storacha client with delegation proofs
        const store = new StoreMemory()
        const storachaClient = await createClient({
          principal: this.signer,
          store
        })
        // Add the delegation proofs to the client
        for (const proof of invocation.proofs) {
          await storachaClient.addProof(
            /** @type {import('@storacha/client/types').Delegation} */ (
              proof
            )
          )
        }

        // Get proofs for plan/get capability
        const proofs = storachaClient.proofs([
          {
            can: PlanCapabilities.get.can,
            with: account,
          },
        ])

        // Call Plan.get to check if the account has a subscription
        const receipt = await storachaClient.agent.invokeAndExecute(PlanCapabilities.get, {
          with: account,
          proofs,
        })

        // Check if the plan call was successful
        if (receipt.out.ok) {
          const planInfo = receipt.out.ok
          // If we got plan info, it means the account has a paid plan
          const hasSubscription = Boolean(planInfo)

          this.auditLog.logSecurityEvent('subscription_plan_service_success', {
            operation: 'subscription_check',
            status: 'success',
            metadata: {
              space,
              account,
              hasSubscription,
              implementation: 'storacha_client'
            }
          })

          return ok({ provisioned: hasSubscription })
        } else {
          // Plan.get failed - this might mean no subscription
          this.auditLog.logSecurityEvent('subscription_plan_service_no_subscription', {
            operation: 'subscription_check',
            status: 'no_subscription',
            metadata: {
              space,
              account,
              error: receipt.out.error?.message || 'Plan.get failed'
            }
          })

          // Return false (no subscription) rather than error for failed plan.get
          return ok({ provisioned: false })
        }
      } catch (clientError) {
        this.auditLog.logSecurityEvent('subscription_plan_service_client_error', {
          operation: 'subscription_check',
          status: 'failure',
          error: clientError instanceof Error ? clientError.message : String(clientError)
        })

        // If client creation or usage fails, deny access
        return error(new Failure('Failed to validate subscription status'))
      }
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
