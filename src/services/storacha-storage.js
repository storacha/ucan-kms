import { Plan } from '@storacha/capabilities'
import { uploadServiceConnection } from '@storacha/client/service'

/**
 * Service for interacting with Storacha storage and plan management
 */
export class StorachaStorageService {
  /**
   * Creates a new StorachaStorageService
   * @param {Object} [config] - Service options
   * @param {URL} [config.uploadServiceURL] - Upload service URL
   * @param {import('@ucanto/interface').DID} [config.uploadServiceDID] - Upload service DID
   */
  constructor(config = {}) {
    this.uploadServiceConnection = uploadServiceConnection({
      id: { did: () => /** @type {import('@ucanto/interface').DID} */(config.uploadServiceDID) },
      url: config.uploadServiceURL,
    })
  }

  /**
   * Gets plan information for an account using a plan/get delegation
   * 
   * @param {import('@ucanto/interface').Delegation} planGetDelegation - The plan/get delegation proof
   * @param {import('@ucanto/interface').Signer<`did:key:${string}`, any>} ucanKmsSigner - The signer to use for the invocation
   * @returns {Promise<{ plan: { product: string }, accountDID: string }>} The plan information and account DID
   * @throws {Error} If the plan/get invocation fails
   */
  async getPlan(planGetDelegation, ucanKmsSigner) {
    const [capability] = planGetDelegation.capabilities
    const accountDID = capability.with
    const invocation = Plan.get.invoke({
      issuer: ucanKmsSigner,
      audience: this.uploadServiceConnection.id,
      with: /** @type {`did:mailto:${string}`} */(accountDID),
      proofs: [planGetDelegation]
    })
    const [receipt] = await this.uploadServiceConnection?.execute(invocation)
    if (!receipt) {
      throw new Error('Plan/Get invocation failed: No receipt')
    }
    const result = receipt.out
    if (!result) {
      throw new Error('Plan/Get invocation failed: No result')
    }
    if (!result.ok) {
      throw new Error('Plan/Get invocation failed: ' + result.error?.message, { cause: result.error })
    }
    const plan = /** @type {import('@storacha/capabilities/types').PlanGetSuccess} */ (result.ok)
    if (!plan.product) {
      throw new Error('Plan/Get invocation failed: No product')
    }

    return {
      plan,
      accountDID
    }
  }

  /**
   * Validates if a plan product is a paid plan
   * 
   * @param {string} planProduct - The plan product identifier
   * @returns {boolean} True if the plan is a paid plan
   */
  isPaidPlan(planProduct) {
    const PAID_PLANS = [
      'did:web:lite.web3.storage',
      'did:web:business.web3.storage',
    ]
    
    return PAID_PLANS.includes(planProduct)
  }
}
