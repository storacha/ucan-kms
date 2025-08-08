import { create as createClient } from '@storacha/client'
import { StoreMemory } from '@storacha/client/stores'
import { Plan } from '@storacha/capabilities'

/**
 * Service for interacting with Storacha storage and plan management
 */
export class StorachaStorageService {
  /**
   * Creates a new StorachaStorageService
   * @param {Object} [options] - Service options
   * @param {import('@storacha/client').Client} [options.client] - Pre-configured Storacha client
   * @param {import('@ucanto/interface').Signer<`did:key:${string}`, any>} [options.signer] - Signer to create client with
   */
  constructor(options = {}) {
    if (options.client) {
      this.client = options.client
    } else if (options.signer) {
      // Create client immediately in constructor
      this.clientPromise = createClient({
        principal: options.signer,
        store: new StoreMemory(),
      })
    } else {
      throw new Error('Either client or signer must be provided')
    }
  }

  /**
   * Gets the client, creating it if needed
   * @private
   */
  async getClient() {
    if (this.client) {
      return this.client
    }
    if (this.clientPromise) {
      this.client = await this.clientPromise
      this.clientPromise = undefined // Clear the promise after resolving
      return this.client
    }
    throw new Error('No client available')
  }

  /**
   * Gets plan information for an account using a plan/get delegation
   * 
   * @param {import('@ucanto/interface').Delegation} planGetDelegation - The plan/get delegation proof
   * @returns {Promise<{ plan: { product: string }, accountDID: string }>} The plan information and account DID
   * @throws {Error} If the plan/get invocation fails
   */
  async getPlan(planGetDelegation) {
    const client = await this.getClient()

    // Add the plan/get delegation proof to the client
    await client.addProof(planGetDelegation)

    // Extract the account DID from the delegation capability
    const [capability] = planGetDelegation.capabilities
    const accountDID = capability.with

    // Get proofs for the plan/get capability
    const clientProofs = client.proofs([{
      can: Plan.get.can,
      with: accountDID,
    }])

    // Invoke plan/get to retrieve the plan information
    const receipt = await client.agent.invokeAndExecute(Plan.get, {
      with: accountDID,
      proofs: clientProofs
    })

    const result = receipt.out
    if (!result.ok) {
      throw new Error(`Plan/Get invocation failed: ${result.error?.message || 'Unknown error'}`)
    }

    return {
      plan: result.ok,
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
