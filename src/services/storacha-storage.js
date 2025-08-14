import { Plan } from '@storacha/capabilities'
import { AgentData } from '@storacha/access/agent'
import { Client as StorachaClient } from '@storacha/client'
import { gatewayServiceConnection, uploadServiceConnection } from '@storacha/client/service'

/**
 * Service for interacting with Storacha storage and plan management
 */
export class StorachaStorageService {
  /**
   * Creates a new StorachaStorageService
   * @param {Object} [options] - Service options
   * @param {import('@storacha/client').Client} [options.client] - Pre-configured Storacha client
   * @param {import('@storacha/access').SpaceDID} [options.space] - The space DID to use
   * @param {import('@ucanto/interface').Signer<`did:key:${string}`, any>} [options.signer] - Signer to create client with
   * @param {URL} [options.uploadServiceURL] - Upload service URL
   * @param {import('@ucanto/interface').DID} [options.uploadServiceDID] - Upload service DID
   */
  constructor(options = {}) {
    if (options.client) {
      this.client = options.client
    } else if (options.signer) {
      const agentData = new AgentData({
        principal: options.signer,
        delegations: new Map(),
        spaces: new Map(),
        currentSpace: options.space,
        meta: {
          name: 'ucan-kms',
          type: 'service',
          description: 'Storacha UCAN KMS',
        },
      })
      const connection = uploadServiceConnection({
        id: {did: () => /** @type {import('@ucanto/interface').DID} */(options.uploadServiceDID) },
        url: options.uploadServiceURL,
      })
      this.client = new StorachaClient(agentData, {
        serviceConf: {
          access: connection,
          upload: connection,
          filecoin: connection,
          gateway: gatewayServiceConnection(),
        },
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
