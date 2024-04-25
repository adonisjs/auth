/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { RuntimeException } from '@adonisjs/core/exceptions'
import { PROVIDER_REAL_USER } from '../../../src/symbols.js'
import type {
  BasicAuthGuardUser,
  LucidAuthenticatable,
  BasicAuthUserProviderContract,
  BasicAuthLucidUserProviderOptions,
} from '../types.js'

/**
 * Uses a Lucid model to verify access tokens and find a user during
 * authentication
 */
export class BasicAuthLucidUserProvider<UserModel extends LucidAuthenticatable>
  implements BasicAuthUserProviderContract<InstanceType<UserModel>>
{
  declare [PROVIDER_REAL_USER]: InstanceType<UserModel>

  /**
   * Reference to the lazily imported model
   */
  protected model?: UserModel

  constructor(
    /**
     * Lucid provider options
     */
    protected options: BasicAuthLucidUserProviderOptions<UserModel>
  ) {}

  /**
   * Imports the model from the provider, returns and caches it
   * for further operations.
   */
  protected async getModel() {
    if (this.model && !('hot' in import.meta)) {
      return this.model
    }

    const importedModel = await this.options.model()
    this.model = importedModel.default
    return this.model
  }

  /**
   * Creates an adapter user for the guard
   */
  async createUserForGuard(
    user: InstanceType<UserModel>
  ): Promise<BasicAuthGuardUser<InstanceType<UserModel>>> {
    const model = await this.getModel()
    if (user instanceof model === false) {
      throw new RuntimeException(
        `Invalid user object. It must be an instance of the "${model.name}" model`
      )
    }

    return {
      getId() {
        /**
         * Ensure user has a primary key
         */
        if (!user.$primaryKeyValue) {
          throw new RuntimeException(
            `Cannot use "${model.name}" model for authentication. The value of column "${model.primaryKey}" is undefined or null`
          )
        }

        return user.$primaryKeyValue
      },
      getOriginal() {
        return user
      },
    }
  }

  /**
   * Verifies credentials using the underlying model
   */
  async verifyCredentials(
    uid: string,
    password: string
  ): Promise<BasicAuthGuardUser<InstanceType<UserModel>> | null> {
    const model = await this.getModel()
    try {
      const user = await model.verifyCredentials(uid, password)
      return this.createUserForGuard(user as InstanceType<UserModel>)
    } catch {
      return null
    }
  }
}
