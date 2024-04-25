/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Secret } from '@adonisjs/core/helpers'
import { RuntimeException } from '@adonisjs/core/exceptions'

import { RememberMeToken } from '../remember_me_token.js'
import { PROVIDER_REAL_USER } from '../../../src/symbols.js'
import type {
  SessionGuardUser,
  LucidAuthenticatable,
  SessionLucidUserProviderOptions,
  SessionUserProviderContract,
} from '../types.js'

/**
 * Uses a lucid model to verify access tokens and find a user during
 * authentication
 */
export class SessionLucidUserProvider<UserModel extends LucidAuthenticatable>
  implements SessionUserProviderContract<InstanceType<UserModel>>
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
    protected options: SessionLucidUserProviderOptions<UserModel>
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
   * Returns the tokens provider associated with the user model
   */
  protected async getTokensProvider() {
    const model = await this.getModel()

    if (!model.rememberMeTokens) {
      throw new RuntimeException(
        `Cannot use "${model.name}" model for verifying remember me tokens. Make sure to assign a token provider to the model.`
      )
    }

    return model.rememberMeTokens
  }

  /**
   * Creates an adapter user for the guard
   */
  async createUserForGuard(
    user: InstanceType<UserModel>
  ): Promise<SessionGuardUser<InstanceType<UserModel>>> {
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
   * Finds a user by their primary key value
   */
  async findById(
    identifier: string | number | BigInt
  ): Promise<SessionGuardUser<InstanceType<UserModel>> | null> {
    const model = await this.getModel()
    const user = await model.find(identifier)

    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }

  /**
   * Creates a remember token for a given user
   */
  async createRememberToken(
    user: InstanceType<UserModel>,
    expiresIn: string | number
  ): Promise<RememberMeToken> {
    const tokensProvider = await this.getTokensProvider()
    return tokensProvider.create(user, expiresIn)
  }

  /**
   * Verify a token by its publicly shared value
   */
  async verifyRememberToken(tokenValue: Secret<string>): Promise<RememberMeToken | null> {
    const tokensProvider = await this.getTokensProvider()
    return tokensProvider.verify(tokenValue)
  }

  /**
   * Delete a token for a user by the token identifier
   */
  async deleteRemeberToken(
    user: InstanceType<UserModel>,
    identifier: string | number | BigInt
  ): Promise<number> {
    const tokensProvider = await this.getTokensProvider()
    return tokensProvider.delete(user, identifier)
  }

  /**
   * Recycle a token for a user by the token identifier
   */
  async recycleRememberToken(
    user: InstanceType<UserModel>,
    identifier: string | number | BigInt,
    expiresIn: string | number
  ) {
    const tokensProvider = await this.getTokensProvider()
    return tokensProvider.recycle(user, identifier, expiresIn)
  }
}
