/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { type Secret } from '@adonisjs/core/helpers'
import { RuntimeException } from '@adonisjs/core/exceptions'

import { type RememberMeToken } from '../remember_me_token.ts'
import { PROVIDER_REAL_USER } from '../../../src/symbols.ts'
import type {
  SessionGuardUser,
  LucidAuthenticatable,
  SessionLucidUserProviderOptions,
  SessionUserProviderContract,
} from '../types.ts'

/**
 * Uses a lucid model to verify access tokens and find a user during
 * authentication
 *
 * @template UserModel - The Lucid model representing the user
 *
 * @example
 * const userProvider = new SessionLucidUserProvider({
 *   model: () => import('#models/user')
 * })
 */
export class SessionLucidUserProvider<
  UserModel extends LucidAuthenticatable,
> implements SessionUserProviderContract<InstanceType<UserModel>> {
  declare [PROVIDER_REAL_USER]: InstanceType<UserModel>

  /**
   * Reference to the lazily imported model
   */
  protected model?: UserModel

  /**
   * Creates a new SessionLucidUserProvider instance
   *
   * @param options - Configuration options for the user provider
   *
   * @example
   * const provider = new SessionLucidUserProvider({
   *   model: () => import('#models/user')
   * })
   */
  constructor(
    /**
     * Lucid provider options
     */
    protected options: SessionLucidUserProviderOptions<UserModel>
  ) {}

  /**
   * Imports the model from the provider, returns and caches it
   * for further operations.
   *
   * @example
   * const UserModel = await provider.getModel()
   * const user = await UserModel.find(1)
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
   *
   * @example
   * const tokensProvider = await provider.getTokensProvider()
   * const token = await tokensProvider.create(user, '7d')
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
   *
   * @param user - The user model instance
   *
   * @example
   * const guardUser = await provider.createUserForGuard(user)
   * console.log('User ID:', guardUser.getId())
   * console.log('Original user:', guardUser.getOriginal())
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
   *
   * @param identifier - The user identifier to search for
   *
   * @example
   * const guardUser = await provider.findById(123)
   * if (guardUser) {
   *   const originalUser = guardUser.getOriginal()
   *   console.log('Found user:', originalUser.email)
   * }
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
   *
   * @param user - The user to create a token for
   * @param expiresIn - Token expiration time
   *
   * @example
   * const token = await provider.createRememberToken(user, '30d')
   * console.log('Remember token:', token.value.release())
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
   *
   * @param tokenValue - The token value to verify
   *
   * @example
   * const token = await provider.verifyRememberToken(
   *   new Secret('rmt_abc123.def456')
   * )
   * if (token && !token.isExpired()) {
   *   console.log('Valid remember token for user:', token.tokenableId)
   * }
   */
  async verifyRememberToken(tokenValue: Secret<string>): Promise<RememberMeToken | null> {
    const tokensProvider = await this.getTokensProvider()
    return tokensProvider.verify(tokenValue)
  }

  /**
   * Delete a token for a user by the token identifier
   *
   * @param user - The user that owns the token
   * @param identifier - The token identifier to delete
   *
   * @example
   * const deletedCount = await provider.deleteRemeberToken(user, 123)
   * console.log('Deleted tokens:', deletedCount)
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
   *
   * @param user - The user that owns the token
   * @param identifier - The token identifier to recycle
   * @param expiresIn - New expiration time
   *
   * @example
   * const newToken = await provider.recycleRememberToken(user, 123, '30d')
   * console.log('Recycled token:', newToken.value.release())
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
