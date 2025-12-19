/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { type Secret } from '@adonisjs/core/helpers'
import type { LucidRow } from '@adonisjs/lucid/types/model'
import { RuntimeException } from '@adonisjs/core/exceptions'

import { type AccessToken } from '../access_token.ts'
import { PROVIDER_REAL_USER } from '../../../src/symbols.ts'
import type {
  LucidTokenable,
  AccessTokensGuardUser,
  AccessTokensUserProviderContract,
  AccessTokensLucidUserProviderOptions,
} from '../types.ts'

/**
 * Uses a lucid model to verify access tokens and find a user during
 * authentication
 *
 * @template TokenableProperty - The property name that holds the tokens provider
 * @template UserModel - The Lucid model representing the user
 *
 * @example
 * const userProvider = new AccessTokensLucidUserProvider({
 *   model: () => import('#models/user'),
 *   tokens: 'accessTokens'
 * })
 */
export class AccessTokensLucidUserProvider<
  TokenableProperty extends string,
  UserModel extends LucidTokenable<TokenableProperty>,
> implements AccessTokensUserProviderContract<InstanceType<UserModel>> {
  declare [PROVIDER_REAL_USER]: InstanceType<UserModel>

  /**
   * Reference to the lazily imported model
   */
  protected model?: UserModel

  /**
   * Creates a new AccessTokensLucidUserProvider instance
   *
   * @param options - Configuration options for the user provider
   *
   * @example
   * const provider = new AccessTokensLucidUserProvider({
   *   model: () => import('#models/user'),
   *   tokens: 'accessTokens'
   * })
   */
  constructor(
    /**
     * Lucid provider options
     */
    protected options: AccessTokensLucidUserProviderOptions<TokenableProperty, UserModel>
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
   * const token = await tokensProvider.create(user, ['read'])
   */
  protected async getTokensProvider() {
    const model = await this.getModel()

    if (!model[this.options.tokens]) {
      throw new RuntimeException(
        `Cannot use "${model.name}" model for verifying access tokens. Make sure to assign a token provider to the model.`
      )
    }

    return model[this.options.tokens]
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
  ): Promise<AccessTokensGuardUser<InstanceType<UserModel>>> {
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
   * Create a token for a given user
   *
   * @param user - The user to create a token for
   * @param abilities - Optional array of abilities the token should have
   * @param options - Optional token configuration
   *
   * @example
   * const token = await provider.createToken(user, ['read', 'write'], {
   *   name: 'API Token',
   *   expiresIn: '30d'
   * })
   * console.log('Created token:', token.value.release())
   */
  async createToken(
    user: InstanceType<UserModel>,
    abilities?: string[] | undefined,
    options?: {
      name?: string
      expiresIn?: string | number
    }
  ): Promise<AccessToken> {
    const tokensProvider = await this.getTokensProvider()
    return tokensProvider.create(user as LucidRow, abilities, options)
  }

  /**
   * Invalidates a token identified by its publicly shared token
   *
   * @param tokenValue - The token value to invalidate
   *
   * @example
   * const wasInvalidated = await provider.invalidateToken(
   *   new Secret('oat_abc123.def456')
   * )
   * console.log('Token invalidated:', wasInvalidated)
   */
  async invalidateToken(tokenValue: Secret<string>) {
    const tokensProvider = await this.getTokensProvider()
    return tokensProvider.invalidate(tokenValue)
  }

  /**
   * Finds a user by the user id
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
  ): Promise<AccessTokensGuardUser<InstanceType<UserModel>> | null> {
    const model = await this.getModel()
    const user = await model.find(identifier)

    if (!user) {
      return null
    }

    return this.createUserForGuard(user)
  }

  /**
   * Verifies a publicly shared access token and returns an
   * access token for it.
   *
   * @param tokenValue - The token value to verify
   *
   * @example
   * const token = await provider.verifyToken(
   *   new Secret('oat_abc123.def456')
   * )
   * if (token && !token.isExpired()) {
   *   console.log('Valid token with abilities:', token.abilities)
   * }
   */
  async verifyToken(tokenValue: Secret<string>): Promise<AccessToken | null> {
    const tokensProvider = await this.getTokensProvider()
    return tokensProvider.verify(tokenValue)
  }
}
