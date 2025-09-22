/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Secret } from '@adonisjs/core/helpers'
import type { HttpContext } from '@adonisjs/core/http'
import type { EmitterLike } from '@adonisjs/core/types/events'

import type { AccessToken } from './access_token.ts'
import { E_UNAUTHORIZED_ACCESS } from '../../src/errors.ts'
import type { AuthClientResponse, GuardContract } from '../../src/types.ts'
import { GUARD_KNOWN_EVENTS, type PROVIDER_REAL_USER } from '../../src/symbols.ts'
import type { AccessTokensGuardEvents, AccessTokensUserProviderContract } from './types.ts'

/**
 * Implementation of access tokens guard for the Auth layer. The heavy lifting
 * of verifying tokens is done by the user provider. However, the guard is
 * used to seamlessly integrate with the auth layer of the package.
 *
 * @template UserProvider - The user provider contract
 *
 * @example
 * const guard = new AccessTokensGuard(
 *   'api',
 *   ctx,
 *   emitter,
 *   userProvider
 * )
 *
 * const user = await guard.authenticate()
 * console.log('Authenticated user:', user.email)
 */
export class AccessTokensGuard<UserProvider extends AccessTokensUserProviderContract<unknown>>
  implements
    GuardContract<UserProvider[typeof PROVIDER_REAL_USER] & { currentAccessToken: AccessToken }>
{
  /**
   * Events emitted by the guard
   */
  declare [GUARD_KNOWN_EVENTS]: AccessTokensGuardEvents<
    UserProvider[typeof PROVIDER_REAL_USER] & { currentAccessToken: AccessToken }
  >

  /**
   * A unique name for the guard.
   */
  #name: string

  /**
   * Reference to the current HTTP context
   */
  #ctx: HttpContext

  /**
   * Provider to lookup user details
   */
  #userProvider: UserProvider

  /**
   * Emitter to emit events
   */
  #emitter: EmitterLike<
    AccessTokensGuardEvents<
      UserProvider[typeof PROVIDER_REAL_USER] & { currentAccessToken: AccessToken }
    >
  >

  /**
   * Driver name of the guard
   */
  driverName: 'access_tokens' = 'access_tokens'

  /**
   * Whether or not the authentication has been attempted
   * during the current request.
   */
  authenticationAttempted = false

  /**
   * A boolean to know if the current request has
   * been authenticated
   */
  isAuthenticated = false

  /**
   * Reference to an instance of the authenticated user.
   * The value only exists after calling one of the
   * following methods.
   *
   * - authenticate
   * - check
   *
   * You can use the "getUserOrFail" method to throw an exception if
   * the request is not authenticated.
   */
  user?: UserProvider[typeof PROVIDER_REAL_USER] & { currentAccessToken: AccessToken }

  /**
   * Creates a new AccessTokensGuard instance
   *
   * @param name - Unique name for the guard instance
   * @param ctx - HTTP context for the current request
   * @param emitter - Event emitter for guard events
   * @param userProvider - User provider for token verification
   *
   * @example
   * const guard = new AccessTokensGuard(
   *   'api',
   *   ctx,
   *   emitter,
   *   new TokenUserProvider()
   * )
   */
  constructor(
    name: string,
    ctx: HttpContext,
    emitter: EmitterLike<
      AccessTokensGuardEvents<
        UserProvider[typeof PROVIDER_REAL_USER] & { currentAccessToken: AccessToken }
      >
    >,
    userProvider: UserProvider
  ) {
    this.#name = name
    this.#ctx = ctx
    this.#emitter = emitter
    this.#userProvider = userProvider
  }

  /**
   * Emits authentication failure and returns an exception
   * to end the authentication cycle.
   */
  #authenticationFailed() {
    const error = new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
      guardDriverName: this.driverName,
    })

    this.#emitter.emit('access_tokens_auth:authentication_failed', {
      ctx: this.#ctx,
      guardName: this.#name,
      error,
    })

    return error
  }

  /**
   * Returns the bearer token from the request headers or fails
   */
  #getBearerToken(): string {
    const bearerToken = this.#ctx.request.header('authorization', '')!
    const [type, token] = bearerToken.split(' ')
    if (!type || type.toLowerCase() !== 'bearer' || !token) {
      throw this.#authenticationFailed()
    }

    return token
  }

  /**
   * Returns an instance of the authenticated user. Or throws
   * an exception if the request is not authenticated.
   *
   * @throws {E_UNAUTHORIZED_ACCESS} When user is not authenticated
   *
   * @example
   * const user = guard.getUserOrFail()
   * console.log('User ID:', user.id)
   * console.log('Current token:', user.currentAccessToken.name)
   */
  getUserOrFail(): UserProvider[typeof PROVIDER_REAL_USER] & { currentAccessToken: AccessToken } {
    if (!this.user) {
      throw new E_UNAUTHORIZED_ACCESS('Unauthorized access', {
        guardDriverName: this.driverName,
      })
    }

    return this.user
  }

  /**
   * Authenticate the current HTTP request by verifying the bearer
   * token or fails with an exception
   *
   * @throws {E_UNAUTHORIZED_ACCESS} When authentication fails
   *
   * @example
   * try {
   *   const user = await guard.authenticate()
   *   console.log('Authenticated as:', user.email)
   *   console.log('Token abilities:', user.currentAccessToken.abilities)
   * } catch (error) {
   *   console.log('Authentication failed')
   * }
   */
  async authenticate(): Promise<
    UserProvider[typeof PROVIDER_REAL_USER] & { currentAccessToken: AccessToken }
  > {
    /**
     * Return early when authentication has already
     * been attempted
     */
    if (this.authenticationAttempted) {
      return this.getUserOrFail()
    }

    /**
     * Notify we begin to attempt the authentication
     */
    this.authenticationAttempted = true
    this.#emitter.emit('access_tokens_auth:authentication_attempted', {
      ctx: this.#ctx,
      guardName: this.#name,
    })

    /**
     * Decode token or fail when unable to do so
     */
    const bearerToken = new Secret(this.#getBearerToken())

    /**
     * Verify for token via the user provider
     */
    const token = await this.#userProvider.verifyToken(bearerToken)
    if (!token) {
      throw this.#authenticationFailed()
    }

    /**
     * Check if a user for the token exists. Otherwise abort
     * authentication
     */
    const providerUser = await this.#userProvider.findById(token.tokenableId)
    if (!providerUser) {
      throw this.#authenticationFailed()
    }

    /**
     * Update local state
     */
    this.isAuthenticated = true
    this.user = providerUser.getOriginal() as UserProvider[typeof PROVIDER_REAL_USER] & {
      currentAccessToken: AccessToken
    }
    this.user!.currentAccessToken = token

    /**
     * Notify
     */
    this.#emitter.emit('access_tokens_auth:authentication_succeeded', {
      ctx: this.#ctx,
      token,
      guardName: this.#name,
      user: this.user,
    })

    return this.user
  }

  /**
   * Create a token for a user (sign in)
   *
   * @param user - The user to create a token for
   * @param abilities - Optional array of abilities the token should have
   * @param options - Optional token configuration
   *
   * @example
   * const token = await guard.createToken(user, ['read', 'write'], {
   *   name: 'Mobile App',
   *   expiresIn: '7d'
   * })
   * console.log('Token:', token.value.release())
   */
  async createToken(
    user: UserProvider[typeof PROVIDER_REAL_USER],
    abilities?: string[],
    options?: {
      expiresIn?: string | number
      name?: string
    }
  ) {
    return await this.#userProvider.createToken(user, abilities, options)
  }

  /**
   * Invalidates the currently authenticated token (sign out)
   *
   * @example
   * await guard.invalidateToken()
   * console.log('Token invalidated successfully')
   */
  async invalidateToken() {
    const bearerToken = new Secret(this.#getBearerToken())
    return await this.#userProvider.invalidateToken(bearerToken)
  }

  /**
   * Returns the Authorization header clients can use to authenticate
   * the request.
   *
   * @param user - The user to authenticate as
   * @param abilities - Optional array of abilities
   * @param options - Optional token configuration
   *
   * @example
   * const clientAuth = await guard.authenticateAsClient(user, ['read'])
   * // Use clientAuth.headers.authorization in API tests
   */
  async authenticateAsClient(
    user: UserProvider[typeof PROVIDER_REAL_USER],
    abilities?: string[],
    options?: {
      expiresIn?: string | number
      name?: string
    }
  ): Promise<AuthClientResponse> {
    const token = await this.#userProvider.createToken(user, abilities, options)
    return {
      headers: {
        authorization: `Bearer ${token.value!.release()}`,
      },
    }
  }

  /**
   * Silently check if the user is authenticated or not. The
   * method is same as the "authenticate" method but does not
   * throw any exceptions.
   *
   * @example
   * const isAuthenticated = await guard.check()
   * if (isAuthenticated) {
   *   const user = guard.user
   *   console.log('User is authenticated:', user.email)
   * }
   */
  async check(): Promise<boolean> {
    try {
      await this.authenticate()
      return true
    } catch (error) {
      if (error instanceof E_UNAUTHORIZED_ACCESS) {
        return false
      }

      throw error
    }
  }
}
