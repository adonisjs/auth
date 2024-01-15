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

import { E_UNAUTHORIZED_ACCESS } from '../../src/errors.js'
import type { AuthClientResponse, GuardContract } from '../../src/types.js'
import { GUARD_KNOWN_EVENTS, PROVIDER_REAL_USER } from '../../src/symbols.js'
import type { AccessTokensGuardEvents, AccessTokensUserProviderContract } from './types.js'

/**
 * Implementation of access tokens guard for the Auth layer. The heavy lifting
 * of verifying tokens is done by the user provider. However, the guard is
 * used to seamlessly integrate with the auth layer of the package.
 */
export class AccessTokensGuard<UserProvider extends AccessTokensUserProviderContract<unknown>>
  implements GuardContract<UserProvider[typeof PROVIDER_REAL_USER]>
{
  /**
   * Events emitted by the guard
   */
  declare [GUARD_KNOWN_EVENTS]: AccessTokensGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>

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
  #emitter: EmitterLike<AccessTokensGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>>

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
  user?: UserProvider[typeof PROVIDER_REAL_USER]

  constructor(
    name: string,
    ctx: HttpContext,
    emitter: EmitterLike<AccessTokensGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>>,
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
    const [, token] = bearerToken.split('Bearer ')
    if (!token) {
      throw this.#authenticationFailed()
    }

    return token
  }

  /**
   * Returns an instance of the authenticated user. Or throws
   * an exception if the request is not authenticated.
   */
  getUserOrFail(): UserProvider[typeof PROVIDER_REAL_USER] {
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
   */
  async authenticate(): Promise<UserProvider[typeof PROVIDER_REAL_USER]> {
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
    this.user = providerUser.getOriginal()

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
   * Returns the Authorization header clients can use to authenticate
   * the request.
   */
  async authenticateAsClient(
    _: UserProvider[typeof PROVIDER_REAL_USER]
  ): Promise<AuthClientResponse> {
    throw new Error('Not supported')
  }

  /**
   * Silently check if the user is authenticated or not. The
   * method is same the "authenticate" method but does not
   * throw any exceptions.
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
