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
import { RuntimeException } from '@adonisjs/core/exceptions'
import type { EmitterLike } from '@adonisjs/core/types/events'

import { E_UNAUTHORIZED_ACCESS } from '../../src/errors.ts'
import { type RememberMeToken } from './remember_me_token.ts'
import type { AuthClientResponse, GuardContract } from '../../src/types.ts'
import { GUARD_KNOWN_EVENTS, type PROVIDER_REAL_USER } from '../../src/symbols.ts'
import type {
  SessionGuardEvents,
  SessionGuardOptions,
  SessionUserProviderContract,
  SessionWithTokensUserProviderContract,
} from './types.ts'

/**
 * Session guard uses AdonisJS session store to track logged-in
 * user information.
 *
 * @template UseRememberTokens - Whether the guard supports remember me tokens
 * @template UserProvider - The user provider contract
 *
 * @example
 * const guard = new SessionGuard(
 *   'web',
 *   ctx,
 *   { useRememberMeTokens: true },
 *   emitter,
 *   userProvider
 * )
 *
 * const user = await guard.authenticate()
 * console.log('Authenticated user:', user.email)
 */
export class SessionGuard<
  UseRememberTokens extends boolean,
  UserProvider extends UseRememberTokens extends true
    ? SessionWithTokensUserProviderContract<unknown>
    : SessionUserProviderContract<unknown>,
> implements GuardContract<UserProvider[typeof PROVIDER_REAL_USER]> {
  /**
   * Events emitted by the guard
   */
  declare [GUARD_KNOWN_EVENTS]: SessionGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>

  /**
   * A unique name for the guard.
   */
  #name: string

  /**
   * Reference to the current HTTP context
   */
  #ctx: HttpContext

  /**
   * Options accepted by the session guard
   */
  #options: Required<SessionGuardOptions<UseRememberTokens>>

  /**
   * Provider to lookup user details
   */
  #userProvider: UserProvider

  /**
   * Emitter to emit events
   */
  #emitter: EmitterLike<SessionGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>>

  /**
   * Driver name of the guard
   */
  driverName: 'session' = 'session'

  /**
   * Whether or not the authentication has been attempted
   * during the current request.
   */
  authenticationAttempted = false

  /**
   * A boolean to know if a remember me token was used in attempt
   * to login a user.
   */
  attemptedViaRemember = false

  /**
   * A boolean to know if the current request has
   * been authenticated
   */
  isAuthenticated = false

  /**
   * A boolean to know if the current request is authenticated
   * using the "rememember_me" token.
   */
  viaRemember = false

  /**
   * Find if the user has been logged out during
   * the current request
   */
  isLoggedOut = false

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

  /**
   * The key used to store the logged-in user id inside
   * session
   *
   * @example
   * console.log('Session key:', guard.sessionKeyName) // 'auth_web'
   */
  get sessionKeyName() {
    return `auth_${this.#name}`
  }

  /**
   * The key used to store the remember me token cookie
   *
   * @example
   * console.log('Remember me key:', guard.rememberMeKeyName) // 'remember_web'
   */
  get rememberMeKeyName() {
    return `remember_${this.#name}`
  }

  /**
   * Creates a new SessionGuard instance
   *
   * @param name - Unique name for the guard instance
   * @param ctx - HTTP context for the current request
   * @param options - Configuration options for the session guard
   * @param emitter - Event emitter for guard events
   * @param userProvider - User provider for authentication
   *
   * @example
   * const guard = new SessionGuard(
   *   'web',
   *   ctx,
   *   { useRememberMeTokens: true, rememberMeTokensAge: '30d' },
   *   emitter,
   *   userProvider
   * )
   */
  constructor(
    name: string,
    ctx: HttpContext,
    options: SessionGuardOptions<UseRememberTokens>,
    emitter: EmitterLike<SessionGuardEvents<UserProvider[typeof PROVIDER_REAL_USER]>>,
    userProvider: UserProvider
  ) {
    this.#name = name
    this.#ctx = ctx
    this.#options = { rememberMeTokensAge: '2 years', ...options }
    this.#emitter = emitter
    this.#userProvider = userProvider
  }

  /**
   * Returns the session instance for the given request,
   * ensuring the property exists
   */
  #getSession() {
    if (!('session' in this.#ctx)) {
      throw new RuntimeException(
        'Cannot authenticate user. Install and configure "@adonisjs/session" package'
      )
    }

    return this.#ctx.session
  }

  /**
   * Emits authentication failure, updates the local state,
   * and returns an exception to end the authentication
   * cycle.
   */
  #authenticationFailed(sessionId: string) {
    this.isAuthenticated = false
    this.viaRemember = false
    this.user = undefined
    this.isLoggedOut = false

    const error = new E_UNAUTHORIZED_ACCESS('Invalid or expired user session', {
      guardDriverName: this.driverName,
    })

    this.#emitter.emit('session_auth:authentication_failed', {
      ctx: this.#ctx,
      guardName: this.#name,
      error,
      sessionId,
    })

    return error
  }

  /**
   * Emits the authentication succeeded event and updates
   * the local state to reflect successful authentication
   */
  #authenticationSucceeded(
    sessionId: string,
    user: UserProvider[typeof PROVIDER_REAL_USER],
    rememberMeToken?: RememberMeToken
  ) {
    this.isAuthenticated = true
    this.viaRemember = !!rememberMeToken
    this.user = user
    this.isLoggedOut = false

    this.#emitter.emit('session_auth:authentication_succeeded', {
      ctx: this.#ctx,
      guardName: this.#name,
      sessionId,
      user,
      rememberMeToken,
    })
  }

  /**
   * Emits the login succeeded event and updates the login
   * state
   */
  #loginSucceeded(
    sessionId: string,
    user: UserProvider[typeof PROVIDER_REAL_USER],
    rememberMeToken?: RememberMeToken
  ) {
    this.user = user
    this.isLoggedOut = false

    this.#emitter.emit('session_auth:login_succeeded', {
      ctx: this.#ctx,
      guardName: this.#name,
      sessionId,
      user,
      rememberMeToken,
    })
  }

  /**
   * Creates session for a given user by their user id.
   */
  #createSessionForUser(userId: string | number | BigInt) {
    const session = this.#getSession()
    session.put(this.sessionKeyName, userId)
    session.regenerate()
  }

  /**
   * Creates the remember me cookie
   */
  #createRememberMeCookie(value: Secret<string>) {
    this.#ctx.response.encryptedCookie(this.rememberMeKeyName, value.release(), {
      maxAge: this.#options.rememberMeTokensAge,
      httpOnly: true,
    })
  }

  /**
   * Authenticates the user using its id read from the session
   * store.
   *
   * - We check the user exists in the db
   * - If not, throw exception.
   * - Otherwise, update local state to mark the user as logged-in
   */
  async #authenticateViaId(userId: string | number | BigInt, sessionId: string) {
    const providerUser = await this.#userProvider.findById(userId)
    if (!providerUser) {
      throw this.#authenticationFailed(sessionId)
    }

    this.#authenticationSucceeded(sessionId, providerUser.getOriginal())
    return this.user!
  }

  /**
   * Authenticates user from the remember me cookie. Creates a fresh
   * session for them and recycles the remember me token as well.
   */
  async #authenticateViaRememberCookie(rememberMeCookie: string, sessionId: string) {
    /**
     * This method is only invoked when "options.useRememberTokens" is set to
     * true and hence the user provider will have methods to manage tokens
     */
    const userProvider = this.#userProvider as SessionWithTokensUserProviderContract<
      UserProvider[typeof PROVIDER_REAL_USER]
    >

    /**
     * Verify the token using the user provider.
     */
    const token = await userProvider.verifyRememberToken(new Secret(rememberMeCookie))
    if (!token) {
      throw this.#authenticationFailed(sessionId)
    }

    /**
     * Check if a user for the token exists. Otherwise abort
     * authentication
     */
    const providerUser = await userProvider.findById(token.tokenableId)
    if (!providerUser) {
      throw this.#authenticationFailed(sessionId)
    }

    /**
     * Recycle remember token and the remember me cookie
     */
    const recycledToken = await userProvider.recycleRememberToken(
      providerUser.getOriginal(),
      token.identifier,
      this.#options.rememberMeTokensAge
    )

    /**
     * Persist remember token inside the cookie
     */
    this.#createRememberMeCookie(recycledToken.value!)

    /**
     * Create session
     */
    this.#createSessionForUser(providerUser.getId())

    /**
     * Emit event and update local state
     */
    this.#authenticationSucceeded(sessionId, providerUser.getOriginal(), token)

    return this.user!
  }

  /**
   * Returns an instance of the authenticated user. Or throws
   * an exception if the request is not authenticated.
   */
  getUserOrFail(): UserProvider[typeof PROVIDER_REAL_USER] {
    if (!this.user) {
      throw new E_UNAUTHORIZED_ACCESS('Invalid or expired user session', {
        guardDriverName: this.driverName,
      })
    }

    return this.user
  }

  /**
   * Login user using sessions. Optionally, you can also create
   * a remember me token to automatically login user when their
   * session expires.
   */
  async login(user: UserProvider[typeof PROVIDER_REAL_USER], remember: boolean = false) {
    const session = this.#getSession()
    const providerUser = await this.#userProvider.createUserForGuard(user)

    this.#emitter.emit('session_auth:login_attempted', {
      ctx: this.#ctx,
      user,
      guardName: this.#name,
    })

    /**
     * Create remember me token and persist it with the provider
     * when remember me token is true.
     */
    let token: RememberMeToken | undefined
    if (remember) {
      if (!this.#options.useRememberMeTokens) {
        throw new RuntimeException('Cannot use "rememberMe" feature. It has been disabled')
      }

      /**
       * Here we assume the userProvider has implemented APIs to manage remember
       * me tokens, since the "useRememberMeTokens" flag is enabled.
       */
      const userProvider = this.#userProvider as SessionWithTokensUserProviderContract<
        UserProvider[typeof PROVIDER_REAL_USER]
      >

      token = await userProvider.createRememberToken(
        providerUser.getOriginal(),
        this.#options.rememberMeTokensAge
      )
    }

    /**
     * Persist remember token inside the cookie (if exists)
     * Otherwise remove the cookie
     */
    if (token) {
      this.#createRememberMeCookie(token.value!)
    } else {
      this.#ctx.response.clearCookie(this.rememberMeKeyName)
    }

    /**
     * Create session
     */
    this.#createSessionForUser(providerUser.getId())

    /**
     * Mark user as logged-in
     */
    this.#loginSucceeded(session.sessionId, providerUser.getOriginal(), token)
  }

  /**
   * Logout a user by removing its state from the session
   * store and delete the remember me cookie (if any).
   */
  async logout() {
    const session = this.#getSession()
    const rememberMeCookie = this.#ctx.request.encryptedCookie(this.rememberMeKeyName)

    /**
     * Clear client side state
     */
    session.forget(this.sessionKeyName)
    this.#ctx.response.clearCookie(this.rememberMeKeyName)

    /**
     * Delete remember me token when
     *
     * - Tokens are enabled
     * - A cookie exists
     * - And we know about the user already
     */
    if (this.user && rememberMeCookie && this.#options.useRememberMeTokens) {
      /**
       * Here we assume the userProvider has implemented APIs to manage remember
       * me tokens, since the "useRememberMeTokens" flag is enabled.
       */
      const userProvider = this.#userProvider as SessionWithTokensUserProviderContract<
        UserProvider[typeof PROVIDER_REAL_USER]
      >

      const token = await userProvider.verifyRememberToken(new Secret(rememberMeCookie))
      if (token) {
        await userProvider.deleteRemeberToken(this.user, token.identifier)
      }
    }

    /**
     * Notify the user has been logged out
     */
    this.#emitter.emit('session_auth:logged_out', {
      ctx: this.#ctx,
      guardName: this.#name,
      user: this.user || null,
      sessionId: session.sessionId,
    })

    /**
     * Update local state
     */
    this.user = undefined
    this.viaRemember = false
    this.isAuthenticated = false
    this.isLoggedOut = true
  }

  /**
   * Authenticate the current HTTP request by verifying the bearer
   * token or fails with an exception
   */
  async authenticate(): Promise<UserProvider[typeof PROVIDER_REAL_USER]> {
    /**
     * Return early when authentication has already been
     * attempted
     */
    if (this.authenticationAttempted) {
      return this.getUserOrFail()
    }

    /**
     * Notify we begin to attempt the authentication
     */
    this.authenticationAttempted = true
    const session = this.#getSession()

    this.#emitter.emit('session_auth:authentication_attempted', {
      ctx: this.#ctx,
      sessionId: session.sessionId,
      guardName: this.#name,
    })

    /**
     * Check if there is a user id inside the session store.
     * If yes, fetch the user from the persistent storage
     * and mark them as logged-in
     */
    const authUserId = session.get(this.sessionKeyName)
    if (authUserId) {
      return this.#authenticateViaId(authUserId, session.sessionId)
    }

    /**
     * If user provider supports remember me tokens and the remember me
     * cookie exists, then attempt to login + authenticate via
     * the remember me token.
     */
    const rememberMeCookie = this.#ctx.request.encryptedCookie(this.rememberMeKeyName)
    if (rememberMeCookie && this.#options.useRememberMeTokens) {
      this.attemptedViaRemember = true
      return this.#authenticateViaRememberCookie(rememberMeCookie, session.sessionId)
    }

    /**
     * Otherwise throw an exception
     */
    throw this.#authenticationFailed(session.sessionId)
  }

  /**
   * Silently check if the user is authenticated or not, without
   * throwing any exceptions
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

  /**
   * Returns the session info for the clients to send during
   * an HTTP request to mark the user as logged-in.
   */
  async authenticateAsClient(
    user: UserProvider[typeof PROVIDER_REAL_USER]
  ): Promise<AuthClientResponse> {
    const providerUser = await this.#userProvider.createUserForGuard(user)
    const userId = providerUser.getId()

    return {
      session: {
        [this.sessionKeyName]: userId,
      },
    }
  }
}
