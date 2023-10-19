/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { Exception } from '@poppinss/utils'
import { string } from '@poppinss/utils/build/helpers'
import { EmitterContract } from '@ioc:Adonis/Core/Event'
import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'

import {
  UserProviderContract,
  SessionGuardConfig,
  SessionGuardContract,
  ProviderUserContract,
  SessionLoginEventData,
  SessionAuthenticateEventData,
} from '@ioc:Adonis/Addons/Auth'

import { BaseGuard } from '../Base'
import { AuthenticationException } from '../../Exceptions/AuthenticationException'

/**
 * Session guard enables user login using sessions. Also it allows for
 * setting remember me tokens for life long login
 */
export class SessionGuard extends BaseGuard<any> implements SessionGuardContract<any, any> {
  constructor(
    name: string,
    config: SessionGuardConfig<any>,
    private emitter: EmitterContract,
    provider: UserProviderContract<any>,
    private ctx: HttpContextContract
  ) {
    super(name, config, provider)
  }

  /**
   * Number of years for the remember me token expiry
   */
  private rememberMeTokenExpiry = '5y'

  /**
   * The name of the session key name
   */
  public get sessionKeyName() {
    return `auth_${this.name}`
  }

  /**
   * The name of the session key name
   */
  public get rememberMeKeyName() {
    return `remember_${this.name}`
  }

  /**
   * Returns the session object from the context.
   */
  private getSession() {
    if (!this.ctx.session) {
      throw new Exception('"@adonisjs/session" is required to use the "session" auth driver')
    }
    return this.ctx.session
  }

  /**
   * Set the user id inside the session. Also forces the session module
   * to re-generate the session id
   */
  private setSession(userId: string | number) {
    this.getSession().put(this.sessionKeyName, userId)
    this.getSession().regenerate()
  }

  /**
   * Generate remember me token
   */
  private generateRememberMeToken(): string {
    return string.generateRandom(20)
  }

  /**
   * Sets the remember me cookie with the remember me token
   */
  private setRememberMeCookie(userId: string | number, token: string) {
    const value = {
      id: userId,
      token: token,
    }

    this.ctx.response.encryptedCookie(this.rememberMeKeyName, value, {
      maxAge: this.rememberMeTokenExpiry,
    })
  }

  /**
   * Clears the remember me cookie
   */
  private clearRememberMeCookie() {
    this.ctx.response.clearCookie(this.rememberMeKeyName)
  }

  /**
   * Clears user session and remember me cookie
   */
  private clearUserFromStorage() {
    this.getSession().forget(this.sessionKeyName)
    this.clearRememberMeCookie()
  }

  /**
   * Returns data packet for the login event. Arguments are
   *
   * - The mapping identifier
   * - Logged in user
   * - HTTP context
   * - Remember me token (optional)
   */
  private getLoginEventData(user: any, token: string | null): SessionLoginEventData<any> {
    return {
      name: this.name,
      ctx: this.ctx,
      user,
      token,
    }
  }

  /**
   * Returns data packet for the authenticate event. Arguments are
   *
   * - The mapping identifier
   * - Logged in user
   * - HTTP context
   * - A boolean to tell if logged in viaRemember or not
   */
  private getAuthenticateEventData(
    user: any,
    viaRemember: boolean
  ): SessionAuthenticateEventData<any> {
    return {
      name: this.name,
      ctx: this.ctx,
      user,
      viaRemember,
    }
  }

  /**
   * Returns the user id for the current HTTP request
   */
  private getRequestSessionId() {
    return this.getSession().get(this.sessionKeyName)
  }

  /**
   * Verifies the remember me token
   */
  private verifyRememberMeToken(
    rememberMeToken: any
  ): asserts rememberMeToken is { id: string; token: string } {
    if (!rememberMeToken || !rememberMeToken.id || !rememberMeToken.token) {
      throw AuthenticationException.invalidSession(this.name)
    }
  }

  /**
   * Returns user from the user session id
   */
  private async getUserForSessionId(id: string | number) {
    const authenticatable = await this.provider.findById(id)
    if (!authenticatable.user) {
      throw AuthenticationException.invalidSession(this.name)
    }

    return authenticatable
  }

  /**
   * Returns user for the remember me token
   */
  private async getUserForRememberMeToken(id: string, token: string) {
    const authenticatable = await this.provider.findByRememberMeToken(id, token)
    if (!authenticatable.user) {
      throw AuthenticationException.invalidSession(this.name)
    }

    return authenticatable
  }

  /**
   * Returns the remember me token of the user that is persisted
   * inside the db. If not persisted, we create one and persist
   * it
   */
  private async getPersistedRememberMeToken(
    providerUser: ProviderUserContract<any>
  ): Promise<string> {
    /**
     * Create and persist the user remember me token, when an existing one is missing
     */
    if (!providerUser.getRememberMeToken()) {
      this.ctx.logger.trace('generating fresh remember me token')
      providerUser.setRememberMeToken(this.generateRememberMeToken())
      await this.provider.updateRememberMeToken(providerUser)
    }

    return providerUser.getRememberMeToken()!
  }

  /**
   * Verify user credentials and perform login
   */
  public async attempt(uid: string, password: string, remember?: boolean): Promise<any> {
    const user = await this.verifyCredentials(uid, password)
    await this.login(user, remember)
    return user
  }

  /**
   * Login user using their id
   */
  public async loginViaId(id: string | number, remember?: boolean): Promise<void> {
    const providerUser = await this.findById(id)
    await this.login(providerUser.user, remember)
    return providerUser.user
  }

  /**
   * Login a user
   */
  public async login(user: any, remember?: boolean): Promise<void> {
    /**
     * Since the login method is exposed to the end user, we cannot expect
     * them to instantiate and return an instance of authenticatable, so
     * we create one manually.
     */
    const providerUser = await this.getUserForLogin(user, this.config.provider.identifierKey)

    /**
     * getUserForLogin raises exception when id is missing, so we can
     * safely assume it is defined
     */
    const id = providerUser.getId()!

    /**
     * Set session
     */
    this.setSession(id)

    /**
     * Set remember me token when enabled
     */
    if (remember) {
      const rememberMeToken = await this.getPersistedRememberMeToken(providerUser)
      this.ctx.logger.trace('setting remember me cookie', { name: this.rememberMeKeyName })
      this.setRememberMeCookie(id, rememberMeToken)
    } else {
      /**
       * Clear remember me cookie, which may have been set previously.
       */
      this.clearRememberMeCookie()
    }

    /**
     * Emit login event. It can be used to track user logins and their devices.
     */
    this.emitter.emit(
      'adonis:session:login',
      this.getLoginEventData(providerUser.user, providerUser.getRememberMeToken())
    )

    this.markUserAsLoggedIn(providerUser.user)
    return providerUser.user
  }

  /**
   * Authenticates the current HTTP request by checking for the user
   * session.
   */
  public async authenticate(): Promise<any> {
    if (this.authenticationAttempted) {
      return this.user
    }

    this.authenticationAttempted = true
    const sessionId = this.getRequestSessionId()

    /**
     * If session id exists, then attempt to login the user using the
     * session and return early
     */
    if (sessionId) {
      const providerUser = await this.getUserForSessionId(sessionId)
      this.markUserAsLoggedIn(providerUser.user, true)
      this.emitter.emit(
        'adonis:session:authenticate',
        this.getAuthenticateEventData(providerUser.user, false)
      )
      return this.user
    }

    /**
     * Otherwise look for remember me token. Raise exception, if both remember
     * me token and session id are missing.
     */
    const rememberMeToken = this.ctx.request.encryptedCookie(this.rememberMeKeyName)
    if (!rememberMeToken) {
      throw AuthenticationException.invalidSession(this.name)
    }

    /**
     * Ensure remember me token is valid after reading it from the cookie
     */
    this.verifyRememberMeToken(rememberMeToken)

    /**
     * Attempt to locate the user for remember me token
     */
    const providerUser = await this.getUserForRememberMeToken(
      rememberMeToken.id,
      rememberMeToken.token
    )
    this.setSession(providerUser.getId()!)
    this.setRememberMeCookie(rememberMeToken.id, rememberMeToken.token)

    this.markUserAsLoggedIn(providerUser.user, true, true)
    this.emitter.emit(
      'adonis:session:authenticate',
      this.getAuthenticateEventData(providerUser.user, true)
    )
    return this.user
  }

  /**
   * Same as [[authenticate]] but returns a boolean over raising exceptions
   */
  public async check(): Promise<boolean> {
    try {
      await this.authenticate()
    } catch (error) {
      /**
       * Throw error when it is not an instance of the authentication
       */
      if (error instanceof AuthenticationException === false) {
        throw error
      }

      this.ctx.logger.trace(error, 'Authentication failure')
    }

    return this.isAuthenticated
  }

  /**
   * Logout by clearing session and cookies
   */
  public async logout(recycleRememberToken?: boolean) {
    /**
     * Return early when not attempting to re-generate the remember me token
     */
    if (!recycleRememberToken) {
      this.clearUserFromStorage()
      this.markUserAsLoggedOut()
      return
    }

    /**
     * Attempt to authenticate the current request if not already authenticated. This
     * will help us get an instance of the current user
     */
    if (!this.authenticationAttempted) {
      await this.check()
    }

    /**
     * If authentication passed, then re-generate the remember me token
     * for the current user.
     */
    if (this.user) {
      const providerUser = await this.provider.getUserFor(this.user)

      this.ctx.logger.trace('re-generating remember me token')
      providerUser.setRememberMeToken(this.generateRememberMeToken())
      await this.provider.updateRememberMeToken(providerUser)
    }

    /**
     * Logout user
     */
    this.clearUserFromStorage()
    this.markUserAsLoggedOut()
  }

  /**
   * Serialize toJSON for JSON.stringify
   */
  public toJSON() {
    return {
      isLoggedIn: this.isLoggedIn,
      isGuest: this.isGuest,
      viaRemember: this.viaRemember,
      authenticationAttempted: this.authenticationAttempted,
      isAuthenticated: this.isAuthenticated,
      user: this.user,
    }
  }
}
