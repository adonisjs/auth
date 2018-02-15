'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const Resetable = require('resetable')
const ms = require('ms')
const uuid = require('uuid')
const GE = require('@adonisjs/generic-exceptions')

const BaseScheme = require('./Base')
const CE = require('../Exceptions')

/**
 * This scheme allows to make use of `sessions` to authenticate
 * a user.
 *
 * The authentication is stateful and logged in user `id` is saved inside
 * cookies to maintain the state across multiple requests.
 *
 * @class SessionScheme
 * @extends BaseScheme
 */
class SessionScheme extends BaseScheme {
  constructor () {
    super()
    this._rememberTokenDuration = new Resetable(0)
  }

  /**
   * Reference to the value of `sessionKey` inside the config block.
   * Defaults to `adonis-auth`
   *
   * @attribute sessionKey
   * @readOnly
   * @return {String}
   */
  get sessionKey () {
    return this._config.sessionKey || 'adonis-auth'
  }

  /**
   * Reference to the value of `rememberMeToken` inside the config block.
   * Defaults to `adonis-remember-token`
   *
   * @attribute rememberTokenKey
   * @readOnly
   * @return {String}
   */
  get rememberTokenKey () {
    return this._config.rememberMeToken || 'adonis-remember-token'
  }

  /**
   * Set authentication session on user instance. Remember me cookie
   * will be saved if `rememberToken` and `duration` are provided.
   *
   * @method _setSession
   *
   * @param  {Number|String}    primaryKeyValue
   * @param  {String}           [rememberToken]
   * @param  {Number}           [duration]
   *
   * @returns {void}
   *
   * @private
   */
  _setSession (primaryKeyValue, rememberToken, duration) {
    this._ctx.session.put(this.sessionKey, primaryKeyValue)

    /**
     * Set remember me cookie when token and duration is
     * defined
     */
    if (rememberToken && duration) {
      this._ctx.response.cookie(this.rememberTokenKey, rememberToken, {
        expires: new Date(Date.now() + duration)
      })
    }
  }

  /**
   * Removes the login session and remember me cookie.
   *
   * @method _removeSession
   *
   * @return {void}
   *
   * @private
   */
  _removeSession () {
    this._ctx.session.forget(this.sessionKey)
    this._ctx.response.clearCookie(this.rememberTokenKey)
  }

  /**
   * Instruct login API to remember the user for a given
   * duration. Defaults to `5years`.
   *
   * This method must be called before `login`, `loginViaId` or
   * `attempt` method.
   *
   * @method remember
   *
   * @param  {String|Number} [duration = 5y]
   *
   * @chainable
   *
   * @example
   * ```js
   * await auth.remember(true).login()
   *
   * // custom durating
   * await auth.remember('2y').login()
   * ```
   */
  remember (duration) {
    if (duration === true || duration === 1) {
      this._rememberTokenDuration.set(ms('5y'))
    } else if (typeof (duration) === 'string') {
      this._rememberTokenDuration.set(ms(duration))
    } else if (duration !== 0 && duration !== false) {
      this._rememberTokenDuration.set(duration)
    }
    return this
  }

  /**
   * Attempt to login the user using `username` and `password`. An
   * exception will be raised when unable to find the user or
   * if password mis-matches.
   *
   * @method attempt
   * @async
   *
   * @param  {String} uid
   * @param  {String} password
   *
   * @return {Object}
   *
   * @throws {UserNotFoundException}     If unable to find user with uid
   * @throws {PasswordMisMatchException} If password mismatches
   *
   * @example
   * ```js
   * try {
   *   await auth.attempt(username, password)
   * } catch (error) {
   *   // Invalid credentials
   * }
   * ```
   */
  async attempt (uid, password) {
    const user = await this.validate(uid, password, true)
    return this.login(user)
  }

  /**
   * Login the user using the user object. An exception will be
   * raised if the same user is already logged in.
   *
   * The exception is raised to improve your code flow, since your code
   * should never try to login a same user twice.
   *
   * @method login
   *
   * @param  {Object} user
   * @async
   *
   * @return {Object}
   *
   * @example
   * ```js
   * try {
   *   await auth.login(user)
   * } catch (error) {
   *   // Unexpected error
   * }
   * ```
   */
  async login (user) {
    if (this.user) {
      throw GE
        .RuntimeException
        .invoke('Cannot login multiple users at once, since a user is already logged in', 500, 'E_CANNOT_LOGIN')
    }

    this.user = user

    /**
     * Make sure primary key value exists.
     */
    if (!this.primaryKeyValue) {
      throw GE
        .RuntimeException
        .invoke('Cannot login user, since user id is not defined', 500, 'E_CANNOT_LOGIN')
    }

    /**
     * Set user remember token when remember token
     * duration is defined.
     */
    const duration = this._rememberTokenDuration.pull()
    const rememberToken = duration ? uuid.v4() : null
    if (rememberToken) {
      await this._serializerInstance.saveToken(user, rememberToken, 'remember_token')
    }

    this._setSession(this.primaryKeyValue, rememberToken, duration)
    return user
  }

  /**
   * Login a user with their unique id.
   *
   * @method loginViaId
   * @async
   *
   * @param  {Number|String}   id
   *
   * @return {Object}
   *
   * @throws {UserNotFoundException}     If unable to find user with id
   *
   * @example
   * ```js
   * try {
   *   await auth.loginViaId(1)
   * } catch (error) {
   *   // Unexpected error
   * }
   * ```
   */
  async loginViaId (id) {
    const user = await this._serializerInstance.findById(id)
    if (!user) {
      throw this.missingUserFor(id, this.primaryKey)
    }

    return this.login(user)
  }

  /**
   * Logout a user by removing the required cookies. Also remember
   * me token will be deleted from the tokens table.
   *
   * @method logout
   * @async
   *
   * @return {void}
   *
   * @example
   * ```js
   * await auth.logout()
   * ```
   */
  async logout () {
    if (this.user) {
      const rememberMeToken = this._ctx.request.cookie(this.rememberTokenKey)
      if (rememberMeToken) {
        await this._serializerInstance.deleteTokens(this.user, [rememberMeToken])
      }
      this.user = null
    }
    this._removeSession()
  }

  /**
   * Check whether the user is logged in or not. If the user session
   * has been expired, but a valid `rememberMe` token exists, this
   * method will re-login the user.
   *
   * @method check
   * @async
   *
   * @return {Boolean}
   *
   * @throws {InvalidSessionException} If session is not valid anymore
   *
   * @example
   * ```js
   * try {
   *   await auth.check()
   * } catch (error) {
   *   // user is not logged
   * }
   * ```
   */
  async check () {
    if (this.user) {
      return true
    }

    const sessionValue = this._ctx.session.get(this.sessionKey)
    const rememberMeToken = this._ctx.request.cookie(this.rememberTokenKey)

    /**
     * Look for user only when there is a session
     * cookie
     */
    if (sessionValue) {
      this.user = await this._serializerInstance.findById(sessionValue)
    }

    /**
     * If got user then return
     */
    if (this.user) {
      return true
    }

    /**
     * Attempt to login the user when remeber me
     * token exists
     */
    if (rememberMeToken) {
      const user = await this._serializerInstance.findByToken(rememberMeToken, 'remember_token')
      if (user) {
        await this.login(user)
        return true
      }
    }

    throw CE.InvalidSessionException.invoke()
  }

  /**
   * Same as {{#crossLink "SessionScheme/check:method"}}{{/crossLink}},
   * but doesn't throw any exceptions. This method is useful for
   * routes, where login is optional.
   *
   * @method loginIfCan
   * @async
   *
   * @return {void}
   *
   * @example
   * ```js
 *   await auth.loginIfCan()
   * ```
   */
  async loginIfCan () {
    if (this.user) {
      return
    }

    /**
     * Don't do anything when there is no session
     */
    const sessionValue = this._ctx.session.get(this.sessionKey)
    const rememberMeToken = this._ctx.request.cookie(this.rememberTokenKey)

    /**
     * Don't attempt for anything when there is no session
     * value and no remember token
     */
    if (!sessionValue && !rememberMeToken) {
      return
    }

    try {
      return await this.check()
    } catch (error) {
      // swallow exception
    }
  }

  /**
   * Login a user as a client. This is required when
   * you want to set the session on a request that
   * will reach the Adonis server.
   *
   * Adonis testing engine uses this method.
   *
   * @method clientLogin
   * @async
   *
   * @param  {Function}    headerFn     - Method to set the header
   * @param  {Function}    sessionFn    - Method to set the session
   * @param  {Object}      user         - User to login
   *
   * @return {void}
   */
  clientLogin (headerFn, sessionFn, user) {
    if (!user[this.primaryKey]) {
      throw new Error(`Cannot login user, since value for ${this.primaryKey} is missing`)
    }

    /**
     * Call the client method to set the session
     */
    sessionFn(this.sessionKey, user[this.primaryKey])
  }
}

module.exports = SessionScheme
