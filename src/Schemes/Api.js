'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const uuid = require('uuid')
const GE = require('@adonisjs/generic-exceptions')

const BaseTokenScheme = require('./BaseToken')
const CE = require('../Exceptions')

/**
 * This scheme allows to make use of Github style personal API tokens
 * to authenticate a user.
 *
 * The tokens for a give user are stored inside the database and user sends
 * a token inside the `Authorization` header or custom header if present from config as following.
 *
 * ```
 * Authorization=Bearer TOKEN
 * ```
 *
 * With custom header config:
 *
 * ```
 * CustomHeader=Bearer TOKEN
 * ```
 *
 * ### Note
 * Token will be encrypted using `EncryptionProvider` before sending it to the user.
 *
 * @class ApiScheme
 * @extends BaseScheme
 */
class ApiScheme extends BaseTokenScheme {
  /**
   * Attempt to valid the user credentials and then
   * generates a new token for it.
   *
   * This method invokes the `generate` method by passing
   * the user found with given credentials.
   *
   * @method attempt
   * @async
   *
   * @param  {String} uid
   * @param  {String} password
   *
   * @return {Object}
   *
   * @example
   * ```js
   * try {
   *   const token = auth.attempt(username, password)
   * } catch (error) {
   *   // Invalid credentials
   * }
   * ```
   */
  async attempt (uid, password) {
    const user = await this.validate(uid, password, true)
    return this.generate(user)
  }

  /**
   * Generates a personal API token for a user. The user payload must
   * be valid as per the serializer in use.
   *
   * @method generate
   * @async
   *
   * @param  {Object} user
   *
   * @return {Object}
   * - `{ type: 'bearer', token: 'xxxxxxxx' }`
   *
   * @example
   * ```js
   * try {
   *   const user = await User.find(1)
   *   const token = await auth.generate(user)
   * } catch (error) {
   *   // Unexpected error
   * }
   * ```
   */
  async generate (user) {
    /**
     * Throw exception when user is not persisted to
     * database
     */
    const userId = user[this.primaryKey]
    if (!userId) {
      throw GE.RuntimeException.invoke('Primary key value is missing for user')
    }

    const plainToken = uuid.v4().replace(/-/g, '')
    await this._serializerInstance.saveToken(user, plainToken, 'api_token')

    /**
     * Encrypting the token before giving it to the
     * user.
     */
    const token = this.Encryption.encrypt(plainToken)
    return { type: 'bearer', token }
  }

  /**
   * Validates the API token by reading it from the request
   * header or using `token` input field as the fallback.
   *
   * Consider user as successfully authenticated, if this
   * method doesn't throws an exception.
   *
   * @method check
   * @async
   *
   * @return {void}
   *
   * @throws {InvalidApiToken} If token is missing or is invalid
   *
   * @example
   * ```js
   * try {
   *   await auth.check()
   * } catch (error) {
   *   // Invalid token
   * }
   * ```
   */
  async check () {
    /**
     * User already exists for this request, so there is
     * no need to re-pull them from the database
     */
    if (this.user) {
      return true
    }

    const token = this.getAuthHeader(['bearer', 'token'])
    if (!token) {
      throw CE.InvalidApiToken.invoke()
    }

    /**
     * Decrypting the token before querying
     * the db.
     */
    const plainToken = this.Encryption.decrypt(token)
    this.user = await this._serializerInstance.findByToken(plainToken, 'api_token')

    /**
     * Throw exception when user is not found
     */
    if (!this.user) {
      throw CE.InvalidApiToken.invoke()
    }

    return true
  }

  /**
   * Same as {{#crossLink "ApiScheme/check:method"}}{{/crossLink}},
   * but doesn't throw any exceptions. This method is useful for
   * routes, where login is optional.
   *
   * @method loginIfCan
   * @async
   *
   * @return {Boolean}
   *
   * @example
   * ```js
 *   await auth.loginIfCan()
   * ```
   */
  async loginIfCan () {
    if (this.user) {
      return true
    }

    const token = this.getAuthHeader(['bearer', 'token'])

    /**
     * Do not attempt to check, when token itself is missing
     */
    if (!token) {
      return false
    }

    try {
      return await this.check()
    } catch (error) {
      return false
      // swallow exception
    }
  }

  /**
   * List all API tokens for a given user
   *
   * @method listTokensForUser
   * @async
   *
   * @param {Object} user
   *
   * @return {Array}
   */
  async listTokensForUser (user) {
    if (!user) {
      return []
    }

    const tokens = await this._serializerInstance.listTokens(user, 'api_token')
    return tokens.toJSON().map((token) => {
      token.token = this.Encryption.encrypt(token.token)
      return token
    })
  }

  /**
   * Login a user as a client. This method will set the
   * API token as a header on the request.
   *
   * Adonis testing engine uses this method.
   *
   * @method clientLogin
   * @async
   *
   * @param  {Function}    headerFn       - Method to set the header
   * @param  {Function}    sessionFn      - Method to set the session
   * @param  {Object}      tokenOrUser    - Pass the token or the user directly
   *
   * @return {void}
   */
  async clientLogin (headerFn, sessionFn, tokenOrUser) {
    if (typeof (tokenOrUser) !== 'string') {
      const { token } = await this.generate(tokenOrUser)
      tokenOrUser = token
    }
    headerFn(this.headerKey, `Bearer ${tokenOrUser}`)
  }
}

module.exports = ApiScheme
