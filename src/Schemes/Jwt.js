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
const jwt = require('jsonwebtoken')
const uuid = require('uuid')
const _ = require('lodash')
const util = require('util')
const GE = require('@adonisjs/generic-exceptions')

const CE = require('../Exceptions')
const BaseTokenScheme = require('./BaseToken')

const signToken = util.promisify(jwt.sign)
const verifyToken = util.promisify(jwt.verify)

/**
 * This scheme allows to make use of JWT tokens to authenticate the user.
 *
 * The user sends a token inside the `Authorization` header as following.
 *
 * ```
 * Authorization=Bearer JWT-TOKEN
 * ```
 *
 * ### Note
 * Token will be encrypted using `EncryptionProvider` before sending it to the user.
 *
 * @class JwtScheme
 * @extends BaseScheme
 */
class JwtScheme extends BaseTokenScheme {
  constructor (Encryption) {
    super(Encryption)
    this._generateRefreshToken = new Resetable(false)
  }

  /**
   * An object of jwt options directly
   * passed to `jsonwebtoken` library
   *
   * @attribute jwtOptions
   * @type {Object|Null}
   * @readOnly
   */
  get jwtOptions () {
    return _.get(this._config, 'options', null)
  }

  /**
   * The jwt secret
   *
   * @attribute jwtSecret
   * @type {String|Null}
   * @readOnly
   */
  get jwtSecret () {
    return _.get(this.jwtOptions, 'secret', null)
  }

  /**
   * The jwt public
   *
   * @attribute jwtPublic
   * @type {String|Null}
   * @readOnly
   */
  get jwtPublic () {
    return _.get(this.jwtOptions, 'public', null)
  }

  /**
   * Signs payload with jwtSecret using {{#crossLink "JwtScheme/jwtOptions:attribute"}}{{/crossLink}}
   *
   * @method _signToken
   * @async
   *
   * @param  {Object}   payload
   *
   * @returns  {String}
   *
   * @private
   */
  _signToken (payload, options) {
    options = _.size(options) && _.isPlainObject(options) ? options : _.omit(this.jwtOptions, ['secret', 'public'])
    return signToken(payload, this.jwtSecret, options)
  }

  /**
   * Verifies the jwt token by decoding it
   *
   * @method _verifyToken
   * @async
   *
   * @param  {String}     token
   *
   * @return {Object}
   *
   * @private
   */
  _verifyToken (token) {
    const options = _.omit(this.jwtOptions, ['secret', 'public'])
    const secretOrPublicKey = this.jwtPublic !== null ? this.jwtPublic : this.jwtSecret
    return verifyToken(token, secretOrPublicKey, options)
  }

  /**
   * Saves jwt refresh token for a given user
   *
   * @method _saveRefreshToken
   *
   * @param  {Object}          user
   *
   * @return {String}
   *
   * @private
   */
  async _saveRefreshToken (user) {
    const refreshToken = uuid.v4()
    await this._serializerInstance.saveToken(user, refreshToken, 'jwt_refresh_token')
    return refreshToken
  }

  /**
   * Instruct class to generate a refresh token
   * when generating the jwt token.
   *
   * @method withRefreshToken
   *
   * @chainable
   *
   * @example
   * ```js
   * await auth
   *   .withRefreshToken()
   *   .generate(user)
   *
   * // or
   * await auth
   *   .withRefreshToken()
   *   .attempt(username, password)
   * ```
   */
  withRefreshToken () {
    this._generateRefreshToken.set(true)
    return this
  }

  /**
   * When issuing a new JWT token from the refresh token, this class will
   * re-use the old refresh token.
   *
   * If you want, you can instruct the class to generate a new refresh token
   * as well and remove the existing one from the DB.
   *
   * @method newRefreshToken
   *
   * @chainable
   *
   * @example
   * ```js
   * await auth
   *   .newRefreshToken()
   *   .generateForRefreshToken(token)
   * ```
   */
  newRefreshToken () {
    return this.withRefreshToken()
  }

  /**
   * Attempt to valid the user credentials and then generate a JWT token.
   *
   * @method attempt
   * @async
   *
   * @param  {String} uid
   * @param  {String} password
   * @param  {Object|Boolean} [jwtPayload]  Pass true when want to attach user object in the payload
   *                                        or set a custom object.
   * @param  {Object}         [jwtOptions]  Passed directly to https://www.npmjs.com/package/jsonwebtoken
   *
   * @return {Object}
   * - `{ type: 'bearer', token: 'xxxx', refreshToken: 'xxxx' }`
   *
   * @example
   * ```js
   * try {
   *   const token = auth.attempt(username, password)
   * } catch (error) {
   *    // Invalid credentials
   * }
   * ```
   *
   * Attach user to the JWT payload
   * ```
   * auth.attempt(username, password, true)
   * ```
   *
   * Attach custom data object to the JWT payload
   * ```
   * auth.attempt(username, password, { ipAddress: '...' })
   * ```
   */
  async attempt (uid, password, jwtPayload, jwtOptions) {
    const user = await this.validate(uid, password, true)
    return this.generate(user, jwtPayload, jwtOptions)
  }

  /**
   * Generates a jwt token for a given user. This method doesn't check the existence
   * of the user in the database.
   *
   * @method generate
   * @async
   *
   * @param  {Object} user
   * @param  {Object|Boolean} [jwtPayload]  Pass true when want to attach user object in the payload
   *                                        or set a custom object.
   * @param  {Object}         [jwtOptions]  Passed directly to https://www.npmjs.com/package/jsonwebtoken
   *
   * @return {Object}
   * - `{ type: 'bearer', token: 'xxxx', refreshToken: 'xxxx' }`
   *
   * @throws {RuntimeException} If jwt secret is not defined or user doesn't have a primary key value
   *
   * @example
   * ```js
   * try {
   *   await auth.generate(user)
   * } catch (error) {
   *   // Unexpected error
   * }
   * ```
   *
   * Attach user to the JWT payload
   * ```
   * auth.auth.generate(user, true)
   * ```
   *
   * Attach custom data object to the JWT payload
   * ```
   * auth.generate(user, { ipAddress: '...' })
   * ```
   */
  async generate (user, jwtPayload, jwtOptions) {
    /**
     * Throw exception when trying to generate token without
     * jwt secret
     */
    if (!this.jwtSecret) {
      throw GE.RuntimeException.incompleteConfig(['secret'], 'config/auth.js', 'jwt')
    }

    /**
     * Throw exception when user is not persisted to
     * database
     */
    const userId = user[this.primaryKey]
    if (!userId) {
      throw GE.RuntimeException.invoke('Primary key value is missing for user')
    }

    /**
     * The jwt payload
     *
     * @type {Object}
     */
    const payload = { uid: userId }

    if (jwtPayload === true) {
      /**
       * Attach user as data object only when
       * jwtPayload is true
       */
      const data = typeof (user.toJSON) === 'function' ? user.toJSON() : user

      /**
       * Remove password from jwt data
       */
      payload.data = _.omit(data, this._config.password)
    } else if (_.isPlainObject(jwtPayload)) {
      /**
       * Attach payload as it is when it's an object
       */
      payload.data = jwtPayload
    }

    /**
     * Return the generate token
     */
    const token = await this._signToken(payload, jwtOptions)
    const withRefresh = this._generateRefreshToken.pull()
    const plainRefreshToken = withRefresh ? await this._saveRefreshToken(user) : null

    /**
     * Encrypting the token before giving it to the
     * user.
     */
    const refreshToken = plainRefreshToken ? this.Encryption.encrypt(plainRefreshToken) : null

    return { type: 'bearer', token, refreshToken }
  }

  /**
   * Generate a new JWT token using the refresh token.
   *
   * If chained with {{#crossLink "JwtScheme/newRefreshToken"}}{{/crossLink}},
   * this method will remove the existing refresh token from database and issues a new one.
   *
   * @method generateForRefreshToken
   * @async
   *
   * @param {String} refreshToken
   * @param  {Object|Boolean} [jwtPayload]  Pass true when want to attach user object in the payload
   *                                        or set a custom object.
   * @param  {Object}         [jwtOptions]  Passed directly to https://www.npmjs.com/package/jsonwebtoken
   *
   * @return {Object}
   * - `{ type: 'bearer', token: 'xxxx', refreshToken: 'xxxx' }`
   *
   * @example
   * ```js
   * await auth.generateForRefreshToken(refreshToken)
   *
   * // create a new refresh token too
   * await auth
   *   .newRefreshToken()
   *   .generateForRefreshToken(refreshToken)
   * ```
   */
  async generateForRefreshToken (refreshToken, jwtPayload, jwtOptions) {
    const user = await this._serializerInstance.findByToken(this.Encryption.decrypt(refreshToken), 'jwt_refresh_token')
    if (!user) {
      throw CE.InvalidRefreshToken.invoke(refreshToken)
    }

    const token = await this.generate(user, jwtPayload, jwtOptions)

    /**
     * If user generated a new refresh token, in that case we
     * should revoke the old one, otherwise we should
     * set the refreshToken as the existing refresh
     * token in the return payload
     */
    if (!token.refreshToken) {
      token.refreshToken = refreshToken
    } else {
      await this.revokeTokensForUser(user, [refreshToken], true)
    }

    return token
  }

  /**
   * Check if user is authenticated for the current HTTP request or not. This
   * method will read the token from the `Authorization` header or fallbacks
   * to the `token` input field.
   *
   * Consider user as successfully authenticated, if this
   * method doesn't throws an exception.
   *
   * @method check
   * @async
   *
   * @return {Boolean}
   *
   * @example
   * ```js
   * try {
   *   await auth.check()
   * } catch (error) {
   *   // invalid jwt token
   * }
   * ```
   */
  async check () {
    if (this.user) {
      return true
    }

    const token = this.getAuthHeader()

    /**
     * Verify jwt token and wrap exception inside custom
     * exception classes
     */
    try {
      this.jwtPayload = await this._verifyToken(token)
    } catch ({ name, message }) {
      if (name === 'TokenExpiredError') {
        throw CE.ExpiredJwtToken.invoke()
      }
      throw CE.InvalidJwtToken.invoke(message)
    }

    this.user = await this._serializerInstance.findById(this.jwtPayload.uid)

    /**
     * Throw exception when user is not found
     */
    if (!this.user) {
      throw CE.InvalidJwtToken.invoke()
    }

    return true
  }

  /**
   * Same as {{#crossLink "JwtScheme/check:method"}}{{/crossLink}},
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

    const token = this.getAuthHeader()

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
   * List all refresh tokens for a given user.
   *
   * @method listTokensForUser
   * @async
   *
   * @param  {Object} user
   *
   * @return {Array}
   */
  async listTokensForUser (user) {
    if (!user) {
      return []
    }

    const tokens = await this._serializerInstance.listTokens(user, 'jwt_refresh_token')
    return tokens.toJSON().map((token) => {
      token.token = this.Encryption.encrypt(token.token)
      return token
    })
  }

  /**
   * Login a user as a client. This method will set the
   * JWT token as a header on the request.
   *
   * @param  {Function}    headerFn     - Method to set the header
   * @param  {Function}    sessionFn    - Method to set the session
   * @param  {Object}      user         - User to login
   * @param  {Object}      [jwtOptions] - Passed directly to https://www.npmjs.com/package/jsonwebtoken
   *
   * @method clientLogin
   * @async
   *
   * @return {void}
   */
  async clientLogin (headerFn, sessionFn, user) {
    const { token } = await this.generate(user)
    headerFn('authorization', `Bearer ${token}`)
  }
}

module.exports = JwtScheme
