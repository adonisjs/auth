'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const GE = require('@adonisjs/generic-exceptions')
const CE = require('../Exceptions')
const unimplementedMethods = ['login', 'logout', 'loginViaId']

/**
 * The base scheme is supposed to be extend by other
 * schemes.
 *
 * @class BaseScheme
 * @constructor
 * @module Lucid
 */
class BaseScheme {
  constructor () {
    this._config = null
    this._serializerInstance = null
    this._instanceUser = null
    this._ctx = null
  }

  /**
   * The uid field name. Reads the `uid` from the config object
   *
   * @attribute uidField
   * @readOnly
   * @type {String}
   */
  get uidField () {
    return this._config.uid
  }

  /**
   * The authenticator field. Get name of the current authenticator
   *
   * @attribute authenticator
   * @readOnly
   * @type {String}
   */
  get authenticator () {
    return this._config.authenticator
  }

  /**
   * The password field name. Reads the `password` from the config object
   *
   * @attribute passwordField
   * @readOnly
   * @type {String}
   */
  get passwordField () {
    return this._config.password
  }

  /**
   * The scheme field name. Reads the `scheme` from the config object
   *
   * @attribute scheme
   * @readOnly
   * @type {String}
   */
  get scheme () {
    return this._config.scheme
  }

  /**
   * The primary key to be used to fetch the unique identifier value
   * for the current user.
   *
   * @attribute primaryKey
   * @readOnly
   * @type {String}
   */
  get primaryKey () {
    return this._serializerInstance.primaryKey
  }

  /**
   * The unique identifier value for the current user. The value relies on
   * primaryKey.
   *
   * @attribute primaryKeyValue
   * @readOnly
   * @type {String|Number}
   */
  get primaryKeyValue () {
    return this._instanceUser[this.primaryKey]
  }

  /**
   * Reference to the current user instance. The output value relies
   * on the serializer in use.
   *
   * @attribute user
   * @return {Mixed}
   */
  get user () {
    return this._instanceUser
  }

  set user (user) {
    this._instanceUser = user
  }

  /**
   * Set the config and the serializer instance on scheme. This method
   * is invoked by the `Auth` facade to feed the current config and
   * serializer in use.
   *
   * @method setOptions
   *
   * @param  {Object}   config
   * @param  {Object}   serializerInstance
   *
   * @chainable
   */
  setOptions (config, serializerInstance) {
    this._config = config
    this._serializerInstance = serializerInstance
    return this
  }

  /**
   * Set http context on the scheme instance. This
   * method is called automatically by `Auth`
   * facade.
   *
   * @method setCtx
   *
   * @param  {Object}   ctx
   *
   * @chainable
   */
  setCtx (ctx) {
    this._ctx = ctx
    return this
  }

  /**
   * Attach a callback to add runtime constraints
   * to the query builder.
   *
   * @method query
   *
   * @param  {Function} callback
   *
   * @chainable
   *
   * @example
   * ```js
   * auth.query((builder) => {
   *   builder.status('active')
   * }).attempt()
   * ```
   */
  query (callback) {
    this._serializerInstance.query(callback)
    return this
  }

  /**
   * Validates the user credentials.
   *
   * This method will never login the user.
   *
   * @method validate
   * @async
   *
   * @param  {String}  uid
   * @param  {String}  password
   * @param  {Boolean} [returnUser = false]
   *
   * @return {Object|Boolean} - User object is returned when `returnUser` is set to true.
   *
   * @throws {UserNotFoundException}     If unable to find user with uid
   * @throws {PasswordMisMatchException} If password mismatches
   *
   * @example
   * ```js
   * try {
   *   await auth.validate(username, password)
   * } catch (error) {
   *   // Invalid credentials
   * }
   * ```
   */
  async validate (uid, password, returnUser = false) {
    const user = await this._serializerInstance.findByUid(uid)
    if (!user) {
      throw this.missingUserFor(uid)
    }

    const validated = await this._serializerInstance.validateCredentails(user, password)
    if (!validated) {
      throw this.invalidPassword()
    }

    return returnUser ? user : !!user
  }

  /**
   * Returns the user logged in for the current request. This method will
   * call the `check` method internally.
   *
   * @method getUser
   * @async
   *
   * @return {Object}
   *
   * @example
   * ```js
 *   await auth.getUser()
   * ```
   */
  async getUser () {
    await this.check()
    return this.user
  }

  /**
   * Returns the value of authorization header
   * or request payload token key value.
   *
   * This method will read the value of `Authorization` header, falling
   * back to `token` input field.
   *
   * @method getAuthHeader
   *
   * @return {String|Null}
   */
  getAuthHeader () {
    const { request } = this._ctx

    /**
     * Parse the auth header and fetch token from it
     */
    let token = request.header('authorization')
    if (token) {
      token = token.split(' ')
      return (token.length === 2 && token[0].toLowerCase() === 'bearer') ? token[1] : null
    }

    /**
     * Fallback to `input` field
     */
    return request.input('token', null)
  }

  /**
   * Raises UserNotFoundException exception and pass required data to it
   *
   * @method missingUserFor
   *
   * @param  {String|Number}    uidValue
   * @param  {String}           [uid=this._config.uid]
   * @param  {String}           [password=this._config.password]
   *
   * @return {UserNotFoundException}
   */
  missingUserFor (uidValue, uid = this._config.uid, password = this._config.password) {
    const message = `Cannot find user with ${uid} as ${uidValue}`
    return CE.UserNotFoundException.invoke(message, uid, password, this.scheme)
  }

  /**
   * Raises PasswordMisMatchException exception and pass required data to it
   *
   * @method invalidPassword
   *
   * @param  {String}        message
   * @param  {String}        [password=this._config.password]
   *
   * @return {PasswordMisMatchException}
   */
  invalidPassword (password = this._config.password) {
    return CE.PasswordMisMatchException.invoke('Cannot verify user password', password, this.scheme)
  }
}

unimplementedMethods.forEach((method) => {
  BaseScheme.prototype[method] = function () {
    throw GE.RuntimeException.invoke(`${method} method is not implemented by ${this.scheme} scheme`, 500, 'E_INVALID_METHOD')
  }
})

module.exports = BaseScheme
