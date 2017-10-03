'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

/**
 * The base scheme is supposed to be extend by other
 * schemes.
 *
 * @class BaseScheme
 * @constructor
 */
class BaseScheme {
  constructor () {
    this._config = null
    this._serializerInstance = null
    this._instanceUser = null
    this._ctx = null
  }

  /**
   * The uid field name
   *
   * @method uidField
   *
   * @return {String}
   */
  get uidField () {
    return this._config.uid
  }

  /**
   * The password field name
   *
   * @method passwordField
   *
   * @return {String}
   */
  get passwordField () {
    return this._config.password
  }

  /**
   * The scheme in use
   *
   * @method scheme
   *
   * @return {String}
   */
  get scheme () {
    return this._config.scheme
  }

  /**
   * The primary key value for a given
   * user
   *
   * @attribute primaryKey
   *
   * @return {String}
   */
  get primaryKey () {
    return this._serializerInstance.primaryKey
  }

  /**
   * Returns primary key value for the logged
   * in user.
   *
   * @attribute primaryKeyValue
   *
   * @return {String|Number}
   */
  get primaryKeyValue () {
    return this._instanceUser[this.primaryKey]
  }

  /**
   * The authenticated user
   *
   * @attribute user
   *
   * @return {Object}
   */
  get user () {
    return this._instanceUser
  }

  /**
   * Update reference to user object
   *
   * @attribute user
   *
   * @param  {Object} user
   *
   * @return {void}
   */
  set user (user) {
    this._instanceUser = user
  }

  /**
   * Set options on the scheme instance. This method is
   * called automatically by the auth class.
   *
   * @method setOptions
   *
   * @param  {Object}   config
   * @param  {Object}   serializerInstance
   *
   * @return {void}
   */
  setOptions (config, serializerInstance) {
    this._config = config
    this._serializerInstance = serializerInstance
    return this
  }

  /**
   * Set http context on the scheme instance. This
   * method is called automatically by auth
   * class.
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
   */
  query (callback) {
    this._serializerInstance.query(callback)
    return this
  }

  /**
   * Returns the value of authorization header
   * or request payload token key value
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
      return (token.length === 2 && token[0] === 'Bearer') ? token[1] : null
    }

    /**
     * Fallback to `input` field
     */
    token = request.input('token', null)
    if (token) {
      return token
    }

    /**
     * Fallback to cookie
     */
     return request.cookie('adonis-auth-jwt')
  }
}

module.exports = BaseScheme
