'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const auth = require('basic-auth')
const BaseScheme = require('./Base')
const CE = require('../Exceptions')

class BasicAuthScheme extends BaseScheme {
  /**
   * Validate user credentials
   *
   * @method validate
   *
   * @param  {String} uid
   * @param  {String} password
   * @param  {Boolean} returnUser
   *
   * @return {Object}
   *
   * @throws {UserNotFoundException} If unable to find user with uid
   * @throws {PasswordMisMatchException} If password mismatches
   */
  async validate (uid, password, returnUser) {
    const user = await this._serializerInstance.findByUid(uid)
    if (!user) {
      throw CE.UserNotFoundException.invoke(`Cannot find user with ${this._config.uid} as ${uid}`)
    }

    const validated = await this._serializerInstance.validateCredentails(user, password)
    if (!validated) {
      throw CE.PasswordMisMatchException.invoke('Cannot verify user password')
    }

    return returnUser ? user : !!user
  }

  /**
   * Check whether a user is logged in or
   * not.
   *
   * @method check
   *
   * @return {Boolean}
   */
  async check () {
    if (this.user) {
      return true
    }

    const credentials = auth(this._ctx.request.request)
    if (!credentials) {
      throw CE.InvalidBasicAuthException.invoke()
    }

    this.user = await this.validate(credentials.name, credentials.pass, true)
    return !!this.user
  }

  /**
   * Makes sure user is loggedin and then
   * returns the user back
   *
   * @method getUser
   *
   * @return {Object}
   */
  async getUser () {
    await this.check()
    return this.user
  }

  /**
   * Login as a user by setting basic auth header
   * before the request reaches the server.
   *
   * @param  {Function}    headerFn
   * @param  {Function}    sessionFn
   * @param  {String}      username
   * @param  {String}      password
   *
   * @method clientLogin
   * @async
   *
   * @return {void}
   */
  async clientLogin (headerFn, sessionFn, username, password) {
    headerFn('authorization', `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`)
  }
}

module.exports = BasicAuthScheme
