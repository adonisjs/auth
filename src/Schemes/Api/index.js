'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const BaseScheme = require('../BaseScheme')
const CE = require('../../Exceptions')
const ms = require('ms')
const uuid = require('uuid')

class ApiScheme extends BaseScheme {

  /**
   * returns user by verifying request token and
   * using serializer to get user.
   *
   * @return {String}
   *
   * @private
   */
  * _getRequestUser () {
    const token = this._getRequestToken()
    if (!token) {
      return null
    }
    try {
      return yield this.validate(token, true)
    } catch (e) {
      return null
    }
  }

  /**
   * validates a user with it's token
   *
   * @param  {String} token
   * @param  {Boolean} [returnUser]
   * @return {Boolean|Object}
   *
   * @throws TokeNotFoundException when unable to locate token
   * @throws InvalidTokenException when token is not valid or is expired
   */
  * validate (token, returnUser) {
    const userToken = yield this.serializer.findByToken(token, this.options)
    if (!userToken) {
      throw new CE.TokeNotFoundException(`Unable to find ${token} token`)
    }
    const isValid = yield this.serializer.validateToken(userToken, this.options)
    if (!isValid) {
      throw new CE.InvalidTokenException(`Invalid or expired ${token} token`)
    }
    return returnUser ? yield this.serializer.getUserForToken(userToken, this.options) : true
  }

  /**
   * generates a new token for a given user and
   * persits it to the database using serializer.
   *
   * @param  {Object} user
   * @param  {String|Number} [expiry]
   * @return {Object}
   *
   * @public
   */
  * generate (user, expiry) {
    if (!user) {
      throw new CE.InvalidArgumentException('user is required to generate a jwt token')
    }
    expiry = expiry || this.options.expiry
    expiry = expiry ? ms(expiry) : null
    const token = uuid.v4().replace(/-/g, '')
    return yield this.serializer.saveToken(user, token, this.options, expiry)
  }

  /**
   * revokes given tokens for a user
   *
   * @param  {Object} user
   * @param  {Array} tokens
   * @return {Number}
   *
   * @public
   */
  revoke (user, tokens) {
    return this.serializer.revokeTokens(user, tokens, null, this.options)
  }

  /**
   * revokes all tokens for a user
   *
   * @param  {Object} user
   * @return {Number}
   *
   * @public
   */
  revokeAll (user) {
    return this.serializer.revokeTokens(user, null, null, this.options)
  }

  /**
   * revokes all except given tokens for a user
   *
   * @param  {Object} user
   * @param  {Array} tokens
   * @return {Number}
   *
   * @public
   */
  revokeExcept (user, tokens) {
    return this.serializer.revokeTokens(user, tokens, true, this.options)
  }

}

module.exports = ApiScheme
