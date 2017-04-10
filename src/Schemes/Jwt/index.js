'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const jwt = require('jsonwebtoken')
const NE = require('node-exceptions')
const BaseScheme = require('../BaseScheme')

class JwtScheme extends BaseScheme {

  constructor (request, serializer, options) {
    super(request, serializer, options)
    if (!options.secret) {
      throw new NE.DomainException('Add secret key to the jwt configuration block')
    }
  }

  /**
   * returns default jwtOptions to be used while
   * generating and verifying tokens.
   *
   * @return {Object}
   *
   * @private
   */
  get jwtOptions () {
    return this.options.options || {}
  }

  /**
   * returns a signed token with given payload
   * @param  {Mixed} payload
   * @param  {Object} [options]
   * @return {Promise}
   *
   * @private
   */
  _signToken (payload, options) {
    return new Promise((resolve, reject) => {
      jwt.sign({payload: payload}, this.options.secret, options, function (error, token) {
        if (error) {
          return reject(error)
        }
        resolve(token)
      })
    })
  }

  /**
   * verifies request JWT token
   *
   * @param  {String} token
   * @return {Promise}
   *
   * @private
   */
  _verifyRequestToken (token, options) {
    return new Promise((resolve, reject) => {
      jwt.verify(token, this.options.secret, options, (error, decoded) => {
        if (error) {
          return reject(error)
        }

        /**
         * For backward compatibility we are going to auto detect the
         * decoded payload and return it as a new payload when it
         * does not have a uid.
         */
        if (decoded.payload && typeof (decoded.payload) === 'number') {
          decoded.payload = {uid: decoded.payload}
        }
        resolve(decoded)
      })
    })
  }

  /**
   * returns user by verifying request token and
   * using serializer to get user.
   *
   * @return {String}
   *
   * @private
   */
  * _getRequestUser () {
    try {
      const requestToken = yield this.decode()
      const userId = requestToken.payload.uid || null
      if (!userId) {
        return null
      }
      return yield this.serializer.findById(userId, this.options)
    } catch (e) {
      return null
    }
  }

  /**
   * Generates a new JWT token for a given user. The user
   * needs to be an instance of model when serializer
   * is Lucid
   *
   * @param  {Object} user
   *
   * @return {String}
   */
  * generate (user, customPayload) {
    if (!user) {
      throw new NE.InvalidArgumentException('user is required to generate a jwt token')
    }
    const primaryKey = this.serializer.primaryKey(this.options)
    const primaryValue = user[primaryKey]
    if (!primaryValue) {
      throw new NE.InvalidArgumentException(`Value for ${primaryKey} is null for given user.`)
    }
    const payload = {uid: primaryValue}
    if (customPayload) {
      payload.data = typeof (customPayload.toJSON) === 'function' ? customPayload.toJSON() : customPayload
    }
    return this._signToken(payload, this.jwtOptions)
  }

  /**
   * Decodes a token and returns jwt object.
   *
   * @return {Object}
   */
  * decode () {
    return yield this._verifyRequestToken(this._getRequestToken(), this.jwtOptions)
  }

  /**
   * Validates a user an returns the token
   * if credentials have been validated.
   *
   * @param  {String} uid
   * @param  {String} password
   *
   * @return {String}
   */
  * attempt (uid, password, customPayload) {
    let payload = null
    const user = yield this.validate(uid, password, true)
    if (customPayload) {
      payload = typeof (customPayload.toJSON) === 'function' ? customPayload.toJSON() : customPayload
    }
    return yield (payload !== null) ? this.generate(user, payload) : this.generate(user)
  }

}

module.exports = JwtScheme
