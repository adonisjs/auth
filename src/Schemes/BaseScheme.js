'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const CE = require('../Exceptions')

class BaseScheme {

  constructor (request, serializer, options) {
    this.request = request
    this.serializer = serializer
    this.options = options
    this.user = null // this property is set once per request
  }

  /**
   * checks whether a user is logged in or not. It
   * is performed by excuting following steps in
   * sequence.
   * 1. return true - If user exists on the instance
   * 2. Check for session value
   * a) return false - If session does not exists
   * b) Go to step 3
   * 3. find the user using the serializer and passing id
   * a) return false - If user does not exist
   * b) Go to step 4
   * 4. set user object on instance and return true
   *
   * @return {Boolean}
   */
  * check () {
    if (this.user) {
      return true
    }
    const requestUser = yield this._getRequestUser()
    this.user = requestUser
    return !!requestUser
  }

  /**
   * returns the logged in user by calling check method
   *
   * @return {Object}
   *
   * @public
   */
  * getUser () {
    const isLoggedIn = yield this.check()
    if (!isLoggedIn) {
      return null
    }
    return this.user
  }

  /**
   * validates a user with uid and password.
   *
   * @param  {String} uid
   * @param  {String} password
   * @param  {Boolean} [returnUser]
   * @return {Boolean|Object}
   *
   * @throws PasswordMisMatchException when password does not match
   */
  * validate (uid, password, returnUser) {
    const user = yield this.serializer.findByCredentials(uid, this.options)
    const isValid = yield this.serializer.validateCredentials(user, password, this.options)
    if (!isValid) {
      throw new CE.PasswordMisMatchException('Password does not match')
    }
    return returnUser ? user : true
  }

  /**
   * returns token passed inside request, it will look
   * for following places.
   * Request header - Authorization=Bearer 'token'
   * Query string - token='token'
   * Request body - token='token'
   *
   * @return {String|Null}
   *
   * @private
   */
  _getRequestToken () {
    let token = this.request.header('authorization')
    if (token) {
      token = token.split(' ')
      return (token.length === 2 && token[0] === 'Bearer') ? token[1] : null
    }
    return this.request.input('token')
  }
}

module.exports = BaseScheme
