'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const coFs = require('co-functional')
const CE = require('../src/Exceptions')

class Auth {
  /**
   * try authenticating the request using number defined
   * authenticators and throw an error once able to
   * authenticate request. It is required to stop
   * async loop and that only be done by throwing
   * error.
   *
   * @param  {Object} request
   * @param  {Array} authenticators
   * @return {Promise}
   *
   * @private
   */
  _tryFail (request, authenticators) {
    return coFs.forEachSerial(function * (authenticator) {
      let result = null
      /**
       * it should make use of existing of existing auth instance when
       * authenticator is set to default. It will avoid invoking new
       * instance, which inturn saves a SQL query.
       */
      if (authenticator === 'default') {
        result = yield request.auth.check()
      } else {
        result = yield request.auth.authenticator(authenticator).check()
      }
      if (result) {
        request.authUser = yield request.auth.authenticator(authenticator).getUser()
        /**
         * we need to break the loop as soon as an authenticator
         * returns true. Ideally one cannot break promises chain
         * without throwing an error, so here we throw an error
         * and handle it gracefully
         */
        throw new Error('Stop execution')
      }
    }, authenticators)
  }

  /**
   * authenticate the request by gracefully handling the Stop execution
   * exception.
   *
   * @param  {Object} request
   * @param  {Array} authenticators
   *
   * @throws Exception when unable to authenticate the request.
   *
   * @private
   */
  * _authenticate (request, authenticators) {
    try {
      yield this._tryFail(request, authenticators)
      throw new CE.InvalidLoginException('Login Failure', 401)
    } catch (e) {
      if (e.message !== 'Stop execution') {
        throw e
      }
    }
  }

  /**
   * authenticates a given request using number of defined
   * authenticators.
   *
   * @param  {Object}   request
   * @param  {Object}   response
   * @param  {Function} next
   *
   * @public
   */
  * handle (request, response, next) {
    const args = Array.prototype.slice.call(arguments)
    const authenticators = args.length > 3 ? args.splice(3, args.length) : ['default']
    yield this._authenticate(request, authenticators)
    yield next
  }

  /**
   * authenticates a web socket request using number of defined
   * authenticators.
   *
   * @param  {Object}   socket
   * @param  {Object}   request
   * @param  {Function} next
   *
   * @public
   */
  * handleWs (socket, request, next) {
    const args = Array.prototype.slice.call(arguments)
    const authenticators = args.length > 3 ? args.splice(3, args.length) : ['default']
    yield this._authenticate(request, authenticators)
    socket.authUser = request.authUser
    yield next
  }

}

module.exports = Auth
