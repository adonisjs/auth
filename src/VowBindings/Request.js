'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const _ = require('lodash')

module.exports = function (Request, Config) {
  /**
   * Macro to login a given user
   */
  Request.macro('loginVia', function () {
    const args = _.toArray(arguments)
    const authenticator = _.size(args) > 1 ? args.pop() : ''
    this._loginArgs = { authenticator, options: args }
    return this
  })

  /**
   * Setting the session or header before making the request.
   * Make sure this hook is executed before the session
   * before hook
   */
  Request.before(async (requestInstance) => {
    /**
     * When writing API server, the session client is not required
     * so we make sure only to use the session fn when it exists.
     * Otherwise we give a substitute fn, which will throw
     * exception when session authenticator is used to
     * authenticate
     */
    const sessionFn = typeof (requestInstance.session) === 'function'
    ? requestInstance.session.bind(requestInstance)
    : function () {
      throw new Error('Cannot set login session, since session client is not used for the test')
    }

    const headerFn = requestInstance.header.bind(requestInstance)

    /**
     * Skip authentication when loginVia was never executed
     */
    if (!requestInstance._loginArgs) {
      return
    }

    const { authenticator, options } = requestInstance._loginArgs

    const args = [headerFn, sessionFn].concat(options)
    const auth = new (use('Adonis/Src/Auth'))({}, Config)
    await auth.authenticator(authenticator).clientLogin(...args)
  })
}
