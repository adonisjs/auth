'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const debug = require('debug')('adonis:auth')

class Auth {
  constructor (Config) {
    const authenticator = Config.get('auth.authenticator')
    this.scheme = Config.get(`auth.${authenticator}.scheme`, null)
  }

  /**
   * Authenticate the user using one of the defined
   * schemes or the default scheme
   *
   * @method handle
   *
   * @param  {Object}   options.auth
   * @param  {Function} next
   *
   * @return {void}
   */
  async handle ({ auth }, next, schemes) {
    let lastError = null
    let authenticatedScheme = null

    schemes = schemes instanceof Array === true ? schemes : [this.scheme]
    debug('attempting to authenticate via %j scheme(s)', schemes)

    /**
     * Loop over all the defined schemes and wait until use is logged
     * via anyone
     */
    for (const scheme of schemes) {
      try {
        await auth.authenticator(scheme).check()
        debug('authenticated using %s scheme', scheme)
        authenticatedScheme = scheme
        lastError = null
        break
      } catch (error) {
        debug('authentication failed using %s scheme', scheme)
        lastError = error
      }
    }

    /**
     * If there is an error from all the schemes
     * then throw it back
     */
    if (lastError) {
      throw lastError
    }

    /**
     * If user got logged then set the `current` property
     * on auth, which is reference to the scheme via
     * which user got authenticated.
     */
    if (authenticatedScheme) {
      /**
       * If logged in scheme is same as the default scheme, the reference
       * the actual authenticator instance, otherwise create a new
       * one for the scheme via which user got authenticated
       */
      auth.current = authenticatedScheme === this.scheme
      ? auth.authenticatorInstance
      : auth.authenticator(authenticatedScheme)
    }

    await next()
  }
}

module.exports = Auth
