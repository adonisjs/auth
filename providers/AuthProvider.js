'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const { ServiceProvider } = require('@adonisjs/fold')
const _ = require('lodash')
const WRONG_ORDER_MESSAGE = `Make sure to register session trait after the auth trait. It should be in following order
  trait('Auth/Client')
  trait('Session/Client')
`

class AuthProvider extends ServiceProvider {
  /**
   * Register auth provider under `Adonis/Src/Auth` namespace
   *
   * @method _registerAuth
   *
   * @return {void}
   *
   * @private
   */
  _registerAuth () {
    this.app.bind('Adonis/Src/Auth', () => require('../src/Auth'))
  }

  /**
   * Register auth manager under `Adonis/Src/Auth` namespace
   *
   * @method _registerAuthManager
   *
   * @return {void}
   *
   * @private
   */
  _registerAuthManager () {
    this.app.manager('Adonis/Src/Auth', require('../src/Auth/Manager'))
  }

  /**
   * Register authinit middleware under `Adonis/Middleware/AuthInit`
   * namespace.
   *
   * @method _registerAuthInitMiddleware
   *
   * @return {void}
   */
  _registerAuthInitMiddleware () {
    this.app.bind('Adonis/Middleware/AuthInit', (app) => {
      const AuthInit = require('../src/Middleware/AuthInit')
      return new AuthInit(app.use('Adonis/Src/Config'))
    })
  }

  /**
   * Register auth middleware under `Adonis/Middleware/Auth` namespace.
   *
   * @method _registerAuthMiddleware
   *
   * @return {void}
   *
   * @private
   */
  _registerAuthMiddleware () {
    this.app.bind('Adonis/Middleware/Auth', (app) => {
      const Auth = require('../src/Middleware/Auth')
      return new Auth(app.use('Adonis/Src/Config'))
    })
  }

  /**
   * Register AllowGuestOnly middleware under `Adonis/Middleware/AllowGuestOnly` namespace.
   *
   * @method _registerAllowGuestOnlyMiddleware
   *
   * @return {void}
   *
   * @private
   */
  _registerAllowGuestOnlyMiddleware () {
    this.app.bind('Adonis/Middleware/AllowGuestOnly', (app) => {
      const AllowGuestOnly = require('../src/Middleware/AllowGuestOnly')
      return new AllowGuestOnly()
    })
  }

  /**
   * Register the vow trait to bind session client
   * under `Adonis/Traits/Session` namespace.
   *
   * @method _registerVowTrait
   *
   * @return {void}
   */
  _registerVowTrait () {
    this.app.bind('Adonis/Traits/Auth', (app) => {
      const Config = app.use('Adonis/Src/Config')
      return ({ Request, traits }) => {
        const sessionIndex = _.findIndex(traits, (trait) => trait.action === 'Session/Client')
        const authIndex = _.findIndex(traits, (trait) => trait.action === 'Auth/Client')

        /**
         * The auth/client should be registered before the `session/client` trait. So that
         * session set by auth is sent as cookies.
         */
        if (sessionIndex > -1 && sessionIndex < authIndex) {
          throw new Error(WRONG_ORDER_MESSAGE)
        }
        require('../src/VowBindings/Request')(Request, Config)
      }
    })
    this.app.alias('Adonis/Traits/Auth', 'Auth/Client')
  }

  /**
   * Register namespaces to the IoC container
   *
   * @method register
   *
   * @return {void}
   */
  register () {
    this._registerAuth()
    this._registerAuthManager()
    this._registerAuthInitMiddleware()
    this._registerAuthMiddleware()
    this._registerAllowGuestOnlyMiddleware()
    this._registerVowTrait()
  }

  /**
   * Attach context getter when all providers have
   * been registered
   *
   * @method boot
   *
   * @return {void}
   */
  boot () {
    const Context = this.app.use('Adonis/Src/HttpContext')
    const Auth = this.app.use('Adonis/Src/Auth')
    const Config = this.app.use('Adonis/Src/Config')

    Context.getter('auth', function () {
      return new Auth({ request: this.request, response: this.response, session: this.session }, Config)
    }, true)

    /**
     * Try adding auth to the websocket context. Since websocket is
     * optional, we need to wrap binding inside a try catch
     */
    try {
      const WsContext = this.app.use('Adonis/Addons/WsContext')
      WsContext.getter('auth', function () {
        return new Auth({ request: this.request, response: this.response, session: this.session }, Config)
      }, true)
    } catch (error) {}

    /**
     * Adding `loggedIn` tag to the view, only when view
     * provider is registered
     */
    try {
      const View = this.app.use('Adonis/Src/View')
      require('../src/ViewBindings')(View)
    } catch (error) {}
  }
}

module.exports = AuthProvider
