/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

export * as errors from './src/errors.js'
export { configure } from './configure.js'
export * as symbols from './src/symbols.js'
export { AuthManager } from './src/auth_manager.js'
export { defineConfig } from './src/define_config.js'
export { Authenticator } from './src/authenticator.js'
export { AuthenticatorClient } from './src/authenticator_client.js'

function isModuleInstalled(moduleName: string) {
  try {
    import.meta.resolve(moduleName)
    return true
  } catch (e) {
    return false
  }
}

// @deprecate Import `withAuthFinder` from `@adonisjs/auth/mixins` instead
let withAuthFinder

if (isModuleInstalled('@adonisjs/lucid')) {
  withAuthFinder = await import('./src/mixins/with_auth_finder.js')
}

export { withAuthFinder }
