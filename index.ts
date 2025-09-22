/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

export * as errors from './src/errors.ts'
export { configure } from './configure.ts'
export * as symbols from './src/symbols.ts'
export { AuthManager } from './src/auth_manager.ts'
export { defineConfig } from './src/define_config.ts'
export { Authenticator } from './src/authenticator.ts'
export { AuthenticatorClient } from './src/authenticator_client.ts'
import type { withAuthFinder as withAuthFinderType } from './src/mixins/lucid.ts'

function isModuleInstalled(moduleName: string) {
  try {
    import.meta.resolve(moduleName)
    return true
  } catch (e) {
    return false
  }
}

/**
 * @deprecated Import `withAuthFinder` from `@adonisjs/auth/mixins/lucid` instead
 */
let withAuthFinder: typeof withAuthFinderType

if (isModuleInstalled('@adonisjs/lucid')) {
  const { withAuthFinder: withAuthFinderFn } = await import('./src/mixins/lucid.js')
  withAuthFinder = withAuthFinderFn
}

export { withAuthFinder }
