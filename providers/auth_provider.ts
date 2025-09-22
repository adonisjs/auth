/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { configProvider } from '@adonisjs/core'
import { RuntimeException } from '@adonisjs/core/exceptions'
import type { ApplicationService } from '@adonisjs/core/types'

import type { AuthService } from '../src/types.ts'
import { AuthManager } from '../src/auth_manager.ts'

declare module '@adonisjs/core/types' {
  export interface ContainerBindings {
    'auth.manager': AuthService
  }
}

/**
 * The AuthProvider service provider registers the auth manager
 * with the IoC container as a singleton
 *
 * @example
 * // The auth manager is automatically registered and can be injected
 * container.use('auth.manager')
 */
export default class AuthProvider {
  /**
   * Creates a new AuthProvider instance
   *
   * @param app - The application service instance
   */
  constructor(protected app: ApplicationService) {}

  /**
   * Registers the auth manager as a singleton service
   * in the IoC container
   *
   * @example
   * // This method is called automatically by AdonisJS
   * // The auth manager becomes available as 'auth.manager'
   */
  register() {
    this.app.container.singleton('auth.manager', async () => {
      const authConfigProvider = this.app.config.get('auth')
      const config = await configProvider.resolve<any>(this.app, authConfigProvider)

      if (!config) {
        throw new RuntimeException(
          'Invalid config exported from "config/auth.ts" file. Make sure to use the defineConfig method'
        )
      }

      return new AuthManager(config)
    })
  }
}
