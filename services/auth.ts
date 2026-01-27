/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import app from '@adonisjs/core/services/app'
import { type AuthService } from '../src/types.js'

let auth: AuthService

/**
 * Returns a singleton instance of the Auth manager class
 */
await app.booted(async () => {
  auth = await app.container.make('auth.manager')
})

export { auth as default }
