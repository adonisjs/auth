/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { debuglog } from 'node:util'

/**
 * Debug logger instance for the AdonisJS auth package.
 * Set NODE_DEBUG=adonisjs:auth environment variable to enable debug logging.
 *
 * @example
 * debug('authenticating user %s', user.email)
 */
export default debuglog('adonisjs:auth')
