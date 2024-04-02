/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { presetAuth } from '@adonisjs/presets/auth'
import type Configure from '@adonisjs/core/commands/configure'

/**
 * Configures the auth package
 */
export async function configure(command: Configure) {
  const codemods = await command.createCodemods()
  let guard: string | undefined = command.parsedFlags.guard

  /**
   * Prompts user to select a guard when not mentioned via
   * the CLI
   */
  if (guard === undefined) {
    guard = await command.prompt.choice(
      'Select the auth guard you want to use',
      [
        {
          name: 'session',
          message: 'Session',
        },
        {
          name: 'access_tokens',
          message: 'Opaque access tokens',
        },
        {
          name: 'basic_auth',
          message: 'Basic Auth',
        },
      ],
      {
        validate(value) {
          return !!value
        },
      }
    )
  }

  /**
   * Ensure selected or guard defined via the CLI flag is
   * valid
   */
  if (!['session', 'access_tokens', 'basic_auth'].includes(guard!)) {
    command.logger.error(
      `The selected guard "${guard}" is invalid. Select one from: session, access_tokens, basic_auth`
    )
    command.exitCode = 1
    return
  }

  await presetAuth(codemods, command.app, {
    guard: guard as 'session' | 'access_tokens' | 'basic_auth',
    userProvider: 'lucid',
  })
}
