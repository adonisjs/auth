/*
 * @adonisjs/session
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import { fs, setupApplication } from '../test-helpers'
import { AuthManager } from '../src/AuthManager'

test.group('Auth Provider', (group) => {
  group.each.teardown(async () => {
    await fs.cleanup()
  })

  test('register auth provider', async ({ assert }) => {
    const app = await setupApplication(['../../providers/AuthProvider'])
    assert.instanceOf(app.container.use('Adonis/Addons/Auth'), AuthManager)
  })

  test('define auth property on http context', async ({ assert }) => {
    const app = await setupApplication(['../../providers/AuthProvider'])
    assert.isTrue(app.container.use('Adonis/Core/HttpContext')['hasGetter']('auth'))
  })
})
