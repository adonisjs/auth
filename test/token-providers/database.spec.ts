/*
 * @adonisjs/auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { test } from '@japa/runner'
import 'reflect-metadata'
import { DateTime } from 'luxon'
import { string } from '@poppinss/utils/build/helpers'
import { ApplicationContract } from '@ioc:Adonis/Core/Application'

import { setupApplication, cleanup, setup, reset, getTokensDbProvider } from '../../test-helpers'
let app: ApplicationContract

const sleep = (time: number) => new Promise((resolve) => setTimeout(resolve, time))

test.group('Database Token Provider', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
  })

  group.each.teardown(async () => {
    await reset(app)
  })

  test('save token to the database', async ({ assert }) => {
    const token = string.generateRandom(40)
    const db = app.container.use('Adonis/Lucid/Database')
    const provider = getTokensDbProvider(db)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local(),
    })

    assert.exists(tokenId)
  })

  test('use custom connection for persistance', async ({ assert }) => {
    const token = string.generateRandom(40)
    const db = app.container.use('Adonis/Lucid/Database')
    const provider = getTokensDbProvider(db)
    provider.setConnection(db.connection('secondary'))

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local(),
    })

    assert.exists(tokenId)
    const secondaryConnectionTokens = await db.connection('secondary').from('api_tokens')
    const primaryConnectionTokens = await db.connection().from('api_tokens')

    assert.lengthOf(secondaryConnectionTokens, 1)
    assert.lengthOf(primaryConnectionTokens, 0)
  })

  test('read token from the database', async ({ assert }) => {
    const token = string.generateRandom(40)
    const db = app.container.use('Adonis/Lucid/Database')
    const provider = getTokensDbProvider(db)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ minutes: 30 }),
    })

    const tokenRow = await provider.read(tokenId, token, 'api_token')
    assert.equal(tokenRow!.name, 'Auth token')
    assert.equal(tokenRow!.tokenHash, token)
    assert.equal(tokenRow!.type, 'api_token')
    assert.exists(tokenRow!.expiresAt)
  })

  test('read token from a custom database connection', async ({ assert }) => {
    const token = string.generateRandom(40)
    const db = app.container.use('Adonis/Lucid/Database')
    const provider = getTokensDbProvider(db)
    provider.setConnection(db.connection('secondary'))

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ minutes: 30 }),
    })

    const tokenRow = await provider.read(tokenId, token, 'api_token')
    assert.equal(tokenRow!.name, 'Auth token')
    assert.equal(tokenRow!.tokenHash, token)
    assert.equal(tokenRow!.type, 'api_token')
    assert.exists(tokenRow!.expiresAt)
  })

  test('return null when there is a token hash mis-match', async ({ assert }) => {
    const token = string.generateRandom(40)
    const db = app.container.use('Adonis/Lucid/Database')
    const provider = getTokensDbProvider(db)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local(),
    })

    assert.isNull(await provider.read(tokenId, 'foo', 'api_token'))
  })

  test('return null when token has been expired', async ({ assert }) => {
    const token = string.generateRandom(40)
    const db = app.container.use('Adonis/Lucid/Database')
    const provider = getTokensDbProvider(db)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local(),
    })

    await sleep(1000)
    assert.isNull(await provider.read(tokenId, token, 'api_token'))
  })

  test('work fine when token has no expiry', async ({ assert }) => {
    const token = string.generateRandom(40)
    const db = app.container.use('Adonis/Lucid/Database')
    const provider = getTokensDbProvider(db)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
    })

    await sleep(1000)
    assert.isNotNull(await provider.read(tokenId, token, 'api_token'))
  })

  test('return null when token is missing', async ({ assert }) => {
    const token = string.generateRandom(40)
    const db = app.container.use('Adonis/Lucid/Database')
    const provider = getTokensDbProvider(db)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local(),
    })

    assert.isNull(await provider.read(tokenId + 1, token, 'api_token'))
  })

  test('delete token from the database', async ({ assert }) => {
    const token = string.generateRandom(40)
    const db = app.container.use('Adonis/Lucid/Database')
    const provider = getTokensDbProvider(db)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local(),
    })

    await provider.destroy(tokenId, 'api_token')
    const tokens = await db.from('api_tokens').select('*')
    assert.lengthOf(tokens, 0)
  })

  test('delete token from a custom database connection', async ({ assert }) => {
    const token = string.generateRandom(40)
    const db = app.container.use('Adonis/Lucid/Database')
    const provider = getTokensDbProvider(db)
    provider.setConnection(db.connection('secondary'))

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local(),
    })

    await provider.destroy(tokenId, 'api_token')
    const tokens = await db.connection('secondary').from('api_tokens').select('*')
    assert.lengthOf(tokens, 0)
  })
})
