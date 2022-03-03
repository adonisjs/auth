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

import { setupApplication, cleanup, setup, reset, getTokensRedisProvider } from '../../test-helpers'
let app: ApplicationContract

const sleep = (time: number) => new Promise((resolve) => setTimeout(resolve, time))

test.group('Redis Token Provider', (group) => {
  group.setup(async () => {
    app = await setupApplication()
    await setup(app)
  })

  group.teardown(async () => {
    await cleanup(app)
    await app.container.use('Adonis/Addons/Redis').flushdb()
    await app.container.use('Adonis/Addons/Redis').quit()
  })

  group.each.teardown(async () => {
    await reset(app)
  })

  test('save token to the database', async ({ assert }) => {
    const token = string.generateRandom(40)
    const redis = app.container.use('Adonis/Addons/Redis')
    const provider = getTokensRedisProvider(redis)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ days: 2 }),
    })

    assert.exists(tokenId)
    const tokenRow = JSON.parse((await redis.get(`api_token:${tokenId}`))!)
    assert.deepEqual(tokenRow, {
      user_id: '1',
      name: 'Auth token',
      token,
    })

    let expiry = await redis.ttl(tokenId)
    assert.isBelow(expiry, 2 * 24 * 3600 + 1)
  })

  test('save token to the database using a custom connection', async ({ assert }) => {
    const token = string.generateRandom(40)
    const redis = app.container.use('Adonis/Addons/Redis')
    const provider = getTokensRedisProvider(redis)
    provider.setConnection(redis.connection('localDb1'))

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ days: 2 }),
    })

    assert.exists(tokenId)
    const tokenRow = JSON.parse((await redis.connection('localDb1').get(`api_token:${tokenId}`))!)
    assert.deepEqual(tokenRow, {
      user_id: '1',
      name: 'Auth token',
      token,
    })

    let expiry = await redis.connection('localDb1').ttl(tokenId)
    assert.isBelow(expiry, 2 * 24 * 3600 + 1)

    await redis.quitAll()
  })

  test('read token from the database', async ({ assert }) => {
    const token = string.generateRandom(40)
    const redis = app.container.use('Adonis/Addons/Redis')
    const provider = getTokensRedisProvider(redis)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ days: 2 }),
    })

    assert.exists(tokenId)
    const tokenRow = await provider.read(tokenId, token, 'api_token')
    assert.equal(tokenRow!.name, 'Auth token')
    assert.equal(tokenRow!.tokenHash, token)
    assert.equal(tokenRow!.type, 'api_token')
  })

  test('read token from a custom database connection', async ({ assert }) => {
    const token = string.generateRandom(40)
    const redis = app.container.use('Adonis/Addons/Redis')
    const provider = getTokensRedisProvider(redis)
    provider.setConnection(redis.connection('localDb1'))

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ days: 2 }),
    })

    assert.exists(tokenId)
    const tokenRow = await provider.read(tokenId, token, 'api_token')
    assert.equal(tokenRow!.name, 'Auth token')
    assert.equal(tokenRow!.tokenHash, token)
    assert.equal(tokenRow!.type, 'api_token')

    await redis.quitAll()
  })

  test('return null when there is a token hash mis-match', async ({ assert }) => {
    const token = string.generateRandom(40)
    const redis = app.container.use('Adonis/Addons/Redis')
    const provider = getTokensRedisProvider(redis)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ minutes: 30 }),
    })

    assert.isNull(await provider.read(tokenId, 'foo', 'api_token'))
  })

  test('return null when token has been expired', async ({ assert }) => {
    const token = string.generateRandom(40)
    const redis = app.container.use('Adonis/Addons/Redis')
    const provider = getTokensRedisProvider(redis)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ seconds: 1 }),
    })

    await sleep(2000)
    assert.isNull(await provider.read(tokenId, token, 'api_token'))
  }).timeout(3000)

  test('work fine when token has no expiry', async ({ assert }) => {
    const token = string.generateRandom(40)
    const redis = app.container.use('Adonis/Addons/Redis')
    const provider = getTokensRedisProvider(redis)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
    })

    await sleep(2000)
    assert.isNotNull(await provider.read(tokenId, token, 'api_token'))

    let expiry = await redis.ttl(`api_token:${tokenId}`)
    assert.equal(expiry, -1)
  }).timeout(3000)

  test('return null when token is missing', async ({ assert }) => {
    const token = string.generateRandom(40)
    const redis = app.container.use('Adonis/Addons/Redis')
    const provider = getTokensRedisProvider(redis)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ seconds: 1 }),
    })

    assert.isNull(await provider.read(tokenId + 1, token, 'api_token'))
  })

  test('delete token from the database', async ({ assert }) => {
    const token = string.generateRandom(40)
    const redis = app.container.use('Adonis/Addons/Redis')
    const provider = getTokensRedisProvider(redis)

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ seconds: 1 }),
    })

    await provider.destroy(tokenId, 'api_token')
    const tokenRow = await redis.get(tokenId)
    assert.isNull(tokenRow)
  })

  test('delete token using a custom connection', async ({ assert }) => {
    const token = string.generateRandom(40)
    const redis = app.container.use('Adonis/Addons/Redis')
    const provider = getTokensRedisProvider(redis)
    provider.setConnection(redis.connection('localDb1'))

    const tokenId = await provider.write({
      name: 'Auth token',
      tokenHash: token,
      userId: '1',
      type: 'api_token',
      expiresAt: DateTime.local().plus({ seconds: 1 }),
    })

    await provider.destroy(tokenId, 'api_token')
    const tokenRow = await redis.connection('localDb1').get(tokenId)
    assert.isNull(tokenRow)

    await redis.quitAll()
  })
})
