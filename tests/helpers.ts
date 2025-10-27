/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { join } from 'node:path'
import timekeeper from 'timekeeper'
import { configDotenv } from 'dotenv'
import { Hash, HashManager } from '@adonisjs/core/hash'
import { mkdir, rm } from 'node:fs/promises'
import { getActiveTest } from '@japa/runner'
import { Emitter } from '@adonisjs/core/events'
import { BaseModel } from '@adonisjs/lucid/orm'
import { CookieClient } from '@adonisjs/core/http'
import { Database } from '@adonisjs/lucid/database'
import { AppFactory } from '@adonisjs/core/factories/app'
import { Scrypt } from '@adonisjs/core/hash/drivers/scrypt'
import { type Encryption } from '@adonisjs/core/encryption'
import { LoggerFactory } from '@adonisjs/core/factories/logger'
import setCookieParser, { type CookieMap } from 'set-cookie-parser'
import { EncryptionFactory } from '@adonisjs/core/factories/encryption'

export const encryption: Encryption = new EncryptionFactory().create()
configDotenv()

/**
 * Creates a fresh instance of AdonisJS hash module
 * with scrypt driver
 */
export function getHasher() {
  return new Hash(new Scrypt({}))
}

export function getHasherManager() {
  return new HashManager({
    default: 'scrypt',
    list: {
      scrypt: () => getHasher(),
    },
  })
}

/**
 * Creates an instance of the database class for making queries
 */
export async function createDatabase() {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "createDatabase" outside of a Japa test')
  }

  const basePath = test.context.fs.basePath
  await mkdir(basePath)

  const app = new AppFactory().create(test.context.fs.baseUrl, () => {})
  const logger = new LoggerFactory().create()
  const emitter = new Emitter(app)
  const db = new Database(
    {
      connection: process.env.DB || 'sqlite',
      connections: {
        sqlite: {
          client: 'sqlite3',
          connection: {
            filename: join(test.context.fs.basePath, 'db.sqlite3'),
          },
        },
        pg: {
          client: 'pg',
          connection: {
            host: process.env.PG_HOST as string,
            port: Number(process.env.PG_PORT),
            database: process.env.PG_DATABASE as string,
            user: process.env.PG_USER as string,
            password: process.env.PG_PASSWORD as string,
          },
        },
        mssql: {
          client: 'mssql',
          connection: {
            server: process.env.MSSQL_HOST as string,
            port: Number(process.env.MSSQL_PORT! as string),
            user: process.env.MSSQL_USER as string,
            password: process.env.MSSQL_PASSWORD as string,
            database: 'master',
            options: {
              enableArithAbort: true,
            },
          },
        },
        mysql: {
          client: 'mysql2',
          connection: {
            host: process.env.MYSQL_HOST as string,
            port: Number(process.env.MYSQL_PORT),
            database: process.env.MYSQL_DATABASE as string,
            user: process.env.MYSQL_USER as string,
            password: process.env.MYSQL_PASSWORD as string,
          },
        },
      },
    },
    logger,
    emitter
  )

  test.cleanup(async () => {
    db.manager.closeAll()
    await rm(basePath, { force: true, recursive: true, maxRetries: 3 })
  })
  BaseModel.useAdapter(db.modelAdapter())
  return db
}

/**
 * Creates needed database tables
 */
export async function createTables(db: Database) {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "createTables" outside of a Japa test')
  }

  test.cleanup(async () => {
    await db.connection().schema.dropTable('users')
    await db.connection().schema.dropTable('auth_access_tokens')
    await db.connection().schema.dropTable('remember_me_tokens')
  })

  await db.connection().schema.createTable('auth_access_tokens', (table) => {
    table.increments()
    table.integer('tokenable_id').notNullable().unsigned()
    table.string('type').notNullable()
    table.string('name').nullable()
    table.string('hash', 80).notNullable()
    table.text('abilities').notNullable()
    table.timestamp('created_at', { precision: 6, useTz: true }).notNullable()
    table.timestamp('updated_at', { precision: 6, useTz: true }).notNullable()
    table.timestamp('expires_at', { precision: 6, useTz: true }).nullable()
    table.timestamp('last_used_at', { precision: 6, useTz: true }).nullable()
  })

  await db.connection().schema.createTable('users', (table) => {
    table.increments()
    table.string('username').unique().notNullable()
    table.string('email').unique().notNullable()
    table.string('password').nullable()
  })

  await db.connection().schema.createTable('remember_me_tokens', (table) => {
    table.increments()
    table.integer('tokenable_id').notNullable().unsigned()
    table.string('hash', 80).notNullable()
    table.timestamp('created_at', { precision: 6, useTz: true }).notNullable()
    table.timestamp('updated_at', { precision: 6, useTz: true }).notNullable()
    table.timestamp('expires_at', { precision: 6, useTz: true }).notNullable()
  })
}

/**
 * Creates an emitter instance for testing with typed
 * events
 */
export function createEmitter<Events extends Record<string, any>>() {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "createEmitter" outside of a Japa test')
  }

  const app = new AppFactory().create(test.context.fs.baseUrl, () => {})
  return new Emitter<Events>(app)
}

/**
 * Promisify an event
 */
export function pEvent<T extends Record<string | symbol | number, any>, K extends keyof T>(
  emitter: Emitter<T>,
  event: K,
  timeout: number = 500
) {
  return new Promise<T[K] | null>((resolve) => {
    function handler(data: T[K]) {
      emitter.off(event, handler)
      resolve(data)
    }

    setTimeout(() => {
      emitter.off(event, handler)
      resolve(null)
    }, timeout)
    emitter.on(event, handler)
  })
}

/**
 * Parses set-cookie header
 */
export function parseCookies(setCookiesHeader: string | string[]) {
  const cookies = setCookieParser(setCookiesHeader, { map: true })
  const client = new CookieClient(encryption)

  return Object.keys(cookies).reduce((result, key) => {
    const cookie = cookies[key]

    result[key] = {
      ...cookie,
      value: cookie.value ? client.parse(cookie.name, cookie.value) : cookie.value,
    }
    return result
  }, {} as CookieMap)
}

/**
 * Define cookies for the request cookie header
 */
export function defineCookies(
  cookies: {
    key: string
    value: string
    type: 'plain' | 'encrypted' | 'signed'
  }[]
) {
  const client = new CookieClient(encryption)

  return cookies
    .reduce((result, cookie) => {
      const value =
        cookie.type === 'plain'
          ? client.encode(cookie.key, cookie.value)
          : cookie.type === 'encrypted'
            ? client.encrypt(cookie.key, cookie.value)
            : client.sign(cookie.key, cookie.value)

      result.push(`${cookie.key}=${value}`)
      return result
    }, [] as string[])
    .join(';')
}

/**
 * Travels time by seconds
 */
export function timeTravel(secondsToTravel: number) {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "timeTravel" outside of a Japa test')
  }

  timekeeper.reset()

  const date = new Date()
  date.setSeconds(date.getSeconds() + secondsToTravel)
  timekeeper.travel(date)

  test.cleanup(() => {
    timekeeper.reset()
  })
}

/**
 * Freezes time in the moment
 */
export function freezeTime() {
  const test = getActiveTest()
  if (!test) {
    throw new Error('Cannot use "freezeTime" outside of a Japa test')
  }

  timekeeper.reset()

  const date = new Date()
  timekeeper.freeze(date)

  test.cleanup(() => {
    timekeeper.reset()
  })
}
