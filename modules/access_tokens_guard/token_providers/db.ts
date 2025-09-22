/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import { inspect } from 'node:util'
import type { Secret } from '@adonisjs/core/helpers'
import { RuntimeException } from '@adonisjs/core/exceptions'
import type { LucidModel } from '@adonisjs/lucid/types/model'

import { AccessToken } from '../access_token.ts'
import type {
  AccessTokenDbColumns,
  AccessTokensProviderContract,
  DbAccessTokensProviderOptions,
} from '../types.ts'

/**
 * DbAccessTokensProvider uses lucid database service to fetch and
 * persist tokens for a given user.
 *
 * The user must be an instance of the associated user model.
 *
 * @template TokenableModel - The Lucid model that can have tokens
 *
 * @example
 * const provider = new DbAccessTokensProvider({
 *   tokenableModel: () => import('#models/user'),
 *   table: 'api_tokens',
 *   type: 'api_token',
 *   prefix: 'api_'
 * })
 */
export class DbAccessTokensProvider<TokenableModel extends LucidModel>
  implements AccessTokensProviderContract<TokenableModel>
{
  /**
   * Create tokens provider instance for a given Lucid model
   *
   * @param model - The tokenable model factory function
   * @param options - Optional configuration options
   *
   * @example
   * const provider = DbAccessTokensProvider.forModel(
   *   () => import('#models/user'),
   *   { prefix: 'api_', type: 'api_token' }
   * )
   */
  static forModel<TokenableModel extends LucidModel>(
    model: DbAccessTokensProviderOptions<TokenableModel>['tokenableModel'],
    options?: Omit<DbAccessTokensProviderOptions<TokenableModel>, 'tokenableModel'>
  ) {
    return new DbAccessTokensProvider<TokenableModel>({ tokenableModel: model, ...(options || {}) })
  }

  /**
   * A unique type for the value. The type is used to identify a
   * bucket of tokens within the storage layer.
   *
   * Defaults to auth_token
   */
  protected type: string

  /**
   * A unique prefix to append to the publicly shared token value.
   *
   * Defaults to oat
   */
  protected prefix: string

  /**
   * Database table to use for querying access tokens
   */
  protected table: string

  /**
   * The length for the token secret. A secret is a cryptographically
   * secure random string.
   */
  protected tokenSecretLength: number

  /**
   * Creates a new DbAccessTokensProvider instance
   *
   * @param options - Configuration options for the provider
   *
   * @example
   * const provider = new DbAccessTokensProvider({
   *   tokenableModel: () => import('#models/user'),
   *   table: 'auth_access_tokens',
   *   tokenSecretLength: 40,
   *   type: 'auth_token',
   *   prefix: 'oat_'
   * })
   */
  constructor(protected options: DbAccessTokensProviderOptions<TokenableModel>) {
    this.table = options.table || 'auth_access_tokens'
    this.tokenSecretLength = options.tokenSecretLength || 40
    this.type = options.type || 'auth_token'
    this.prefix = options.prefix || 'oat_'
  }

  /**
   * Check if value is an object
   */
  #isObject(value: unknown) {
    return value !== null && typeof value === 'object' && !Array.isArray(value)
  }

  /**
   * Ensure the provided user is an instance of the user model and
   * has a primary key
   */
  #ensureIsPersisted(user: InstanceType<TokenableModel>) {
    const model = this.options.tokenableModel
    if (user instanceof model === false) {
      throw new RuntimeException(
        `Invalid user object. It must be an instance of the "${model.name}" model`
      )
    }

    if (!user.$primaryKeyValue) {
      throw new RuntimeException(
        `Cannot use "${model.name}" model for managing access tokens. The value of column "${model.primaryKey}" is undefined or null`
      )
    }
  }

  /**
   * Maps a database row to an AccessToken instance
   *
   * @param dbRow - The database row containing token data
   *
   * @example
   * const token = provider.dbRowToAccessToken({
   *   id: 1,
   *   tokenable_id: 123,
   *   type: 'auth_token',
   *   hash: 'sha256hash',
   *   // ... other columns
   * })
   */
  protected dbRowToAccessToken(dbRow: AccessTokenDbColumns): AccessToken {
    return new AccessToken({
      identifier: dbRow.id,
      tokenableId: dbRow.tokenable_id,
      type: dbRow.type,
      name: dbRow.name,
      hash: dbRow.hash,
      abilities: JSON.parse(dbRow.abilities),
      createdAt:
        typeof dbRow.created_at === 'number' ? new Date(dbRow.created_at) : dbRow.created_at,
      updatedAt:
        typeof dbRow.updated_at === 'number' ? new Date(dbRow.updated_at) : dbRow.updated_at,
      lastUsedAt:
        typeof dbRow.last_used_at === 'number' ? new Date(dbRow.last_used_at) : dbRow.last_used_at,
      expiresAt:
        typeof dbRow.expires_at === 'number' ? new Date(dbRow.expires_at) : dbRow.expires_at,
    })
  }

  /**
   * Returns a query client instance from the parent model
   *
   * @example
   * const db = await provider.getDb()
   * const tokens = await db.from('auth_access_tokens').select('*')
   */
  protected async getDb() {
    const model = this.options.tokenableModel
    return model.$adapter.query(model).client
  }

  /**
   * Create a token for a user
   *
   * @param user - The user instance to create a token for
   * @param abilities - Array of abilities the token should have
   * @param options - Optional token configuration
   *
   * @example
   * const token = await provider.create(user, ['read', 'write'], {
   *   name: 'Mobile App Token',
   *   expiresIn: '7d'
   * })
   * console.log('Token:', token.value.release())
   */
  async create(
    user: InstanceType<TokenableModel>,
    abilities: string[] = ['*'],
    options?: {
      name?: string
      expiresIn?: string | number
    }
  ) {
    this.#ensureIsPersisted(user)

    const queryClient = await this.getDb()

    /**
     * Creating a transient token. Transient token abstracts
     * the logic of creating a random secure secret and its
     * hash
     */
    const transientToken = AccessToken.createTransientToken(
      user.$primaryKeyValue!,
      this.tokenSecretLength,
      options?.expiresIn || this.options.expiresIn
    )

    /**
     * Row to insert inside the database. We expect exactly these
     * columns to exist.
     */
    const dbRow: Omit<AccessTokenDbColumns, 'id'> = {
      tokenable_id: transientToken.userId,
      type: this.type,
      name: options?.name || null,
      hash: transientToken.hash,
      abilities: JSON.stringify(abilities),
      created_at: new Date(),
      updated_at: new Date(),
      last_used_at: null,
      expires_at: transientToken.expiresAt || null,
    }

    /**
     * Insert data to the database.
     */
    const result = await queryClient.table(this.table).insert(dbRow).returning('id')
    const id = this.#isObject(result[0]) ? result[0].id : result[0]

    /**
     * Throw error when unable to find id in the return value of
     * the insert query
     */
    if (!id) {
      throw new RuntimeException(
        `Cannot save access token. The result "${inspect(result)}" of insert query is unexpected`
      )
    }

    /**
     * Convert db row to an access token
     */
    return new AccessToken({
      identifier: id,
      tokenableId: dbRow.tokenable_id,
      type: dbRow.type,
      prefix: this.prefix,
      secret: transientToken.secret,
      name: dbRow.name,
      hash: dbRow.hash,
      abilities: JSON.parse(dbRow.abilities),
      createdAt: dbRow.created_at,
      updatedAt: dbRow.updated_at,
      lastUsedAt: dbRow.last_used_at,
      expiresAt: dbRow.expires_at,
    })
  }

  /**
   * Find a token for a user by the token id
   *
   * @param user - The user instance that owns the token
   * @param identifier - The token identifier to search for
   *
   * @example
   * const token = await provider.find(user, 123)
   * if (token) {
   *   console.log('Found token:', token.name)
   * }
   */
  async find(user: InstanceType<TokenableModel>, identifier: string | number | BigInt) {
    this.#ensureIsPersisted(user)

    const queryClient = await this.getDb()
    const dbRow = await queryClient
      .query<AccessTokenDbColumns>()
      .from(this.table)
      .where({ id: identifier, tokenable_id: user.$primaryKeyValue, type: this.type })
      .limit(1)
      .first()

    if (!dbRow) {
      return null
    }

    return this.dbRowToAccessToken(dbRow)
  }

  /**
   * Delete a token by its id
   *
   * @param user - The user instance that owns the token
   * @param identifier - The token identifier to delete
   *
   * @example
   * const deletedCount = await provider.delete(user, 123)
   * console.log('Deleted tokens:', deletedCount)
   */
  async delete(
    user: InstanceType<TokenableModel>,
    identifier: string | number | BigInt
  ): Promise<number> {
    this.#ensureIsPersisted(user)

    const queryClient = await this.getDb()
    const affectedRows = await queryClient
      .query<number>()
      .from(this.table)
      .where({ id: identifier, tokenable_id: user.$primaryKeyValue, type: this.type })
      .del()
      .exec()

    return affectedRows as unknown as number
  }

  /**
   * Returns all the tokens for a given user
   *
   * @param user - The user instance to get tokens for
   *
   * @example
   * const tokens = await provider.all(user)
   * console.log('User has', tokens.length, 'tokens')
   * tokens.forEach(token => console.log(token.name))
   */
  async all(user: InstanceType<TokenableModel>) {
    this.#ensureIsPersisted(user)

    const queryClient = await this.getDb()
    const dbRows = await queryClient
      .query<AccessTokenDbColumns>()
      .from(this.table)
      .where({ tokenable_id: user.$primaryKeyValue, type: this.type })
      .ifDialect('postgres', (query) => {
        query.orderBy([
          {
            column: 'last_used_at',
            order: 'desc',
            nulls: 'last',
          },
        ])
      })
      .unlessDialect('postgres', (query) => {
        query.orderBy([
          {
            column: 'last_used_at',
            order: 'asc',
            nulls: 'last',
          },
        ])
      })
      .orderBy('id', 'desc')
      .exec()

    return dbRows.map((dbRow) => {
      return this.dbRowToAccessToken(dbRow)
    })
  }

  /**
   * Verifies a publicly shared access token and returns an
   * access token for it.
   *
   * Returns null when unable to verify the token or find it
   * inside the storage
   *
   * @param tokenValue - The token value to verify
   *
   * @example
   * const token = await provider.verify(new Secret('oat_abc123.def456'))
   * if (token && !token.isExpired()) {
   *   console.log('Valid token for user:', token.tokenableId)
   * }
   */
  async verify(tokenValue: Secret<string>) {
    const decodedToken = AccessToken.decode(this.prefix, tokenValue.release())
    if (!decodedToken) {
      return null
    }

    const db = await this.getDb()
    const dbRow = await db
      .query<AccessTokenDbColumns>()
      .from(this.table)
      .where({ id: decodedToken.identifier, type: this.type })
      .limit(1)
      .first()

    if (!dbRow) {
      return null
    }

    /**
     * Update last time the token is used
     */
    dbRow.last_used_at = new Date()
    await db
      .from(this.table)
      .where({ id: dbRow.id, type: dbRow.type })
      .update({ last_used_at: dbRow.last_used_at })

    /**
     * Convert to access token instance
     */
    const accessToken = this.dbRowToAccessToken(dbRow)

    /**
     * Ensure the token secret matches the token hash
     */
    if (!accessToken.verify(decodedToken.secret) || accessToken.isExpired()) {
      return null
    }

    return accessToken
  }

  /**
   * Invalidates a token identified by its publicly shared token
   *
   * @param tokenValue - The token value to invalidate
   *
   * @example
   * const wasInvalidated = await provider.invalidate(new Secret('oat_abc123.def456'))
   * if (wasInvalidated) {
   *   console.log('Token successfully invalidated')
   * }
   */
  async invalidate(tokenValue: Secret<string>) {
    const decodedToken = AccessToken.decode(this.prefix, tokenValue.release())
    if (!decodedToken) {
      return false
    }

    const db = await this.getDb()
    const deleteCount = await db
      .query<AccessTokenDbColumns>()
      .from(this.table)
      .where({ id: decodedToken.identifier, type: this.type })
      .del()
      .exec()

    return Boolean(deleteCount)
  }
}
