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

import { RememberMeToken } from '../remember_me_token.ts'
import type {
  RememberMeTokenDbColumns,
  RememberMeTokensProviderContract,
  DbRememberMeTokensProviderOptions,
} from '../types.ts'

/**
 * DbRememberMeTokensProvider uses lucid database service to fetch and
 * persist tokens for a given user.
 *
 * The user must be an instance of the associated user model.
 *
 * @template TokenableModel - The Lucid model that can have remember me tokens
 *
 * @example
 * const provider = new DbRememberMeTokensProvider({
 *   tokenableModel: () => import('#models/user'),
 *   table: 'remember_me_tokens',
 *   tokenSecretLength: 32
 * })
 */
export class DbRememberMeTokensProvider<TokenableModel extends LucidModel>
  implements RememberMeTokensProviderContract<TokenableModel>
{
  /**
   * Create tokens provider instance for a given Lucid model
   *
   * @param model - The tokenable model factory function
   * @param options - Optional configuration options
   *
   * @example
   * const provider = DbRememberMeTokensProvider.forModel(
   *   () => import('#models/user'),
   *   { table: 'user_remember_tokens' }
   * )
   */
  static forModel<TokenableModel extends LucidModel>(
    model: DbRememberMeTokensProviderOptions<TokenableModel>['tokenableModel'],
    options?: Omit<DbRememberMeTokensProviderOptions<TokenableModel>, 'tokenableModel'>
  ) {
    return new DbRememberMeTokensProvider<TokenableModel>({
      tokenableModel: model,
      ...(options || {}),
    })
  }

  /**
   * Database table to use for querying remember me tokens
   */
  protected table: string

  /**
   * The length for the token secret. A secret is a cryptographically
   * secure random string.
   */
  protected tokenSecretLength: number

  /**
   * Creates a new DbRememberMeTokensProvider instance
   *
   * @param options - Configuration options for the provider
   *
   * @example
   * const provider = new DbRememberMeTokensProvider({
   *   tokenableModel: () => import('#models/user'),
   *   table: 'remember_me_tokens',
   *   tokenSecretLength: 40
   * })
   */
  constructor(protected options: DbRememberMeTokensProviderOptions<TokenableModel>) {
    this.table = options.table || 'remember_me_tokens'
    this.tokenSecretLength = options.tokenSecretLength || 40
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
        `Cannot use "${model.name}" model for managing remember me tokens. The value of column "${model.primaryKey}" is undefined or null`
      )
    }
  }

  /**
   * Maps a database row to an instance token instance
   *
   * @param dbRow - The database row containing token data
   *
   * @example
   * const token = provider.dbRowToRememberMeToken({
   *   id: 1,
   *   tokenable_id: 123,
   *   hash: 'sha256hash',
   *   // ... other columns
   * })
   */
  protected dbRowToRememberMeToken(dbRow: RememberMeTokenDbColumns): RememberMeToken {
    return new RememberMeToken({
      identifier: dbRow.id,
      tokenableId: dbRow.tokenable_id,
      hash: dbRow.hash,
      createdAt:
        typeof dbRow.created_at === 'number' ? new Date(dbRow.created_at) : dbRow.created_at,
      updatedAt:
        typeof dbRow.updated_at === 'number' ? new Date(dbRow.updated_at) : dbRow.updated_at,
      expiresAt:
        typeof dbRow.expires_at === 'number' ? new Date(dbRow.expires_at) : dbRow.expires_at,
    })
  }

  /**
   * Returns a query client instance from the parent model
   *
   * @example
   * const db = await provider.getDb()
   * const tokens = await db.from('remember_me_tokens').select('*')
   */
  protected async getDb() {
    const model = this.options.tokenableModel
    return model.$adapter.query(model).client
  }

  /**
   * Create a token for a user
   *
   * @param user - The user instance to create a token for
   * @param expiresIn - Token expiration time
   *
   * @example
   * const token = await provider.create(user, '30d')
   * console.log('Remember token:', token.value.release())
   */
  async create(user: InstanceType<TokenableModel>, expiresIn: string | number) {
    this.#ensureIsPersisted(user)

    const queryClient = await this.getDb()

    /**
     * Creating a transient token. Transient token abstracts
     * the logic of creating a random secure secret and its
     * hash
     */
    const transientToken = RememberMeToken.createTransientToken(
      user.$primaryKeyValue!,
      this.tokenSecretLength,
      expiresIn
    )

    /**
     * Row to insert inside the database. We expect exactly these
     * columns to exist.
     */
    const dbRow: Omit<RememberMeTokenDbColumns, 'id'> = {
      tokenable_id: transientToken.userId,
      hash: transientToken.hash,
      created_at: new Date(),
      updated_at: new Date(),
      expires_at: transientToken.expiresAt,
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
     * Convert db row to a remember token
     */
    return new RememberMeToken({
      identifier: id,
      tokenableId: dbRow.tokenable_id,
      secret: transientToken.secret,
      hash: dbRow.hash,
      createdAt: dbRow.created_at,
      updatedAt: dbRow.updated_at,
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
   *   console.log('Found token with id:', token.identifier)
   * }
   */
  async find(user: InstanceType<TokenableModel>, identifier: string | number | BigInt) {
    this.#ensureIsPersisted(user)

    const queryClient = await this.getDb()
    const dbRow = await queryClient
      .query<RememberMeTokenDbColumns>()
      .from(this.table)
      .where({ id: identifier, tokenable_id: user.$primaryKeyValue })
      .limit(1)
      .first()

    if (!dbRow) {
      return null
    }

    return this.dbRowToRememberMeToken(dbRow)
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
      .where({ id: identifier, tokenable_id: user.$primaryKeyValue })
      .del()
      .exec()

    return affectedRows as unknown as number
  }

  /**
   * Returns all the tokens a given user
   *
   * @param user - The user instance to get tokens for
   *
   * @example
   * const tokens = await provider.all(user)
   * console.log('User has', tokens.length, 'remember tokens')
   * tokens.forEach(token => console.log(token.identifier))
   */
  async all(user: InstanceType<TokenableModel>) {
    this.#ensureIsPersisted(user)

    const queryClient = await this.getDb()
    const dbRows = await queryClient
      .query<RememberMeTokenDbColumns>()
      .from(this.table)
      .where({ tokenable_id: user.$primaryKeyValue })
      .orderBy('id', 'desc')
      .exec()

    return dbRows.map((dbRow) => {
      return this.dbRowToRememberMeToken(dbRow)
    })
  }

  /**
   * Verifies a publicly shared remember me token and returns an
   * RememberMeToken for it.
   *
   * Returns null when unable to verify the token or find it
   * inside the storage
   *
   * @param tokenValue - The token value to verify
   *
   * @example
   * const token = await provider.verify(new Secret('rmt_abc123.def456'))
   * if (token && !token.isExpired()) {
   *   console.log('Valid remember token for user:', token.tokenableId)
   * }
   */
  async verify(tokenValue: Secret<string>) {
    const decodedToken = RememberMeToken.decode(tokenValue.release())
    if (!decodedToken) {
      return null
    }

    const db = await this.getDb()
    const dbRow = await db
      .query<RememberMeTokenDbColumns>()
      .from(this.table)
      .where({ id: decodedToken.identifier })
      .limit(1)
      .first()

    if (!dbRow) {
      return null
    }

    /**
     * Convert to remember me token instance
     */
    const rememberMeToken = this.dbRowToRememberMeToken(dbRow)

    /**
     * Ensure the token secret matches the token hash
     */
    if (!rememberMeToken.verify(decodedToken.secret) || rememberMeToken.isExpired()) {
      return null
    }

    return rememberMeToken
  }

  /**
   * Recycles a remember me token by deleting the old one and
   * creates a new one.
   *
   * Ideally, the recycle should update the existing token, but we
   * skip that for now and come back to it later and handle race
   * conditions as well.
   *
   * @param user - The user that owns the token
   * @param identifier - The token identifier to recycle
   * @param expiresIn - New expiration time
   *
   * @example
   * const newToken = await provider.recycle(user, 123, '30d')
   * console.log('Recycled token:', newToken.value.release())
   */
  async recycle(
    user: InstanceType<TokenableModel>,
    identifier: string | number | BigInt,
    expiresIn: string | number
  ): Promise<RememberMeToken> {
    await this.delete(user, identifier)
    return this.create(user, expiresIn)
  }
}
