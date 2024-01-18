/*
 * @adonisjs/auth
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { Secret } from '@adonisjs/core/helpers'
import type { LucidModel } from '@adonisjs/lucid/types/model'

import { RememberMeToken } from '../remember_me_token.js'
import type {
  RememberMeTokenDbColumns,
  RememberMeTokensProviderContract,
  DbRememberMeTokensProviderOptions,
} from '../types.js'
import { RuntimeException } from '@adonisjs/core/exceptions'

/**
 * DbAccessTokensProvider uses lucid database service to fetch and
 * persist tokens for a given user.
 *
 * The user must be an instance of the associated user model.
 */
export class DbRememberMeTokensProvider<TokenableModel extends LucidModel>
  implements RememberMeTokensProviderContract<TokenableModel>
{
  /**
   * Create tokens provider instance for a given Lucid model
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
   * Duration after which the token should expire
   */
  protected expiresIn: string | number

  /**
   * Database table to use for querying access tokens
   */
  protected table: string

  /**
   * The length for the token secret. A secret is a cryptographically
   * secure random string.
   */
  protected tokenSecretLength: number

  constructor(protected options: DbRememberMeTokensProviderOptions<TokenableModel>) {
    this.table = options.table || 'remember_me_tokens'
    this.expiresIn = options.expiresIn || '2 years'
    this.tokenSecretLength = options.tokenSecretLength || 40
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
   */
  protected dbRowToAccessToken(dbRow: RememberMeTokenDbColumns): RememberMeToken {
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
   */
  protected async getDb() {
    const model = this.options.tokenableModel
    return model.$adapter.query(model).client
  }

  /**
   * Create a token for a user
   */
  async create(user: InstanceType<TokenableModel>, expiresIn?: string | number) {
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
      expiresIn || this.expiresIn
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
    const [id] = await queryClient.table(this.table).insert(dbRow)

    /**
     * Convert db row to an access token
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

    return this.dbRowToAccessToken(dbRow)
  }

  /**
   * Delete a token by its id
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
      return this.dbRowToAccessToken(dbRow)
    })
  }

  /**
   * Verifies a publicly shared access token and returns an
   * access token for it.
   *
   * Returns null when unable to verify the token or find it
   * inside the storage
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
   * Recycles a remember me token by deleting the old one and
   * creates a new one.
   *
   * Ideally, the recycle should update the existing token, but we
   * skip that for now and come back to it later and handle race
   * conditions as well.
   */
  async recycle(
    user: InstanceType<TokenableModel>,
    identifier: string | number | BigInt,
    expiresIn?: string | number
  ): Promise<RememberMeToken> {
    await this.delete(user, identifier)
    return this.create(user, expiresIn)
  }
}
