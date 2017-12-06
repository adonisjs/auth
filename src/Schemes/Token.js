'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const uuid = require('uuid')
const _ = require('lodash')
const ApiScheme = require('./Api')
const GE = require('@adonisjs/generic-exceptions')
const CE = require('../Exceptions')

class TokenScheme extends ApiScheme {
  constructor (Encryption) {
    super()
    this.Encryption = Encryption
  }

  /**
   * Generates a plain personal API token for a user
   *
   * @method generate
   * @async
   *
   * @param  {Object} user
   *
   * @return {Object}
   */
  async generate (user) {
    /**
     * Throw exception when user is not persisted to
     * database
     */
    const userId = user[this.primaryKey]
    if (!userId) {
      throw GE.RuntimeException.invoke('Primary key value is missing for user')
    }

    const token = uuid.v4().replace(/-/g, '')
    await this._serializerInstance.saveToken(user, token, 'plain_token')

    return { type: 'bearer', token }
  }

  /**
   * Check whether the api token has been passed
   * in the request header and is it valid or
   * not.
   *
   * @method check
   *
   * @return {Boolean}
   */
  async check () {
    if (this.user) {
      return true
    }

    const token = this.getAuthHeader()
    if (!token) {
      throw CE.InvalidApiToken.invoke()
    }

    this.user = await this._serializerInstance.findByToken(token, 'plain_token')

    /**
     * Throw exception when user is not found
     */
    if (!this.user) {
      throw CE.InvalidApiToken.invoke()
    }
    return true
  }

  /**
   * List tokens for a given user for the
   * currently logged in user.
   *
   * @method listTokens
   *
   * @param  {Object} forUser
   *
   * @return {Object}
   */
  async listTokens (forUser) {
    forUser = forUser || this.user
    if (!forUser) {
      return this._serializerInstance.fakeResult()
    }

    const tokens = await this._serializerInstance.listTokens(forUser, 'plain_token')

    /**
     * We need to pull the `rows` when serializer is lucid, otherwise
     * we use the array as it is.
     *
     * @type {Array}
     */
    const tokensArray = _.isArray(tokens) ? tokens : tokens.rows

    /**
     * If tokens array is empty then return the fake response
     */
    if (!_.isArray(tokensArray) || !_.size(tokensArray)) {
      return this._serializerInstance.fakeResult()
    }

    /**
     * Encrypt the tokens
     */
    tokensArray.forEach((token) => {
      token.token = this.Encryption.encrypt(token.token)
    })

    return tokens
  }
}

module.exports = TokenScheme
