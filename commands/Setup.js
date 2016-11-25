'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const Ioc = require('adonis-fold').Ioc
const path = require('path')
const Command = Ioc.use('Adonis/Src/Command')

class AuthSetup extends Command {

  get signature () {
    return 'auth:setup'
  }

  get description () {
    return 'Setup migrations and models for authentication'
  }

  * handle () {
    this.run('make:migration', 'create_users_table', { template: path.join(__dirname, './templates/userSchema.mustache') })
    this.run('make:migration', 'create_tokens_table', { template: path.join(__dirname, './templates/tokenSchema.mustache') })
    this.run('make:model', 'User', { template: path.join(__dirname, './templates/userModel.mustache') })
    this.run('make:model', 'Token', { template: path.join(__dirname, './templates/tokenModel.mustache') })
  }

}

module.exports = AuthSetup
