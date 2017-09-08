'use strict'

/*
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

require('@adonisjs/lucid/lib/iocResolver').setFold(require('@adonisjs/fold'))

const { ioc, registrar } = require('@adonisjs/fold')
const path = require('path')
const Macroable = require('macroable')
const { Config } = require('@adonisjs/sink')
const helpers = require('../../unit/helpers')

class Context extends Macroable {
}
Context._getters = {}
Context._macros = {}

module.exports = async () => {
  ioc.bind('Adonis/Src/HttpContext', () => {
    return Context
  })

  ioc.bind('Adonis/Src/Encryption', () => {
    return {
      encrypt (token) {
        return `e${token}`
      },

      decrypt (token) {
        return token.replace(/^e/, '')
      }
    }
  })

  ioc.bind('Adonis/Src/Exception', () => {
    return {
      handle () {}
    }
  })

  ioc.bind('Adonis/Src/Config', () => {
    const config = new Config()

    config.set('auth', {
      authenticator: 'session',
      session: {
        uid: 'email',
        password: 'password',
        model: 'App/Models/User',
        serializer: 'lucid',
        scheme: 'session'
      },
      basic: {
        uid: 'email',
        password: 'password',
        model: 'App/Models/User',
        serializer: 'lucid',
        scheme: 'basic'
      },
      jwt: {
        model: 'App/Models/User',
        scheme: 'jwt',
        serializer: 'lucid',
        uid: 'email',
        password: 'password',
        options: {
          secret: 'SECRET'
        }
      }
    })

    return config
  })

  ioc.bind('App/Models/User', () => {
    return helpers.getUserModel()
  })

  await registrar.providers([
    path.join(__dirname, '../../../providers/AuthProvider')
  ]).registerAndBoot()
}
