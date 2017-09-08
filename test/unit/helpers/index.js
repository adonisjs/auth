'use strict'

const path = require('path')
const _ = require('lodash')
const Model = require('@adonisjs/lucid/src/Lucid/Model')
const cookie = require('cookie')

module.exports = {
  getConfig () {
    return _.cloneDeep({
      client: 'sqlite',
      connection: {
        filename: path.join(__dirname, '../tmp/dev.sqlite3')
      },
      debug: process.env.DEBUG
    })
  },

  createTables (db) {
    return Promise.all([
      db.schema.createTable('users', function (table) {
        table.increments()
        table.string('email')
        table.string('password')
        table.boolean('is_active')
        table.timestamps()
        table.timestamp('deleted_at').nullable()
      }),
      db.schema.createTable('tokens', function (table) {
        table.increments()
        table.integer('user_id')
        table.string('token')
        table.string('type')
        table.boolean('is_revoked')
        table.timestamps()
      })
    ])
  },

  dropTables (db) {
    return Promise.all([
      db.schema.dropTable('users'),
      db.schema.dropTable('tokens')
    ])
  },

  getRequest (req) {
    return {
      request: req,
      cookie (key) {
        if (!this.request.headers.cookie) {
          return null
        }
        const parsedCookies = cookie.parse(this.request.headers.cookie)
        return parsedCookies[key]
      },
      header (key) {
        key = key.toLowerCase()
        return this.request.headers[key]
      },
      input (key) {
        return ''
      }
    }
  },

  getResponse (req, res) {
    return {
      request: req,
      response: res,
      cookie (key, value) {
        this.response.setHeader('set-cookie', `${key}=${value}`)
      }
    }
  },

  getSession (req, res) {
    return {
      req,
      res,
      put (key, value) {
        this.res.setHeader('set-cookie', `${key}=${value}`)
      },

      get (key) {
        if (!this.req.headers.cookie) {
          return null
        }
        const parsedCookies = cookie.parse(this.req.headers.cookie)
        return parsedCookies[key]
      }
    }
  },

  getUserModel () {
    class Tokens extends Model {
      static get createdAtColumn () {
        return null
      }

      static get updatedAtColumn () {
        return null
      }
    }

    class User extends Model {
      tokens () {
        return this.hasMany(Tokens)
      }
    }

    User._bootIfNotBooted()
    Tokens._bootIfNotBooted()
    return User
  },

  sleep (time) {
    return new Promise((resolve) => {
      setTimeout(resolve, time)
    })
  }
}
