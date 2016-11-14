'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

/* global it, describe, before, context */
const chai = require('chai')
const expect = chai.expect
const jwt = require('jsonwebtoken')
const JwtScheme = require('../../../src/Schemes').jwt
const LucidSerializer = require('../../../src/Serializers').Lucid
const sinon = require('sinon-es6')
require('co-mocha')

const Config = function (model, options) {
  return {
    serializer: 'Lucid',
    model: model,
    uid: 'email',
    password: 'password',
    scheme: 'jwt',
    secret: 'bubblegum',
    options: options
  }
}

const request = {
  header: function () {
    return null
  },
  input: function () {}
}

const Hash = {
  verify: function * (password, actualPassword) {
    return password === actualPassword
  }
}

class Model {
  static query () {
    return this
  }
  static where () {
    return this
  }
}

describe('Authenticators', function () {
  before(function () {
    this.serializer = new LucidSerializer(Hash)
  })

  context('Jwt', function () {
    it('should not initialize if secret key is missing', function * () {
      class User extends Model {
      }
      try {
        const config = Config(User)
        config.secret = null
        const jwtAuth = new JwtScheme(request, this.serializer, config)
        expect(jwtAuth).to.equal(undefined)
      } catch (e) {
        expect(e.name).to.equal('DomainException')
        expect(e.message).to.match(/Add secret key to the jwt configuration block/)
      }
    })

    it('should return false when request does not have authorization header set', function * () {
      class User extends Model {
      }
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield jwtAuth.check()
      expect(isLoggedIn).to.equal(false)
    })

    it('should return false when request has authorization header set but value is not a valid jwt token', function * () {
      class User extends Model {
      }
      const request = {
        header: function () {
          return 'Bearer foo'
        }
      }
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield jwtAuth.check()
      expect(isLoggedIn).to.equal(false)
    })

    it('should return false when request has valid jwt token but user does not exists', function * () {
      class User extends Model {
        static * find () {
          return null
        }
      }
      const request = {
        header: function () {
          return 'Bearer ' + jwt.sign({payload: {identityId: 1}}, Config(User).secret)
        }
      }
      sinon.spy(User, 'find')
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield jwtAuth.check()
      expect(isLoggedIn).to.equal(false)
      expect(User.find.calledOnce).to.equal(true)
      expect(User.find.calledWith(1)).to.equal(true)
      User.find.restore()
    })

    it('should return true when request has valid jwt token and serializer returns user', function * () {
      class User extends Model {
        static * find (id) {
          return {
            id: id
          }
        }
      }
      const request = {
        header: function () {
          return 'Bearer ' + jwt.sign({payload: {identityId: 1}}, Config(User).secret)
        }
      }
      sinon.spy(User, 'find')
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield jwtAuth.check()
      expect(isLoggedIn).to.equal(true)
      expect(User.find.calledOnce).to.equal(true)
      expect(User.find.calledWith(1)).to.equal(true)
      expect(jwtAuth.user).deep.equal({id: 1})
      User.find.restore()
    })

    it('should return true when request has valid jwt token as a query string and serializer returns user', function * () {
      class User extends Model {
        static * find (id) {
          return {
            id: id
          }
        }
      }
      const request = {
        header: function () {
          return null
        },
        input: function () {
          return jwt.sign({payload: {identityId: 1}}, Config(User).secret)
        }
      }
      sinon.spy(User, 'find')
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield jwtAuth.check()
      expect(isLoggedIn).to.equal(true)
      expect(User.find.calledOnce).to.equal(true)
      expect(User.find.calledWith(1)).to.equal(true)
      expect(jwtAuth.user).deep.equal({id: 1})
      User.find.restore()
    })

    it('should return user if check is successful', function * () {
      class User extends Model {
        static * find (id) {
          return {
            id: id
          }
        }
      }
      const request = {
        header: function () {
          return 'Bearer ' + jwt.sign({payload: {identityId: 1}}, Config(User).secret)
        }
      }
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User))
      const user = yield jwtAuth.getUser()
      expect(user).deep.equal({id: 1})
    })

    it('should throw an error when trying to generate token without a user', function * () {
      class User {
        static get primaryKey () {
          return 'id'
        }
      }
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User))
      try {
        yield jwtAuth.generate()
        expect(true).to.equal(false)
      } catch (e) {
        expect(e.name).to.equal('InvalidArgumentException')
        expect(e.message).to.match(/user is required to generate a jwt token/)
      }
    })

    it('should throw an error when value of primaryKey is not defined', function * () {
      class User {
        static get primaryKey () {
          return 'id'
        }
      }
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User))
      try {
        yield jwtAuth.generate({foo: 'bar'})
        expect(true).to.equal(false)
      } catch (e) {
        expect(e.name).to.equal('InvalidArgumentException')
        expect(e.message).to.match(/Value for id is null for given user/)
      }
    })

    it('should be able to generate a token for a given user', function * () {
      class User {
        static get primaryKey () {
          return 'id'
        }
      }
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User))
      const token = yield jwtAuth.generate({id: 1})
      expect(jwt.verify(token, Config(User).secret).payload.identityId).to.equal(1)
    })

    it('should be able to generate a token for a given user with a custom payload', function * () {
      class User {
        static get primaryKey () {
          return 'id'
        }
      }
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User))
      const token = yield jwtAuth.generate({id: 1}, {name: 'test'})
      expect(jwt.verify(token, Config(User).secret).payload.data).to.deep.equal({name: 'test'})
    })

    it('should be able to define issuer while generating a token', function * () {
      class User {
        static get primaryKey () {
          return 'id'
        }
      }
      const jwtAuth = new JwtScheme(request, this.serializer, Config(User, {issuer: 'adonisjs.com'}))
      const token = yield jwtAuth.generate({id: 1})
      const decoded = jwt.verify(token, Config(User).secret)
      expect(decoded.payload.identityId).to.equal(1)
      expect(decoded.iss).to.equal('adonisjs.com')
    })

    it('should throw UserNotFoundException when serializer find results null', function * () {
      class User extends Model {
        static query () {
          return this
        }

        static where () {
          return this
        }

        static * first () {
          return null
        }
      }
      const sessionAuth = new JwtScheme(request, this.serializer, Config(User))
      sinon.spy(User, 'query')
      sinon.spy(User, 'where')
      sinon.spy(User, 'first')
      try {
        yield sessionAuth.validate('foo@bar.com', 'secret')
        expect(true).to.equal(false)
      } catch (e) {
        expect(e.name).to.equal('UserNotFoundException')
        expect(e.message).to.match(/Unable to find user with foo@bar\.com email/)
        expect(User.query.calledOnce).to.equal(true)
        expect(User.where.calledOnce).to.equal(true)
        expect(User.first.calledOnce).to.equal(true)
        expect(User.where.calledWith('email', 'foo@bar.com')).to.equal(true)
      } finally {
        User.query.restore()
        User.where.restore()
        User.first.restore()
      }
    })

    it('should throw PasswordMisMatch Exception when serializer passwords do not match', function * () {
      class User extends Model {
        static query () {
          return this
        }

        static where () {
          return this
        }

        static * first () {
          return {password: 'foo'}
        }
      }
      const sessionAuth = new JwtScheme(request, this.serializer, Config(User))
      sinon.spy(User, 'query')
      sinon.spy(User, 'where')
      sinon.spy(User, 'first')
      try {
        yield sessionAuth.validate('foo@bar.com', 'secret')
        expect(true).to.equal(false)
      } catch (e) {
        expect(e.name).to.equal('PasswordMisMatchException')
        expect(e.message).to.match(/Password does not match/)
        expect(User.query.calledOnce).to.equal(true)
        expect(User.where.calledOnce).to.equal(true)
        expect(User.first.calledOnce).to.equal(true)
        expect(User.where.calledWith('email', 'foo@bar.com')).to.equal(true)
      } finally {
        User.query.restore()
        User.where.restore()
        User.first.restore()
      }
    })

    it('should generate the token when password does match', function * () {
      class User extends Model {
        static get primaryKey () {
          return 'id'
        }

        static query () {
          return this
        }

        static where () {
          return this
        }

        static * first () {
          return {password: 'secret', id: 1}
        }
      }
      const sessionAuth = new JwtScheme(request, this.serializer, Config(User))
      sinon.spy(User, 'query')
      sinon.spy(User, 'where')
      sinon.spy(User, 'first')
      const token = yield sessionAuth.attempt('foo@bar.com', 'secret')
      const decoded = jwt.verify(token, Config(User).secret)
      expect(decoded.payload.identityId).to.equal(1)
      User.query.restore()
      User.where.restore()
      User.first.restore()
    })
  })
})
