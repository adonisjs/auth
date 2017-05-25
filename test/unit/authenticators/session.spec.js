'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

/* global it, describe, context, before */
const chai = require('chai')
const expect = chai.expect
const SessionScheme = require('../../../src/Schemes/Session')
const LucidSerializer = require('../../../src/Serializers').Lucid
const sinon = require('sinon-es6')
require('co-mocha')

const Config = function (model) {
  return {
    serializer: 'Lucid',
    model: model,
    scheme: 'session',
    uid: 'email',
    password: 'password'
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

const request = {
  session: {
    put: function * () {},
    get: function * () {},
    forget: function * () {}
  }
}

describe('Authenticators', function () {
  before(function () {
    const Hash = {
      verify: function * () {
        return true
      }
    }
    this.serializer = new LucidSerializer(Hash)
  })
  context('Session', function () {
    it('should throw password mismatch error when serializer validateCredentials returns false', function * () {
      class User extends Model {
        static * first () {
          return {
            password: '123'
          }
        }
      }
      const customHash = {
        verify: function * () {
          return false
        }
      }
      const serializer = new LucidSerializer(customHash)
      const sessionAuth = new SessionScheme(request, serializer, Config(User))
      try {
        yield sessionAuth.validate('foo@bar.com', 'secret')
        expect(true).to.equal(false)
      } catch (e) {
        expect(e.name).to.equal('PasswordMisMatchException')
        expect(e.message).to.match(/Password does not match/)
      }
    })

    it('should return true when serializer returns a user and verifyCredentials returns true', function * () {
      class User extends Model {
        static * first () {
          return {
            password: '123'
          }
        }
      }
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const isValid = yield sessionAuth.validate('foo@bar.com', 'secret')
      expect(isValid).to.equal(true)
    })

    it('should return user object when returnUser is passed along with validate method', function * () {
      class User extends Model {
        static * first () {
          return {
            password: '123'
          }
        }
      }
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const user = yield sessionAuth.validate('foo@bar.com', 'secret', {}, true)
      expect(user).deep.equal({password: '123'})
    })

    it('should login a user when validate methods returns user', function * () {
      class User extends Model {
        static * first () {
          return {
            password: '123',
            id: 1
          }
        }
        static get primaryKey () {
          return 'id'
        }
      }
      sinon.spy(request.session, 'put')
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const tryLogin = yield sessionAuth.attempt('foo@bar.com', 'secret', {})
      expect(tryLogin).to.equal(true)
      expect(request.session.put.calledOnce).to.equal(true)
      expect(request.session.put.calledWith('adonis-auth', 1)).to.equal(true)
      expect(sessionAuth.user).deep.equal({password: '123', id: 1})
    })

    it('should return true when user property exists on the auth instance', function * () {
      class User extends Model {
      }
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      sessionAuth.user = new User()
      const isLoggedIn = yield sessionAuth.check()
      expect(isLoggedIn).to.equal(true)
    })

    it('should return false when session cookie does not exists', function * () {
      class User extends Model {
      }
      sinon.stub(request.session, 'get').returns(function * () { return null })
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield sessionAuth.check()
      expect(isLoggedIn).to.equal(false)
      request.session.get.restore()
    })

    it('should return false when session cookie exists but user does not exists for given id', function * () {
      class User extends Model {
        static * find () {
          return null
        }
      }
      sinon.stub(request.session, 'get').returns(function * () { return 1 })
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield sessionAuth.check()
      expect(isLoggedIn).to.equal(false)
      request.session.get.restore()
    })

    it('should return true when session cookie and user both exists', function * () {
      class User extends Model {
        static * find (id) {
          return {
            id: id
          }
        }
      }
      sinon.stub(request.session, 'get').returns(function * () { return 2 })
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield sessionAuth.check()
      expect(isLoggedIn).to.equal(true)
      expect(sessionAuth.user).deep.equal({id: 2})
      request.session.get.restore()
    })

    it('should return null when check methods returns false', function * () {
      class User extends Model {
      }
      sinon.stub(request.session, 'get').returns(function * () { return null })
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const loggedUser = yield sessionAuth.getUser()
      expect(loggedUser).to.equal(null)
      request.session.get.restore()
    })

    it('should return user when check methods returns true', function * () {
      class User extends Model {
        static * find (id) {
          return {
            id: id
          }
        }
      }
      sinon.stub(request.session, 'get').returns(function * () { return 1 })
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const loggedUser = yield sessionAuth.getUser()
      expect(loggedUser).deep.equal({id: 1})
      request.session.get.restore()
    })

    it('should return false when findById returns null', function * () {
      class User extends Model {
        static * find () {
          return null
        }
      }
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield sessionAuth.loginViaId(1)
      expect(isLoggedIn).to.equal(false)
    })

    it('should return true when findById returns a user', function * () {
      class User extends Model {
        static * find (id) {
          return {id: id}
        }
        static get primaryKey () {
          return 'id'
        }
      }
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield sessionAuth.loginViaId(1)
      expect(isLoggedIn).to.equal(true)
      expect(sessionAuth.user).deep.equal({id: 1})
    })

    it('should throw an error when trying to login a user without primaryValue', function * () {
      class User extends Model {
        static get primaryKey () {
          return 'id'
        }
      }
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      try {
        yield sessionAuth.login(new User())
        expect(true).to.equal(false)
      } catch (e) {
        expect(e.name).to.equal('InvalidArgumentException')
        expect(e.message).to.match(/Value for id is null/)
      }
    })

    it('should login user using user object', function * () {
      class User extends Model {
        constructor () {
          super()
          this.id = 1
        }
        static get primaryKey () {
          return 'id'
        }
      }
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const isLoggedIn = yield sessionAuth.login(new User())
      expect(isLoggedIn).to.equal(true)
      expect(sessionAuth.user).deep.equal({id: 1})
    })

    it('should logout a user by setting session and local user instance to null', function * () {
      class User extends Model {
      }
      sinon.spy(request.session, 'forget')
      const sessionAuth = new SessionScheme(request, this.serializer, Config(User))
      const isLoggedOut = yield sessionAuth.logout(new User())
      expect(isLoggedOut).to.equal(true)
      expect(sessionAuth.user).to.equal(null)
      expect(request.session.forget.calledOnce).to.equal(true)
      expect(request.session.forget.calledWith('adonis-auth')).to.equal(true)
      request.session.forget.restore()
    })
  })
})
