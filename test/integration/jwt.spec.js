'use strict'

/**
 * adonis-auth
 *
 * (c) Harminder Virk <virk@adonisjs.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

/* global it, describe, context, before  */
const chai = require('chai')
const expect = chai.expect
const http = require('http')
const supertest = require('supertest')
const jwt = require('jsonwebtoken')
const co = require('co')
const setup = require('./setup')
require('co-mocha')

describe('Authenticators', function () {
  before(function * () {
    yield setup.registerProviders()
  })

  context('Jwt Auth', function () {
    it('should return false when request does not have Auth header', function * () {
      const server = http.createServer(function (req, res) {
        const request = setup.decorateRequest(req, 'jwt')
        co(function * () {
          return yield request.auth.check()
        })
        .then(function (check) {
          res.writeHead(200, {'content-type': 'application/json'})
          res.write(JSON.stringify(check))
          res.end()
        })
        .catch(function (error) {
          res.writeHead(500, {'content-type': 'application/json'})
          res.write(JSON.stringify(error))
          res.end()
        })
      })
      const response = yield supertest(server).get('/')
      expect(response.body).to.equal(false)
    })

    it('should return false when request has invalid token', function * () {
      const server = http.createServer(function (req, res) {
        const request = setup.decorateRequest(req, 'jwt')
        co(function * () {
          return yield request.auth.check()
        })
        .then(function (check) {
          res.writeHead(200, {'content-type': 'application/json'})
          res.write(JSON.stringify(check))
          res.end()
        })
        .catch(function (error) {
          res.writeHead(500, {'content-type': 'application/json'})
          res.write(JSON.stringify(error))
          res.end()
        })
      })
      const response = yield supertest(server).get('/').set('Authorization', 'Bearer foo')
      expect(response.body).to.equal(false)
    })

    it('should return false when token is correct but there is no user for a given token', function * () {
      const server = http.createServer(function (req, res) {
        const request = setup.decorateRequest(req, 'jwt')
        co(function * () {
          return yield request.auth.check()
        })
        .then(function (check) {
          res.writeHead(200, {'content-type': 'application/json'})
          res.write(JSON.stringify(check))
          res.end()
        })
        .catch(function (error) {
          res.writeHead(500, {'content-type': 'application/json'})
          res.write(JSON.stringify(error))
          res.end()
        })
      })
      const jwtToken = jwt.sign({payload: {identityId: 1}}, 'bubblegum')
      const response = yield supertest(server).get('/').set('Authorization', `Bearer ${jwtToken}`)
      expect(response.body).to.equal(false)
    })

    it('should return true when credentials are correct', function * () {
      const server = http.createServer(function (req, res) {
        const request = setup.decorateRequest(req, 'jwt')
        co(function * () {
          return yield request.auth.check()
        })
        .then(function (check) {
          res.writeHead(200, {'content-type': 'application/json'})
          res.write(JSON.stringify(check))
          res.end()
        })
        .catch(function (error) {
          res.writeHead(500, {'content-type': 'application/json'})
          res.write(JSON.stringify(error))
          res.end()
        })
      })
      const jwtToken = jwt.sign({payload: {identityId: 2}}, 'bubblegum')
      const response = yield supertest(server).get('/').set('Authorization', `Bearer ${jwtToken}`)
      expect(response.body).to.equal(true)
    })
  })
})
