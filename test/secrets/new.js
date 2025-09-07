/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')
const crypto = require('crypto')

suite('secrets', () => {
  test('share-size', () => {
    let secret = crypto.randomBytes(32)
    let shares = mfkdf.secrets.share(secret, 1, 3)
    shares.should.be.an('array').of.length(3)
    shares[0].length.should.equal(32)
    shares[0].should.equal(secret)
    shares[1].length.should.equal(32)
    shares[1].should.equal(secret)
    shares[2].length.should.equal(32)
    shares[2].should.equal(secret)
    mfkdf.secrets
      .combine(shares, 1, 3)
      .toString('hex')
      .should.equal(secret.toString('hex'))
    shares[1] = null
    mfkdf.secrets
      .combine(shares, 1, 3)
      .toString('hex')
      .should.equal(secret.toString('hex'))
    shares[2] = null
    mfkdf.secrets
      .combine(shares, 1, 3)
      .toString('hex')
      .should.equal(secret.toString('hex'))

    secret = crypto.randomBytes(32)
    shares = mfkdf.secrets.share(secret, 2, 3)
    shares.should.be.an('array').of.length(3)
    shares[0].length.should.equal(32)
    shares[1].length.should.equal(32)
    shares[2].length.should.equal(32)
    mfkdf.secrets
      .combine(shares, 2, 3)
      .toString('hex')
      .should.equal(secret.toString('hex'))
    shares[1] = null
    mfkdf.secrets
      .combine(shares, 2, 3)
      .toString('hex')
      .should.equal(secret.toString('hex'))

    secret = crypto.randomBytes(32)
    shares = mfkdf.secrets.share(secret, 3, 3)
    shares.should.be.an('array').of.length(3)
    shares[0].length.should.equal(32)
    shares[1].length.should.equal(32)
    shares[2].length.should.equal(32)
    mfkdf.secrets
      .combine(shares, 3, 3)
      .toString('hex')
      .should.equal(secret.toString('hex'))
  })
})
