/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('secrets', () => {
  test('1-of-1', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678', 'hex'), 1, 1)
    shares.should.be.an('array').of.length(1)
    shares[0].toString('hex').should.equal('12345678')

    const secret = mfkdf.secrets.combine(shares, 1, 1)
    secret.toString('hex').should.equal('12345678');

    (() => {
      mfkdf.secrets.combine([], 1, 1)
    }).should.throw(RangeError)
  })

  test('1-of-n', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678', 'hex'), 1, 5)
    shares.should.be.an('array').of.length(5)
    shares[0].toString('hex').should.equal('12345678')

    const secret1 = mfkdf.secrets.combine(shares, 1, 5)
    secret1.toString('hex').should.equal('12345678')

    const secret2 = mfkdf.secrets.combine(
      [shares[0], shares[1], shares[2]],
      1,
      5
    )
    secret2.toString('hex').should.equal('12345678')

    const secret3 = mfkdf.secrets.combine([shares[0]], 1, 5)
    secret3.toString('hex').should.equal('12345678')

    const secret4 = mfkdf.secrets.combine([null, shares[0], null], 1, 5)
    secret4.toString('hex').should.equal('12345678');

    (() => {
      mfkdf.secrets.combine([], 1, 5)
    }).should.throw(RangeError)
  })

  test('k-of-n', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678', 'hex'), 2, 3)
    shares.should.be.an('array').of.length(3)

    const secret1 = mfkdf.secrets.combine(
      [shares[0], shares[1], shares[2]],
      2,
      3
    )
    secret1.toString('hex').should.equal('12345678')

    const secret2 = mfkdf.secrets.combine([null, shares[1], shares[2]], 2, 3)
    secret2.toString('hex').should.equal('12345678')

    const secret3 = mfkdf.secrets.combine([shares[0], null, shares[2]], 2, 3)
    secret3.toString('hex').should.equal('12345678')

    const secret4 = mfkdf.secrets.combine([shares[0], shares[1], null], 2, 3)
    secret4.toString('hex').should.equal('12345678');

    (() => {
      mfkdf.secrets.combine([shares[0], shares[1]], 2, 3)
    }).should.throw(RangeError)
  })

  test('k-of-n (medium)', () => {
    const shares = mfkdf.secrets.share(
      Buffer.from('35002a68d437', 'hex'),
      5,
      255
    )

    const secret1 = mfkdf.secrets.combine(shares, 5, 255)
    secret1.toString('hex').should.equal('35002a68d437')
  })

  test('k-of-n (large)', () => {
    const shares = mfkdf.secrets.share(
      Buffer.from('35002a68d437', 'hex'),
      5,
      255
    )
    shares.should.be.an('array').of.length(255)

    const secret1 = mfkdf.secrets.combine(shares, 5, 255)
    secret1.toString('hex').should.equal('35002a68d437')

    for (let i = 1; i < 250; i++) {
      shares[i] = null
    }

    const secret2 = mfkdf.secrets.combine(shares, 5, 255)
    secret2.toString('hex').should.equal('35002a68d437')

    shares[251] = null;

    (() => {
      mfkdf.secrets.combine(shares, 5, 1024)
    }).should.throw(RangeError)
  })

  test('2-of-2', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678', 'hex'), 2, 2)
    shares.should.be.an('array').of.length(2)
  })

  test('n-of-n', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678', 'hex'), 5, 5)
    shares.should.be.an('array').of.length(5)

    const secret = mfkdf.secrets.combine(shares, 5, 5)
    secret.toString('hex').should.equal('12345678');

    (() => {
      mfkdf.secrets.combine([shares[0], shares[1], shares[2], shares[3]], 5, 5)
    }).should.throw(RangeError)
  })
})
