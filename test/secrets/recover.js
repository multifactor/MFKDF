/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('secrets/recover', () => {
  test('k-of-n', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678'), 2, 3)

    const shares1 = mfkdf.secrets.recover([shares[0], shares[1], null], 2, 3)
    shares1.should.deep.equal(shares)

    const shares2 = mfkdf.secrets.recover([shares[0], null, shares[2]], 2, 3)
    shares2.should.deep.equal(shares)

    const shares3 = mfkdf.secrets.recover([null, shares[1], shares[2]], 2, 3)
    shares3.should.deep.equal(shares)

    const shares4 = mfkdf.secrets.recover([shares2[0], null, shares2[2]], 2, 3)
    shares4.should.deep.equal(shares)
  })

  test('1-of-n', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678'), 1, 3)

    const shares1 = mfkdf.secrets.recover([shares[0], null, null], 1, 3)
    shares1.should.deep.equal(shares)

    const shares2 = mfkdf.secrets.recover([null, shares[1], null], 1, 3)
    shares2.should.deep.equal(shares)

    const shares3 = mfkdf.secrets.recover([null, null, shares[2]], 1, 3)
    shares3.should.deep.equal(shares)

    const shares4 = mfkdf.secrets.recover([null, shares2[1], null], 1, 3)
    shares4.should.deep.equal(shares)
  })

  test('n-of-n', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678'), 3, 3)

    const shares1 = mfkdf.secrets.recover([shares[0], shares[1], shares[2]], 3, 3)
    shares1.should.deep.equal(shares)

    const shares2 = mfkdf.secrets.recover([shares1[0], shares1[1], shares1[2]], 3, 3)
    shares2.should.deep.equal(shares)
  })

  test('invalid/count n-of-n', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678'), 3, 3);

    (() => {
      mfkdf.secrets.recover([shares[0], shares[1]], 3, 3)
    }).should.throw(RangeError)
  })

  test('invalid/count k-of-n 1', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678'), 2, 3);

    (() => {
      mfkdf.secrets.recover([shares[0], shares[1]], 2, 3)
    }).should.throw(RangeError)
  })

  test('invalid/count k-of-n 2', () => {
    const shares = mfkdf.secrets.share(Buffer.from('12345678'), 2, 3);

    (() => {
      mfkdf.secrets.recover([shares[0], null, null], 2, 3)
    }).should.throw(RangeError)
  })

  test('invalid/type', () => {
    (() => {
      mfkdf.secrets.recover('hello', 1, 1)
    }).should.throw(TypeError);

    (() => {
      mfkdf.secrets.recover([Buffer.from('12345678')], 'hello', 1)
    }).should.throw(TypeError);

    (() => {
      mfkdf.secrets.recover([Buffer.from('12345678')], 1, 'hello')
    }).should.throw(TypeError)
  })

  test('invalid/range', () => {
    (() => {
      mfkdf.secrets.recover([], 1, 1)
    }).should.throw(RangeError);

    (() => {
      mfkdf.secrets.recover([Buffer.from('12345678')], 0, 1)
    }).should.throw(RangeError);

    (() => {
      mfkdf.secrets.recover([Buffer.from('12345678')], 1, 0)
    }).should.throw(RangeError);

    (() => {
      mfkdf.secrets.recover([Buffer.from('12345678')], 2, 1)
    }).should.throw(RangeError)
  })
})
