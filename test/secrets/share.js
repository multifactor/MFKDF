/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')
const rcc = require('randchacha')

suite('secrets/share', () => {
  test('valid', () => {
    const rng = new rcc.ChaChaRng(Buffer.alloc(32, 10))
    mfkdf.secrets.share(Buffer.from('12345678'), 1, 1, rng)
  })

  test('invalid/type', () => {
    (() => {
      const rng = new rcc.ChaChaRng(Buffer.alloc(32, 10))
      mfkdf.secrets.share('hello', 1, 1, rng)
    }).should.throw(TypeError);

    (() => {
      const rng = new rcc.ChaChaRng(Buffer.alloc(32, 10))
      mfkdf.secrets.share(Buffer.from('12345678'), 'hello', 1, rng)
    }).should.throw(TypeError);

    (() => {
      const rng = new rcc.ChaChaRng(Buffer.alloc(32, 10))
      mfkdf.secrets.share(Buffer.from('12345678'), 1, 'hello', rng)
    }).should.throw(TypeError)
  })

  test('invalid/range', () => {
    (() => {
      const rng = new rcc.ChaChaRng(Buffer.alloc(32, 10))
      mfkdf.secrets.share(Buffer.from(''), 1, 1, rng)
    }).should.throw(RangeError);

    (() => {
      const rng = new rcc.ChaChaRng(Buffer.alloc(32, 10))
      mfkdf.secrets.share(Buffer.from('12345678'), 0, 1, rng)
    }).should.throw(RangeError);

    (() => {
      const rng = new rcc.ChaChaRng(Buffer.alloc(32, 10))
      mfkdf.secrets.share(Buffer.from('12345678'), 1, 0, rng)
    }).should.throw(RangeError);

    (() => {
    const rng = new rcc.ChaChaRng(Buffer.alloc(32, 10))
      mfkdf.secrets.share(Buffer.from('12345678'), 2, 1, rng)
    }).should.throw(RangeError)
  })
})
