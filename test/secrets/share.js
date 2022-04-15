/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('secrets/share', () => {
  test('valid', () => {
    mfkdf.secrets.share(Buffer.from('12345678'), 1, 1)
  })

  test('invalid/type', () => {
    (() => {
      mfkdf.secrets.share('hello', 1, 1)
    }).should.throw(TypeError);

    (() => {
      mfkdf.secrets.share(Buffer.from('12345678'), 'hello', 1)
    }).should.throw(TypeError);

    (() => {
      mfkdf.secrets.share(Buffer.from('12345678'), 1, 'hello')
    }).should.throw(TypeError)
  })

  test('invalid/range', () => {
    (() => {
      mfkdf.secrets.share(Buffer.from(''), 1, 1)
    }).should.throw(RangeError);

    (() => {
      mfkdf.secrets.share(Buffer.from('12345678'), 0, 1)
    }).should.throw(RangeError);

    (() => {
      mfkdf.secrets.share(Buffer.from('12345678'), 1, 0)
    }).should.throw(RangeError)
  })
})
