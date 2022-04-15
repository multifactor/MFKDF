/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('secrets/share', () => {
  test('valid', () => {
    mfkdf.secrets.combine([Buffer.from('12345678')], 1, 1)
  })

  test('invalid/type', () => {
    (() => {
      mfkdf.secrets.combine('hello', 1, 1)
    }).should.throw(TypeError);

    (() => {
      mfkdf.secrets.combine([Buffer.from('12345678')], 'hello', 1)
    }).should.throw(TypeError);

    (() => {
      mfkdf.secrets.combine([Buffer.from('12345678')], 1, 'hello')
    }).should.throw(TypeError)
  })

  test('invalid/range', () => {
    (() => {
      mfkdf.secrets.combine([], 1, 1)
    }).should.throw(RangeError);

    (() => {
      mfkdf.secrets.combine([Buffer.from('12345678')], 0, 1)
    }).should.throw(RangeError);

    (() => {
      mfkdf.secrets.combine([Buffer.from('12345678')], 1, 0)
    }).should.throw(RangeError);

    (() => {
      mfkdf.secrets.combine([Buffer.from('12345678')], 2, 1)
    }).should.throw(RangeError)
  })
})
