/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../../src')
const { suite, test } = require('mocha')

suite('derive/factors/password', () => {
  test('invalid/type', () => {
    (() => {
      mfkdf.derive.factors.password(12345)
    }).should.throw(TypeError)
  })

  test('invalid/range', () => {
    (() => {
      mfkdf.derive.factors.password('')
    }).should.throw(RangeError)
  })
})
