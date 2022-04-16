/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../../src')
const { suite, test } = require('mocha')

suite('derive/factors/uuid', () => {
  test('invalid/type', () => {
    (() => {
      mfkdf.derive.factors.uuid(12345)
    }).should.throw(TypeError)
  })

  test('invalid/range', () => {
    (() => {
      mfkdf.derive.factors.uuid('')
    }).should.throw(TypeError)
  })
})
