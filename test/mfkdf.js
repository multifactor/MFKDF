/* eslint no-unused-expressions: "off" */
require('chai').should()
const mfkdf = require('../src')
const { suite, test } = require('mocha')

suite('mfkdf', () => {
  test('true', () => {
    mfkdf.derive().should.be.true
  })
})
