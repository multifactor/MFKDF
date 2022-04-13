/* eslint no-unused-expressions: "off" */
require('chai').should()
const mfkdf = require('../src')
const { suite, test } = require('mocha')

suite('hotpFactor', () => {
  test('example', async () => {
    const hotpFactor = await mfkdf.factors.hotp(
      0,
      0,
      { size: 16 }
    )
    hotpFactor.toString('hex').should.equal('6baabde48c93cc7408e7b3230ee6aba4')
  })
})
