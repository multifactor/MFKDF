/* eslint no-unused-expressions: "off" */
require('chai').should()
const mfkdf = require('../src')
const { suite, test } = require('mocha')

suite('recoveryCodeFactor', () => {
  test('example', async () => {
    const recoveryCodeFactor = await mfkdf.factors.recoveryCode(
      '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d',
      { size: 16 }
    )
    recoveryCodeFactor.toString('hex').should.equal('51766dfd9a56d3faa51b263796747a94')
  })
})
