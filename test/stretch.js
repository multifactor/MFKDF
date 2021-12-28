/* eslint no-unused-expressions: "off" */
require('chai').should()
const mfkdf = require('../src')
const { suite, test } = require('mocha')

suite('stretch', () => {
  test('eg', async () => {
    const stretched = await mfkdf.stretch('9e26857e1d0a121f', 16)
    stretched.toString('hex').should.equal('c4b871e1edebc2907de74535a3d2bff2')
  })
})
