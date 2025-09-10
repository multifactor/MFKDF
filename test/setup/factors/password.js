/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../../src')
const { suite, test } = require('mocha')

suite('setup/factors/password', () => {
  test('invalid/type', async () => {
    await mfkdf.setup.factors.password(12345).should.be.rejectedWith(TypeError)
    await mfkdf.setup.factors
      .password('password', { id: 12345 })
      .should.be.rejectedWith(TypeError)
  })

  test('invalid/range', async () => {
    await mfkdf.setup.factors.password('').should.be.rejectedWith(RangeError)
    await mfkdf.setup.factors
      .password('password', { id: '' })
      .should.be.rejectedWith(RangeError)
  })

  test('valid', async () => {
    const factor = await mfkdf.setup.factors.password('hello')
    factor.type.should.equal('password')
    factor.data.toString('hex').should.equal('68656c6c6f')
    const params = await factor.params()
    params.should.deep.equal({})
  })
})
