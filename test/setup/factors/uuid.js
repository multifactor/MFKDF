/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../../src')
const { suite, test } = require('mocha')

suite('setup/factors/uuid', () => {
  test('invalid/type', () => {
    mfkdf.setup.factors.uuid({ uuid: 12345 }).should.be.rejectedWith(TypeError)
    mfkdf.setup.factors.uuid({ uuid: 'hello' }).should.be.rejectedWith(TypeError)
    mfkdf.setup.factors.uuid({ id: 12345 }).should.be.rejectedWith(TypeError)
  })

  test('invalid/range', () => {
    mfkdf.setup.factors.uuid({ id: '' }).should.be.rejectedWith(RangeError)
  })

  test('valid', async () => {
    const factor = await mfkdf.setup.factors.uuid({ uuid: '6ec0bd7f-11c0-43da-975e-2a8ad9ebae0b' })
    factor.type.should.equal('uuid')
    factor.data.toString('hex').should.equal('6ec0bd7f11c043da975e2a8ad9ebae0b')
    const params = await factor.params()
    params.should.deep.equal({})
  })

  test('random', async () => {
    const factor = await mfkdf.setup.factors.uuid({})
    factor.type.should.equal('uuid')
    const output = await factor.output()
    factor.data.toString('hex').should.equal(output.uuid.replaceAll('-', ''))
    const params = await factor.params()
    params.should.deep.equal({})
  })
})
