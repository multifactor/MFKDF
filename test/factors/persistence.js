/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('persistence', () => {
  test('valid', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.hotp(),
      await mfkdf.setup.factors.password('password')
    ])

    const hotp = setup.persistFactor('hotp')

    const derive = await mfkdf.derive.key(setup.policy, {
      hotp: mfkdf.derive.factors.persisted(hotp),
      password: mfkdf.derive.factors.password('password')
    })

    derive.key.toString('hex').should.equal(setup.key.toString('hex'))
  })

  test('share/type', async () => {
    (() => {
      mfkdf.derive.factors.persisted('12345')
    }).should.throw(TypeError)
  })
})
