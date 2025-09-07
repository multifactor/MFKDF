/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('encrypt', () => {
  suite('utils', () => {
    test('subkey', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({
          id: 'uuid1',
          uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
        })
      ])

      const key3 = await setup.getSubkey()
      const key4 = await setup.getSubkey(32, '', 'sha512')
      key3.toString('hex').should.equal(key4.toString('hex'))
    })
  })
})
