/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('asymmetric', () => {
  suite('encryption', () => {
    test('rsa1024', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])
      const ct = await setup.encrypt('hello world', 'rsa1024')
      const pt = await setup.decrypt(ct, 'rsa1024')
      pt.toString().should.equal('hello world')
    })

    test('rsa2048', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])
      const ct = await setup.encrypt('hello world', 'rsa2048')
      const pt = await setup.decrypt(ct, 'rsa2048')
      pt.toString().should.equal('hello world')
    })
  })

  suite('signatures', () => {
    test('rsa1024', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])
      const signature = await setup.sign('hello world', 'rsa1024')
      const validity = await setup.verify('hello world', signature, 'rsa1024')
      validity.should.be.true
    })

    test('rsa2048', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])
      const signature = await setup.sign('hello world', 'rsa2048')
      const validity = await setup.verify('hello world', signature, 'rsa2048')
      validity.should.be.true
    }).timeout(10000)

    test('rsa3072', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])
      const signature = await setup.sign('hello world', 'rsa3072')
      const validity = await setup.verify('hello world', signature, 'rsa3072')
      validity.should.be.true
    }).timeout(50000)

    test('defaults', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])
      const signature = await setup.sign('hello world')
      const validity = await setup.verify('hello world', signature)
      validity.should.be.true
      await setup.getAsymmetricKeyPair()
    }).timeout(50000)

    test('ed25519', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])
      await setup.getAsymmetricKeyPair('ed25519')
    })

    test('unknown', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])
      setup.getAsymmetricKeyPair('unknown').should.be.rejectedWith(RangeError)
    })

    test('errors', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])
      setup.sign(12345, 'rsa1024').should.be.rejectedWith(TypeError)
      const signature = await setup.sign('hello world')
      setup.verify(12345, signature).should.be.rejectedWith(TypeError)
    }).timeout(10000)
  })
})
