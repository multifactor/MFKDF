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
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])

      const key1 = await setup.getSubkey(32, 'AES256', 'sha256')
      const key2 = await setup.getSymmetricKey('aes256')
      key1.toString('hex').should.equal(key2.toString('hex'))

      const key3 = await setup.getSubkey()
      const key4 = await setup.getSubkey(32, '', 'sha512')
      key3.toString('hex').should.equal(key4.toString('hex'))
    })

    test('symmetric key', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])

      const key1 = await setup.getSymmetricKey()
      const key2 = await setup.getSymmetricKey('aes256')
      key1.toString('hex').should.equal(key2.toString('hex'))
    })
  })

  suite('errors', () => {
    test('invalid key', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])

      setup.encrypt('hello world', 'unknown').should.be.rejectedWith(RangeError)
    })

    test('invalid message', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])

      setup.encrypt(12345, 'unknown').should.be.rejectedWith(TypeError)
    })

    test('invalid ciphertext', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
      ])

      setup.decrypt(12345, 'unknown').should.be.rejectedWith(TypeError)
    })
  })

  test('defaults', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])

    const ciphertext = await setup.encrypt(Buffer.from('hello world'))

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })

    const plaintext = await derive.decrypt(ciphertext)
    plaintext.toString().should.equal('hello world')
  })

  test('AES256-CBC', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])

    const ciphertext = await setup.encrypt(Buffer.from('hello world'), 'aes256')

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })

    const plaintext = await derive.decrypt(ciphertext, 'aes256')
    plaintext.toString().should.equal('hello world')
  })

  test('AES192-CBC', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])

    const ciphertext = await setup.encrypt('hello world', 'aes192')

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })

    const plaintext = await derive.decrypt(ciphertext, 'aes192')
    plaintext.toString().should.equal('hello world')
  })

  test('AES128-CBC', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])

    const ciphertext = await setup.encrypt('hello world', 'aes128')

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })

    const plaintext = await derive.decrypt(ciphertext, 'aes128')
    plaintext.toString().should.equal('hello world')
  })

  test('3DES-CBC', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])

    const ciphertext = await setup.encrypt('hello world', '3des')

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })

    const plaintext = await derive.decrypt(ciphertext, '3des')
    plaintext.toString().should.equal('hello world')
  })

  test('AES256-ECB', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])

    const ciphertext = await setup.encrypt(Buffer.from('hello world'), 'aes256', 'ECB')

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })

    const plaintext = await derive.decrypt(ciphertext, 'aes256', 'ECB')
    plaintext.toString().should.equal('hello world')
  })

  test('AES192-ECB', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])

    const ciphertext = await setup.encrypt('hello world', 'aes192', 'ECB')

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })

    const plaintext = await derive.decrypt(ciphertext, 'aes192', 'ECB')
    plaintext.toString().should.equal('hello world')
  })

  test('AES128-ECB', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])

    const ciphertext = await setup.encrypt('hello world', 'aes128', 'ECB')

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })

    const plaintext = await derive.decrypt(ciphertext, 'aes128', 'ECB')
    plaintext.toString().should.equal('hello world')
  })

  test('3DES-ECB', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.uuid({ id: 'uuid1', uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d' })
    ])

    const ciphertext = await setup.encrypt('hello world', '3des', 'ECB')

    const derive = await mfkdf.derive.key(setup.policy, {
      uuid1: mfkdf.derive.factors.uuid('9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d')
    })

    const plaintext = await derive.decrypt(ciphertext, '3des', 'ECB')
    plaintext.toString().should.equal('hello world')
  })
})
