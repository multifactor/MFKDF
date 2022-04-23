/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('authentication', () => {
  test('getKey/auth', async () => {
    const key = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password1', { id: 'password1' })
    ])

    let authKey
    let encKey

    authKey = await key.getSymmetricKey('des', true)
    encKey = await key.getSymmetricKey('des', false)
    authKey.toString('hex').should.not.equal(encKey.toString('hex'))

    authKey = await key.getSymmetricKey('3des', true)
    encKey = await key.getSymmetricKey('3des', false)
    authKey.toString('hex').should.not.equal(encKey.toString('hex'))

    authKey = await key.getSymmetricKey('aes128', true)
    encKey = await key.getSymmetricKey('aes128', false)
    authKey.toString('hex').should.not.equal(encKey.toString('hex'))

    authKey = await key.getSymmetricKey('aes192', true)
    encKey = await key.getSymmetricKey('aes192', false)
    authKey.toString('hex').should.not.equal(encKey.toString('hex'))

    authKey = await key.getSymmetricKey('aes256', true)
    encKey = await key.getSymmetricKey('aes256', false)
    authKey.toString('hex').should.not.equal(encKey.toString('hex'))

    authKey = await key.getAsymmetricKeyPair('ed25519', true)
    encKey = await key.getAsymmetricKeyPair('ed25519', false)
    authKey.publicKey.toString('hex').should.not.equal(encKey.publicKey.toString('hex'))

    authKey = await key.getAsymmetricKeyPair('rsa1024', true)
    encKey = await key.getAsymmetricKeyPair('rsa1024', false)
    authKey.publicKey.toString('hex').should.not.equal(encKey.publicKey.toString('hex'))

    authKey = await key.getAsymmetricKeyPair('rsa2048', true)
    encKey = await key.getAsymmetricKeyPair('rsa2048', false)
    authKey.publicKey.toString('hex').should.not.equal(encKey.publicKey.toString('hex'))

    authKey = await key.getAsymmetricKeyPair('rsa3072', true)
    encKey = await key.getAsymmetricKeyPair('rsa3072', false)
    authKey.publicKey.toString('hex').should.not.equal(encKey.publicKey.toString('hex'))
  }).timeout(50000)

  suite('valid', () => {
    test('ISO97982PassUnilateralAuthSymmetric', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const challenge = Buffer.from('hello world')
      const identity = Buffer.from('bob')

      const response = await key.ISO97982PassUnilateralAuthSymmetric(challenge, identity)
      const authKey = await key.ISO9798SymmetricKey()

      const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthSymmetric(challenge, identity, response, authKey)
      valid.should.be.true
    })

    test('ISO97982PassUnilateralAuthAsymmetric', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const challenge = Buffer.from('hello world')
      const identity = Buffer.from('bob')

      const response = await key.ISO97982PassUnilateralAuthAsymmetric(challenge, identity)
      const authKey = await key.ISO9798AsymmetricKey()

      const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthAsymmetric(challenge, identity, response, authKey)
      valid.should.be.true
    })

    test('ISO97982PassUnilateralAuthCCF', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const challenge = Buffer.from('hello world')
      const identity = Buffer.from('bob')

      const response = await key.ISO97982PassUnilateralAuthCCF(challenge, identity)
      const authKey = await key.ISO9798CCFKey()

      const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthCCF(challenge, identity, response, authKey)
      valid.should.be.true
    })

    test('ISO97981PassUnilateralAuthSymmetric', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const identity = Buffer.from('bob')

      const response = await key.ISO97981PassUnilateralAuthSymmetric(identity)
      const authKey = await key.ISO9798SymmetricKey()

      const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthSymmetric(identity, response, authKey)
      valid.should.be.true
    })

    test('ISO97981PassUnilateralAuthAsymmetric', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const identity = Buffer.from('bob')

      const response = await key.ISO97981PassUnilateralAuthAsymmetric(identity)
      const authKey = await key.ISO9798AsymmetricKey()

      const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthAsymmetric(identity, response, authKey)
      valid.should.be.true
    })

    test('ISO97981PassUnilateralAuthCCF', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const identity = Buffer.from('bob')

      const response = await key.ISO97981PassUnilateralAuthCCF(identity)
      const authKey = await key.ISO9798CCFKey()

      const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthCCF(identity, response, authKey)
      valid.should.be.true
    })
  })

  suite('invalid', () => {
    test('ISO97982PassUnilateralAuthSymmetric', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const key2 = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ])

      const challenge = Buffer.from('hello world')
      const identity = Buffer.from('bob')

      const response = await key.ISO97982PassUnilateralAuthSymmetric(challenge, identity)
      const authKey = await key2.ISO9798SymmetricKey()

      const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthSymmetric(challenge, identity, response, authKey)
      valid.should.be.false
    })

    test('ISO97982PassUnilateralAuthAsymmetric', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const key2 = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ])

      const challenge = Buffer.from('hello world')
      const identity = Buffer.from('bob')

      const response = await key.ISO97982PassUnilateralAuthAsymmetric(challenge, identity)
      const authKey = await key2.ISO9798AsymmetricKey()

      const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthAsymmetric(challenge, identity, response, authKey)
      valid.should.be.false
    })

    test('ISO97982PassUnilateralAuthCCF', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const key2 = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ])

      const challenge = Buffer.from('hello world')
      const identity = Buffer.from('bob')

      const response = await key.ISO97982PassUnilateralAuthCCF(challenge, identity)
      const authKey = await key2.ISO9798CCFKey()

      const valid = await mfkdf.auth.VerifyISO97982PassUnilateralAuthCCF(challenge, identity, response, authKey)
      valid.should.be.false
    })

    test('ISO97981PassUnilateralAuthSymmetric', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const key2 = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ])

      const identity = Buffer.from('bob')

      const response = await key.ISO97981PassUnilateralAuthSymmetric(identity)
      const authKey = await key2.ISO9798SymmetricKey()

      const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthSymmetric(identity, response, authKey)
      valid.should.be.false
    })

    test('ISO97981PassUnilateralAuthAsymmetric', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const key2 = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ])

      const identity = Buffer.from('bob')

      const response = await key.ISO97981PassUnilateralAuthAsymmetric(identity)
      const authKey = await key2.ISO9798AsymmetricKey()

      const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthAsymmetric(identity, response, authKey)
      valid.should.be.false
    })

    test('ISO97981PassUnilateralAuthCCF', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const key2 = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ])

      const identity = Buffer.from('bob')

      const response = await key.ISO97981PassUnilateralAuthCCF(identity)
      const authKey = await key2.ISO9798CCFKey()

      const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthCCF(identity, response, authKey)
      valid.should.be.false
    })

    test('ISO97981PassUnilateralAuthSymmetric/window', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const identity = Buffer.from('bob')

      const response = await key.ISO97981PassUnilateralAuthSymmetric(identity)
      const authKey = await key.ISO9798SymmetricKey()

      const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthSymmetric(identity, response, authKey, -1)
      valid.should.be.false
    })

    test('ISO97981PassUnilateralAuthAsymmetric/window', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const identity = Buffer.from('bob')

      const response = await key.ISO97981PassUnilateralAuthAsymmetric(identity)
      const authKey = await key.ISO9798AsymmetricKey()

      const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthAsymmetric(identity, response, authKey, -1)
      valid.should.be.false
    })

    test('ISO97981PassUnilateralAuthCCF/window', async () => {
      const key = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      const identity = Buffer.from('bob')

      const response = await key.ISO97981PassUnilateralAuthCCF(identity)
      const authKey = await key.ISO9798CCFKey()

      const valid = await mfkdf.auth.VerifyISO97981PassUnilateralAuthCCF(identity, response, authKey, -1)
      valid.should.be.false
    })
  })
})
