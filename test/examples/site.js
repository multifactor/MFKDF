/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')
// const crypto = require('crypto')

suite('site', () => {
  test('Go beyond passwords', async () => {
    const keyPolicy = JSON.stringify(
      (
        await mfkdf.setup.key(
          [
            await mfkdf.setup.factors.password('password'),
            await mfkdf.setup.factors.hotp({
              secret: Buffer.from('hello world')
            }),
            await mfkdf.setup.factors.uuid({
              id: 'recovery',
              uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
            })
          ],
          { threshold: 2, size: 16, pbkdf2rounds: 1 }
        )
      ).policy
    )

    const derivedKey = await mfkdf.derive.key(JSON.parse(keyPolicy), {
      password: mfkdf.derive.factors.password('Tr0ub4dour'),
      hotp: mfkdf.derive.factors.hotp(365287),
      recovery: mfkdf.derive.factors.uuid(
        '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
      )
    })

    derivedKey.should.be.a('object')
  })

  test('Increased key entropy', async () => {
    Math.floor(
      (
        await mfkdf.setup.key([
          await mfkdf.setup.factors.password('Tr0ub4dour')
        ])
      ).entropyBits.real
    ).should.equal(16)

    Math.floor(
      (
        await mfkdf.setup.key([
          await mfkdf.setup.factors.password('Tr0ub4dour'),
          await mfkdf.setup.factors.hotp(),
          await mfkdf.setup.factors.hmacsha1()
        ])
      ).entropyBits.real
    ).should.equal(196)
  })

  test('Enforce advanced policies', async () => {
    const policyBasedKey = await mfkdf.policy.setup(
      await mfkdf.policy.or(
        await mfkdf.setup.factors.uuid({ id: 'recoveryCode' }),
        await mfkdf.policy.and(
          await mfkdf.setup.factors.password('Tr0ub4dour'),
          await mfkdf.setup.factors.totp()
        )
      )
    )
    policyBasedKey.should.be.a('object')
  })

  test('Self-service factor recovery', async () => {
    const keyPolicy = JSON.stringify(
      (
        await mfkdf.setup.key(
          [
            await mfkdf.setup.factors.password('password'),
            await mfkdf.setup.factors.hotp({
              secret: Buffer.from('hello world')
            }),
            await mfkdf.setup.factors.uuid({
              id: 'recoveryCode',
              uuid: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
            })
          ],
          { threshold: 2, size: 16, pbkdf2rounds: 1 }
        )
      ).policy
    )

    const key = await mfkdf.derive.key(JSON.parse(keyPolicy), {
      hotp: mfkdf.derive.factors.hotp(365287),
      recoveryCode: mfkdf.derive.factors.uuid(
        '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
      )
    })

    await key.recoverFactor(
      await mfkdf.setup.factors.password('myNewPassword', { id: 'password' })
    ) // modify key to use new password factor
  })
})
