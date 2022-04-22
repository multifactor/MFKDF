/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../src')
const { suite, test } = require('mocha')

suite('entropy', () => {
  test('3-of-3', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('12345678', { id: 'password1' }),
      await mfkdf.setup.factors.password('ABCDEFGH', { id: 'password2' }),
      await mfkdf.setup.factors.password('abcdefgh', { id: 'password3' })
    ], { threshold: 3 })

    Math.floor(setup.entropyBits.real).should.equal(Math.floor(Math.log2(4) + Math.log2(33) + Math.log2(33)))
    setup.entropyBits.theoretical.should.equal(8 * 8 * 3)
  })

  test('2-of-3', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('12345678', { id: 'password1' }),
      await mfkdf.setup.factors.password('ABCDEFGH', { id: 'password2' }),
      await mfkdf.setup.factors.password('abcdefgh', { id: 'password3' })
    ], { threshold: 2 })

    Math.floor(setup.entropyBits.real).should.equal(Math.floor(Math.log2(4) + Math.log2(33)))
    setup.entropyBits.theoretical.should.equal(8 * 8 * 2)
  })

  test('1-of-3', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('12345678', { id: 'password1' }),
      await mfkdf.setup.factors.password('ABCDEFGH', { id: 'password2' }),
      await mfkdf.setup.factors.password('abcdefgh', { id: 'password3' })
    ], { threshold: 1 })

    Math.floor(setup.entropyBits.real).should.equal(Math.floor(Math.log2(4)))
    setup.entropyBits.theoretical.should.equal(8 * 8 * 1)
  })

  test('policy', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.and(
        await mfkdf.setup.factors.password('12345678', { id: 'password1' }),
        await mfkdf.policy.any([
          await mfkdf.setup.factors.password('12345678', { id: 'password7' }),
          await mfkdf.policy.or(
            await mfkdf.setup.factors.password('Tr0ub4dour&3', { id: 'password2' }),
            await mfkdf.setup.factors.password('Tr0ub4dour&3', { id: 'password3' })
          ),
          await mfkdf.policy.and(
            await mfkdf.setup.factors.password('Tr0ub4dour&3', { id: 'password4' }),
            await mfkdf.policy.or(
              await mfkdf.setup.factors.password('Tr0ub4dour&3', { id: 'password5' }),
              await mfkdf.setup.factors.password('Tr0ub4dour&3', { id: 'password6' })
            )
          )
        ])
      )
    )
    Math.floor(setup.entropyBits.real).should.equal(Math.floor(Math.log2(4) * 2))
  })

  test('totp/hotp-6', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.totp(),
      await mfkdf.setup.factors.hotp()
    ], { threshold: 2 })

    Math.floor(setup.entropyBits.real).should.equal(Math.floor(Math.log2(10 ** 6) * 2))
  })

  test('totp/hotp-8', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.totp({ digits: 8 }),
      await mfkdf.setup.factors.hotp({ digits: 8 })
    ], { threshold: 2 })

    Math.floor(setup.entropyBits.real).should.equal(Math.floor(Math.log2(10 ** 8) * 2))
  })
})
