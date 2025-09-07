/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('kdf', () => {
  test('types', async () => {
    const argon2 = await mfkdf.kdf(
      'password',
      'somesalt',
      16,
      mfkdf.setup.kdf({ kdf: 'argon2id' })
    )
    Buffer.isBuffer(argon2).should.be.true
  })

  test('argon2i', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ kdf: 'argon2i' })
    )
    key
      .toString('hex')
      .should.equal(
        '7357892df510f136a0688ceab37bbaf7ba695de590065072717fa6728961c92a'
      )
  })

  test('argon2d', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ kdf: 'argon2d' })
    )
    key
      .toString('hex')
      .should.equal(
        '423b0dcc7bbfe16fa8ee7a2e2ebd8891873d726f9dfe70890a7197a5503a2848'
      )
  })

  test('argon2id', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ kdf: 'argon2id' })
    )
    key
      .toString('hex')
      .should.equal(
        '5cddd5b69d1fe5d83bc3e04e9122f05d9b2128a194cb739baf74679875c4b3a1'
      )
  })

  test('argon2id/mem', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ type: 'argon2id', argon2mem: 16384 })
    )
    key
      .toString('hex')
      .should.equal(
        'e043f979311b14ff8378b785469974e899a08f05509323a04b2ca29ef63ff3af'
      )
  })

  test('argon2id/time', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ type: 'argon2id', argon2time: 1 })
    )
    key
      .toString('hex')
      .should.equal(
        'bf6b1773bdae362ecea04b889079b6628d1f35d96a2be9f2a5481c2d1236e8d7'
      )
  })

  test('argon2id/parallelism', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({ type: 'argon2id', argon2parallelism: 2 })
    )
    key
      .toString('hex')
      .should.equal(
        '5c12c6873b938cd8467b677d23e525389e3ff7ed62b4ad9e285e1191244f40ca'
      )
  })

  test('default', async () => {
    const key = await mfkdf.kdf(
      'password',
      'somesalt',
      32,
      mfkdf.setup.kdf({})
    )
    key
      .toString('hex')
      .should.equal(
        '5cddd5b69d1fe5d83bc3e04e9122f05d9b2128a194cb739baf74679875c4b3a1'
      )
  })

  test('invalid', async () => {
    await mfkdf
      .kdf('password1', 'salt1', 16, { type: 'invalid', params: {} })
      .should.be.rejectedWith(RangeError)
  })
})
