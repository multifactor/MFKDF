/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')
const speakeasy = require('speakeasy')

suite('factors/totp', () => {
  test('size', async () => {
    await mfkdf.setup.factors
      .totp({
        secret: Buffer.from('hello world')
      })
      .should.be.rejectedWith(RangeError)
  })

  test('dynamic', async () => {
    const setup = await mfkdf.setup.key([await mfkdf.setup.factors.totp()])

    const code = parseInt(
      speakeasy.totp({
        secret: setup.outputs.totp.secret.toString('hex'),
        encoding: 'hex',
        step: setup.outputs.totp.period,
        algorithm: setup.outputs.totp.algorithm,
        digits: setup.outputs.totp.digits
      })
    )

    const derive1 = await mfkdf.derive.key(setup.policy, {
      totp: mfkdf.derive.factors.totp(code)
    })

    const derive2 = await mfkdf.derive.key(derive1.policy, {
      totp: mfkdf.derive.factors.totp(code)
    })

    const derive3 = await mfkdf.derive.key(derive2.policy, {
      totp: mfkdf.derive.factors.totp(code)
    })

    derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
    derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
  })

  test('static', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.totp({
        secret: Buffer.from('abcdefghijklmnopqrst'),
        time: 1
      })
    ])

    const derive1 = await mfkdf.derive.key(setup.policy, {
      totp: mfkdf.derive.factors.totp(953265, { time: 1 })
    })

    const derive2 = await mfkdf.derive.key(derive1.policy, {
      totp: mfkdf.derive.factors.totp(241063, { time: 30001 })
    })

    const derive3 = await mfkdf.derive.key(derive1.policy, {
      totp: mfkdf.derive.factors.totp(361687, { time: 60001 })
    })

    derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
    derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
  })

  test('defaults', async () => {
    await mfkdf.setup.key([await mfkdf.setup.factors.totp()])
  })

  suite('errors', async () => {
    test('code/type', async () => {
      (() => {
        mfkdf.derive.factors.totp('hello')
      }).should.throw(TypeError)
    })

    test('code/window', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          time: 1650430806597
        })
      ])

      await mfkdf.derive
        .key(setup.policy, {
          totp: mfkdf.derive.factors.totp(953265, { time: 1750430943604 })
        })
        .should.be.rejectedWith(RangeError)
    })

    test('time/type', async () => {
      (() => {
        mfkdf.derive.factors.totp(12345, { time: 'hello' })
      }).should.throw(TypeError)
    })

    test('time/range', async () => {
      (() => {
        mfkdf.derive.factors.totp(12345, { time: -1 })
      }).should.throw(RangeError)
    })

    test('id/type', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          id: 12345
        })
        .should.be.rejectedWith(TypeError)
    })

    test('id/range', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          id: ''
        })
        .should.be.rejectedWith(RangeError)
    })

    test('digits/type', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 'hello'
        })
        .should.be.rejectedWith(TypeError)
    })

    test('digits/low', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 4
        })
        .should.be.rejectedWith(RangeError)
    })

    test('digits/high', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          digits: 9
        })
        .should.be.rejectedWith(RangeError)
    })

    test('hash/range', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: Buffer.from('abcdefghijklmnopqrst'),
          hash: 'sha123'
        })
        .should.be.rejectedWith(RangeError)
    })

    test('secret/type', async () => {
      await mfkdf.setup.factors
        .totp({
          secret: 'hello'
        })
        .should.be.rejectedWith(TypeError)
    })

    test('time/type', async () => {
      await mfkdf.setup.factors
        .totp({
          time: 'hello'
        })
        .should.be.rejectedWith(TypeError)
    })

    test('time/range', async () => {
      await mfkdf.setup.factors
        .totp({
          time: -1
        })
        .should.be.rejectedWith(RangeError)
    })

    test('step/type', async () => {
      await mfkdf.setup.factors
        .totp({
          step: 'hello'
        })
        .should.be.rejectedWith(TypeError)
    })

    test('step/range', async () => {
      await mfkdf.setup.factors
        .totp({
          step: -1
        })
        .should.be.rejectedWith(RangeError)
    })

    test('window/type', async () => {
      await mfkdf.setup.factors
        .totp({
          window: 'hello'
        })
        .should.be.rejectedWith(TypeError)
    })

    test('window/range', async () => {
      await mfkdf.setup.factors
        .totp({
          window: -1
        })
        .should.be.rejectedWith(RangeError)
    })
  })
})
