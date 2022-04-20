/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')
const speakeasy = require('speakeasy')

suite('factors/totp', () => {
  test('dynamic', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.totp()
    ])

    const code = parseInt(speakeasy.totp({
      secret: setup.outputs.totp.secret.toString('hex'),
      encoding: 'hex',
      step: setup.outputs.totp.period,
      algorithm: setup.outputs.totp.algorithm,
      digits: setup.outputs.totp.digits
    }))

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
        secret: Buffer.from('hello world'),
        time: 1650430806597
      })
    ])

    const derive1 = await mfkdf.derive.key(setup.policy, {
      totp: mfkdf.derive.factors.totp(528258, { time: 1650430943604 })
    })

    const derive2 = await mfkdf.derive.key(derive1.policy, {
      totp: mfkdf.derive.factors.totp(99922, { time: 1650430991083 })
    })

    const derive3 = await mfkdf.derive.key(derive1.policy, {
      totp: mfkdf.derive.factors.totp(398884, { time: 1650431018392 })
    })

    derive1.key.toString('hex').should.equal(setup.key.toString('hex'))
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
    derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
  })

  test('defaults', async () => {
    await mfkdf.setup.key([
      await mfkdf.setup.factors.totp()
    ])
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
          secret: Buffer.from('hello world'),
          time: 1650430806597
        })
      ])

      mfkdf.derive.key(setup.policy, {
        totp: mfkdf.derive.factors.totp(528258, { time: 1750430943604 })
      }).should.be.rejectedWith(RangeError)
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
      mfkdf.setup.factors.totp({
        secret: Buffer.from('hello world'),
        id: 12345
      }).should.be.rejectedWith(TypeError)
    })

    test('id/range', async () => {
      mfkdf.setup.factors.totp({
        secret: Buffer.from('hello world'),
        id: ''
      }).should.be.rejectedWith(RangeError)
    })

    test('digits/type', async () => {
      mfkdf.setup.factors.totp({
        secret: Buffer.from('hello world'),
        digits: 'hello'
      }).should.be.rejectedWith(TypeError)
    })

    test('digits/low', async () => {
      mfkdf.setup.factors.totp({
        secret: Buffer.from('hello world'),
        digits: 4
      }).should.be.rejectedWith(RangeError)
    })

    test('digits/high', async () => {
      mfkdf.setup.factors.totp({
        secret: Buffer.from('hello world'),
        digits: 9
      }).should.be.rejectedWith(RangeError)
    })

    test('hash/range', async () => {
      await mfkdf.setup.factors.totp({
        secret: Buffer.from('hello world'),
        hash: 'sha123'
      }).should.be.rejectedWith(RangeError)
    })

    test('secret/type', async () => {
      mfkdf.setup.factors.totp({
        secret: 'hello'
      }).should.be.rejectedWith(TypeError)
    })

    test('time/type', async () => {
      mfkdf.setup.factors.totp({
        time: 'hello'
      }).should.be.rejectedWith(TypeError)
    })

    test('time/range', async () => {
      mfkdf.setup.factors.totp({
        time: -1
      }).should.be.rejectedWith(RangeError)
    })

    test('step/type', async () => {
      mfkdf.setup.factors.totp({
        step: 'hello'
      }).should.be.rejectedWith(TypeError)
    })

    test('step/range', async () => {
      mfkdf.setup.factors.totp({
        step: -1
      }).should.be.rejectedWith(RangeError)
    })

    test('window/type', async () => {
      mfkdf.setup.factors.totp({
        window: 'hello'
      }).should.be.rejectedWith(TypeError)
    })

    test('window/range', async () => {
      mfkdf.setup.factors.totp({
        window: -1
      }).should.be.rejectedWith(RangeError)
    })
  })
})
