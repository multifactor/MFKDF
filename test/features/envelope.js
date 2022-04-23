/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('enveloping', () => {
  test('secrets', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password1', { id: 'password1' }),
      await mfkdf.setup.factors.password('password2', { id: 'password2' }),
      await mfkdf.setup.factors.password('password3', { id: 'password3' })
    ], { threshold: 2 })

    const input = Buffer.from('12345678')
    await setup.addEnvelopedSecret('key', input)
    await setup.addEnvelopedSecret('key2', input)
    await setup.addEnvelopedSecret('key3', input)
    await setup.removeEnvelopedSecret('key2')

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2')
    })

    const output = await derive.getEnvelopedSecret('key')

    output.toString('hex').should.equal(input.toString('hex'))
  })

  test('keys', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password1', { id: 'password1' }),
      await mfkdf.setup.factors.password('password2', { id: 'password2' }),
      await mfkdf.setup.factors.password('password3', { id: 'password3' })
    ], { threshold: 2 })

    await setup.addEnvelopedKey('key1')
    await setup.addEnvelopedKey('key2', 'rsa1024')
    await setup.addEnvelopedKey('key3', 'rsa2048')
    await setup.addEnvelopedKey('key4', 'ed25519')

    const key11 = await setup.getEnvelopedKey('key1')
    const key12 = await setup.getEnvelopedKey('key2')
    const key13 = await setup.getEnvelopedKey('key3')
    const key14 = await setup.getEnvelopedKey('key4')

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2')
    })

    const key21 = await derive.getEnvelopedKey('key1')
    const key22 = await derive.getEnvelopedKey('key2')
    const key23 = await derive.getEnvelopedKey('key3')
    const key24 = await derive.getEnvelopedKey('key4')

    key11.export({ format: 'jwk' }).should.deep.equal(key21.export({ format: 'jwk' }))
    key12.export({ format: 'jwk' }).should.deep.equal(key22.export({ format: 'jwk' }))
    key13.export({ format: 'jwk' }).should.deep.equal(key23.export({ format: 'jwk' }))
    key14.export({ format: 'jwk' }).should.deep.equal(key24.export({ format: 'jwk' }))
  })

  suite('errors', () => {
    suite('addEnvelopedSecret', () => {
      test('id/type', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 })

        const input = Buffer.from('12345678')
        setup.addEnvelopedSecret(12345, input).should.be.rejectedWith(TypeError)
      })

      test('value/type', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 })

        setup.addEnvelopedSecret('id', 12345).should.be.rejectedWith(TypeError)
      })

      test('type/type', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 })

        const input = Buffer.from('12345678')
        setup.addEnvelopedSecret('id', input, 12345).should.be.rejectedWith(TypeError)
      })

      test('id/unique', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 })

        const input = Buffer.from('12345678')
        await setup.addEnvelopedSecret('key', input)
        setup.addEnvelopedSecret('key', input).should.be.rejectedWith(RangeError)
      })
    })

    suite('removeEnvelopedSecret', () => {
      test('id/type', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 });

        (() => {
          setup.removeEnvelopedSecret(12345)
        }).should.throw(TypeError)
      })

      test('id/range', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 });

        (() => {
          setup.removeEnvelopedSecret('12345')
        }).should.throw(RangeError)
      })
    })

    suite('addEnvelopedKey', () => {
      test('id/type', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 })

        setup.addEnvelopedKey(12345).should.be.rejectedWith(TypeError)
      })

      test('type/type', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 })

        setup.addEnvelopedKey('12345', 12345).should.be.rejectedWith(TypeError)
      })

      test('type/range', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 })

        setup.addEnvelopedKey('12345', '12345').should.be.rejectedWith(RangeError)
      })
    })

    suite('getEnvelopedSecret', () => {
      test('id/type', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 })

        setup.getEnvelopedSecret(12345).should.be.rejectedWith(TypeError)
      })

      test('id/range', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 })

        setup.getEnvelopedSecret('12345').should.be.rejectedWith(RangeError)
      })
    })

    suite('getEnvelopedKey', () => {
      test('id/type', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 })

        setup.getEnvelopedKey(12345).should.be.rejectedWith(TypeError)
      })
    })

    suite('hasEnvelopedSecret', () => {
      test('id/type', async () => {
        const setup = await mfkdf.setup.key([
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ], { threshold: 2 });

        (() => {
          setup.hasEnvelopedSecret(12345)
        }).should.throw(TypeError)
      })
    })
  })
})
