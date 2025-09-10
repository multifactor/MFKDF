/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('derive/key', () => {
  test('hkdf', async () => {
    const setup = await mfkdf.setup.key(
      [await mfkdf.setup.factors.password('password1', { id: 'password1' })],
      { kdf: 'hkdf' }
    )

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1')
    })

    derive.key.toString('hex').should.equal(setup.key.toString('hex'))
  })

  suite('shares', () => {
    test('valid', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 2 }
      )

      const derive1 = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      })

      const derive2 = await mfkdf.derive.key(derive1.policy, {
        password2: mfkdf.derive.factors.password('password2'),
        password3: mfkdf.derive.factors.password('password3')
      })

      const derive3 = await mfkdf.derive.key(derive2.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password3: mfkdf.derive.factors.password('password3')
      })

      derive1.shares.should.deep.equal(setup.shares)
      derive2.shares.should.deep.equal(setup.shares)
      derive3.shares.should.deep.equal(setup.shares)
    })
  })

  suite('invalid', () => {
    test('schema', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', { id: 'password1' })
      ])

      delete setup.policy.$id

      await mfkdf.derive
        .key(setup.policy, {
          password1: mfkdf.derive.factors.password('password1')
        })
        .should.be.rejectedWith(TypeError)
    })

    test('factors', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 2 }
      )

      await mfkdf.derive
        .key(setup.policy, {
          password1: mfkdf.derive.factors.password('password1')
        })
        .should.be.rejectedWith(RangeError)
    })
  })

  test('correct', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2 }
    )

    const derive1 = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2')
    })

    const derive2 = await mfkdf.derive.key(setup.policy, {
      password2: mfkdf.derive.factors.password('password2'),
      password3: mfkdf.derive.factors.password('password3')
    })

    const derive3 = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password3: mfkdf.derive.factors.password('password3')
    })

    const derive4 = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2'),
      password3: mfkdf.derive.factors.password('password3')
    })

    setup.key.toString('hex').should.equal(derive1.key.toString('hex'))
    setup.key.toString('hex').should.equal(derive2.key.toString('hex'))
    setup.key.toString('hex').should.equal(derive3.key.toString('hex'))
    setup.key.toString('hex').should.equal(derive4.key.toString('hex'))

    JSON.stringify(setup.policy).should.equal(JSON.stringify(derive1.policy))
    JSON.stringify(setup.policy).should.equal(JSON.stringify(derive2.policy))
    JSON.stringify(setup.policy).should.equal(JSON.stringify(derive3.policy))
    JSON.stringify(setup.policy).should.equal(JSON.stringify(derive4.policy))
  })

  test('incorrect', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, integrity: false }
    )

    const derive1 = await mfkdf.derive.key(
      setup.policy,
      {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('wrongpassword2')
      },
      false
    )

    const derive2 = await mfkdf.derive.key(
      setup.policy,
      {
        password2: mfkdf.derive.factors.password('wrongpassword2'),
        password3: mfkdf.derive.factors.password('wrongpassword3')
      },
      false
    )

    const derive3 = await mfkdf.derive.key(
      setup.policy,
      {
        password1: mfkdf.derive.factors.password('password1'),
        password3: mfkdf.derive.factors.password('password2')
      },
      false
    )

    const derive4 = await mfkdf.derive.key(
      setup.policy,
      {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2'),
        password3: mfkdf.derive.factors.password('password4')
      },
      false
    )

    setup.key.toString('hex').should.not.equal(derive1.key.toString('hex'))
    setup.key.toString('hex').should.not.equal(derive2.key.toString('hex'))
    setup.key.toString('hex').should.not.equal(derive3.key.toString('hex'))
    setup.key.toString('hex').should.not.equal(derive4.key.toString('hex'))
  })

  test('mismatch', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password', { id: 'password' })
    ])

    await mfkdf.derive
      .key(setup.policy, {
        password: mfkdf.derive.factors.uuid(
          '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d'
        )
      })
      .should.be.rejectedWith(TypeError)
  })
})
