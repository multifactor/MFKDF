/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('integrity', () => {
  test('disabled', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ])
    )

    // Tamper with policy
    setup.policy.factors[0].id = 'tampered'

    await mfkdf.policy.derive(
      setup.policy,
      {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2'),
        password3: mfkdf.derive.factors.password('password3'),
        password4: mfkdf.derive.factors.password('password4')
      },
      false
    )
  })

  test('safety', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ]),
      { integrity: true }
    )

    const derive = await mfkdf.policy.derive(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2'),
      password3: mfkdf.derive.factors.password('password3'),
      password4: mfkdf.derive.factors.password('password4')
    })

    derive.key.toString('hex').should.equal(setup.key.toString('hex'))

    // Tamper with policy
    setup.policy.factors[0].id = 'tampered'

    await mfkdf.policy
      .derive(
        setup.policy,
        {
          password1: mfkdf.derive.factors.password('password1'),
          password2: mfkdf.derive.factors.password('password2'),
          password3: mfkdf.derive.factors.password('password3'),
          password4: mfkdf.derive.factors.password('password4')
        },
        true
      )
      .should.be.rejectedWith(RangeError)
  })

  test('liveness', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ]),
      { integrity: true }
    )

    const derive = await mfkdf.policy.derive(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2'),
      password3: mfkdf.derive.factors.password('password3'),
      password4: mfkdf.derive.factors.password('password4')
    })

    derive.key.toString('hex').should.equal(setup.key.toString('hex'))

    await mfkdf.policy.derive(
      setup.policy,
      {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2'),
        password3: mfkdf.derive.factors.password('password3'),
        password4: mfkdf.derive.factors.password('password4')
      },
      true
    )
  })

  test('$id', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ]),
      { integrity: true }
    )

    // Tamper with policy
    setup.policy.$id = 'tampered'

    await mfkdf.policy
      .derive(
        setup.policy,
        {
          password1: mfkdf.derive.factors.password('password1'),
          password2: mfkdf.derive.factors.password('password2')
        },
        true
      )
      .should.be.rejectedWith(RangeError)
  })

  test('threshold', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ]),
      { integrity: true }
    )

    // Tamper with policy
    setup.policy.threshold += 1

    await mfkdf.policy
      .derive(
        setup.policy,
        {
          password1: mfkdf.derive.factors.password('password1'),
          password2: mfkdf.derive.factors.password('password2')
        },
        true
      )
      .should.be.rejectedWith(RangeError)
  })

  test('salt', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ]),
      { integrity: true }
    )

    // Tamper with policy
    setup.policy.salt = 'Ny9+L9LQHOKh1x3Acqy7pMb9JaEIfNfxU/TsDON+Ht4='

    await mfkdf.policy
      .derive(
        setup.policy,
        {
          password1: mfkdf.derive.factors.password('password1'),
          password2: mfkdf.derive.factors.password('password2')
        },
        true
      )
      .should.be.rejectedWith(RangeError)
  })

  test('factor/id', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ]),
      { integrity: true }
    )

    // Tamper with policy
    setup.policy.factors[0].id = 'tampered'

    await mfkdf.policy
      .derive(
        setup.policy,
        {
          password1: mfkdf.derive.factors.password('password1'),
          password2: mfkdf.derive.factors.password('password2')
        },
        true
      )
      .should.be.rejectedWith(RangeError)
  })

  test('derive', async () => {
    const setup = await mfkdf.policy.setup(
      await mfkdf.policy.all([
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ]),
      { integrity: true }
    )

    const derive = await mfkdf.policy.derive(
      setup.policy,
      {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2'),
        password3: mfkdf.derive.factors.password('password3'),
        password4: mfkdf.derive.factors.password('password4')
      },
      true
    )

    derive.key.toString('hex').should.equal(setup.key.toString('hex'))

    // Tamper with policy
    derive.policy.factors[0].id = 'tampered'

    await mfkdf.policy
      .derive(
        derive.policy,
        {
          password1: mfkdf.derive.factors.password('password1'),
          password2: mfkdf.derive.factors.password('password2'),
          password3: mfkdf.derive.factors.password('password3'),
          password4: mfkdf.derive.factors.password('password4')
        },
        true
      )
      .should.be.rejectedWith(RangeError)
  })

  test('reconstitution', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2, integrity: true }
    )
    const key = setup.key.toString('hex')

    await setup.recoverFactor(
      await mfkdf.setup.factors.password('differentPassword3', {
        id: 'password3'
      })
    )

    const derive = await mfkdf.derive.key(
      setup.policy,
      {
        password1: mfkdf.derive.factors.password('password1'),
        password3: mfkdf.derive.factors.password('differentPassword3')
      },
      true
    )
    derive.key.toString('hex').should.equal(key)
  })
})
