/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('mfkdf2/strengthening', () => {
  suite('setup', () => {
    test('time', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { time: 5 }
      )

      setup.policy.time.should.equal(5)

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.policy.time.should.equal(5)

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('memory', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { memory: 32768 }
      )

      setup.policy.memory.should.equal(32768)

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.policy.memory.should.equal(32768)

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('time-and-memory', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', {
            id: 'password1'
          })
        ],
        { time: 3, memory: 16384 }
      )

      setup.policy.time.should.equal(3)
      setup.policy.memory.should.equal(16384)

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.policy.time.should.equal(3)
      derive.policy.memory.should.equal(16384)

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('throws', async () => {
      await mfkdf.setup
        .key(
          [
            await mfkdf.setup.factors.password('password1', {
              id: 'password1'
            })
          ],
          { time: -1 }
        )
        .should.be.rejectedWith(RangeError, 'time must be non-negative')

      await mfkdf.setup
        .key(
          [
            await mfkdf.setup.factors.password('password1', {
              id: 'password1'
            })
          ],
          { time: 1.5 }
        )
        .should.be.rejectedWith(TypeError, 'time must be an integer')

      await mfkdf.setup
        .key(
          [
            await mfkdf.setup.factors.password('password1', {
              id: 'password1'
            })
          ],
          { memory: -1 }
        )
        .should.be.rejectedWith(RangeError, 'memory must be non-negative')

      await mfkdf.setup
        .key(
          [
            await mfkdf.setup.factors.password('password1', {
              id: 'password1'
            })
          ],
          { memory: 1.5 }
        )
        .should.be.rejectedWith(TypeError, 'memory must be an integer')
    })
  })

  suite('strengthening', () => {
    test('time', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])

      setup.policy.time.should.equal(0)

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.policy.time.should.equal(0)

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      await derive.strenthen(5, 0)

      derive.policy.time.should.equal(5)
      derive.policy.memory.should.equal(0)

      const derive2 = await mfkdf.derive.key(derive.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive2.policy.time.should.equal(5)
      derive2.policy.memory.should.equal(0)

      derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('memory', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])

      setup.policy.memory.should.equal(0)

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.policy.memory.should.equal(0)

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      await derive.strenthen(0, 32768)

      derive.policy.time.should.equal(0)
      derive.policy.memory.should.equal(32768)

      const derive2 = await mfkdf.derive.key(derive.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive2.policy.time.should.equal(0)
      derive2.policy.memory.should.equal(32768)

      derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
    })

    test('time-and-memory', async () => {
      const setup = await mfkdf.setup.key([
        await mfkdf.setup.factors.password('password1', {
          id: 'password1'
        })
      ])

      setup.policy.time.should.equal(0)
      setup.policy.memory.should.equal(0)

      const derive = await mfkdf.derive.key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive.policy.time.should.equal(0)
      derive.policy.memory.should.equal(0)

      derive.key.toString('hex').should.equal(setup.key.toString('hex'))

      await derive.strenthen(3, 16384)

      derive.policy.time.should.equal(3)
      derive.policy.memory.should.equal(16384)

      const derive2 = await mfkdf.derive.key(derive.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })

      derive2.policy.time.should.equal(3)
      derive2.policy.memory.should.equal(16384)

      derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
    })
  })

  test('strengthening-throws', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password1', {
        id: 'password1'
      })
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1')
    })

    await derive
      .strenthen(-1, 0)
      .should.be.rejectedWith(TypeError, 'time must be a non-negative integer')

    await derive
      .strenthen(1.5, 0)
      .should.be.rejectedWith(TypeError, 'time must be a non-negative integer')

    await derive
      .strenthen(0, -1)
      .should.be.rejectedWith(
        TypeError,
        'memory must be a non-negative integer'
      )

    await derive
      .strenthen(0, 1.5)
      .should.be.rejectedWith(
        TypeError,
        'memory must be a non-negative integer'
      )
  })

  test('strengthening-works-multiple-times', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password1', {
        id: 'password1'
      })
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1')
    })

    derive.key.toString('hex').should.equal(setup.key.toString('hex'))

    await derive.strenthen(2, 8192)
    derive.policy.time.should.equal(2)
    derive.policy.memory.should.equal(8192)

    const derive2 = await mfkdf.derive.key(derive.policy, {
      password1: mfkdf.derive.factors.password('password1')
    })
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'))

    derive.policy.time = 0
    derive.policy.memory = 0

    await mfkdf.derive
      .key(derive.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })
      .should.be.rejectedWith(Error)

    await derive2.strenthen(3, 16384)
    derive2.policy.time.should.equal(3)
    derive2.policy.memory.should.equal(16384)

    const derive3 = await mfkdf.derive.key(derive2.policy, {
      password1: mfkdf.derive.factors.password('password1')
    })
    derive3.policy.time.should.equal(3)
    derive3.policy.memory.should.equal(16384)
    derive3.key.toString('hex').should.equal(setup.key.toString('hex'))

    derive2.policy.time = 0
    derive2.policy.memory = 0

    await mfkdf.derive
      .key(derive2.policy, {
        password1: mfkdf.derive.factors.password('password1')
      })
      .should.be.rejectedWith(Error)
  })

  test('strengthening-with-other-factors', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password1', {
        id: 'password1'
      }),
      await mfkdf.setup.factors.password('password2', {
        id: 'password2'
      })
    ])
    const derive = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2')
    })
    derive.key.toString('hex').should.equal(setup.key.toString('hex'))

    await derive.strenthen(2, 8192)
    derive.policy.time.should.equal(2)
    derive.policy.memory.should.equal(8192)
    const derive2 = await mfkdf.derive.key(derive.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2')
    })
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'))

    await derive2.strenthen()
    derive2.policy.time.should.equal(0)
    derive2.policy.memory.should.equal(0)

    const derive3 = await mfkdf.derive.key(derive2.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2')
    })
    derive3.policy.time.should.equal(0)
    derive3.policy.memory.should.equal(0)
    derive3.key.toString('hex').should.equal(setup.key.toString('hex'))
  })

  test('strengthening-with-reconstitution', async () => {
    const setup = await mfkdf.setup.key([
      await mfkdf.setup.factors.password('password1', {
        id: 'password1'
      }),
      await mfkdf.setup.factors.password('password2', {
        id: 'password2'
      })
    ])
    const derive = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2')
    })
    derive.key.toString('hex').should.equal(setup.key.toString('hex'))

    await derive.strenthen(2, 8192)
    derive.policy.time.should.equal(2)
    derive.policy.memory.should.equal(8192)

    await derive.setThreshold(1)
    await derive.removeFactor('password2')

    const derive2 = await mfkdf.derive.key(derive.policy, {
      password1: mfkdf.derive.factors.password('password1')
    })
    derive2.key.toString('hex').should.equal(setup.key.toString('hex'))
  })
})
