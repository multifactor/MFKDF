/* eslint no-unused-expressions: "off" */
const chai = require('chai')
const chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
chai.should()

const mfkdf = require('../../src')
const { suite, test } = require('mocha')

suite('reconstitution', () => {
  test('setThreshold', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ],
      { threshold: 3, integrity: false }
    )
    const key = setup.key.toString('hex')

    await mfkdf.derive
      .key(
        setup.policy,
        {
          password1: mfkdf.derive.factors.password('password1'),
          password2: mfkdf.derive.factors.password('password2')
        },
        false
      )
      .should.be.rejectedWith(RangeError)

    await setup.setThreshold(2)

    const derive = await mfkdf.derive.key(
      setup.policy,
      {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      },
      false
    )

    derive.key.toString('hex').should.equal(key)
  })

  test('removeFactor', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    const derive1 = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password2: mfkdf.derive.factors.password('password2')
    })
    derive1.key.toString('hex').should.equal(key)

    await setup.removeFactor('password1')

    const derive2 = await mfkdf.derive.key(setup.policy, {
      password2: mfkdf.derive.factors.password('password2'),
      password3: mfkdf.derive.factors.password('password3')
    })
    derive2.key.toString('hex').should.equal(key)

    await mfkdf.derive
      .key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password2: mfkdf.derive.factors.password('password2')
      })
      .should.be.rejectedWith(RangeError)

    await derive2.removeFactor('password2').should.be.rejectedWith(RangeError)

    await derive2.setThreshold(1)

    await derive2.removeFactor('password2')

    const derive3 = await mfkdf.derive.key(derive2.policy, {
      password3: mfkdf.derive.factors.password('password3')
    })
    derive3.key.toString('hex').should.equal(key)

    await mfkdf.derive
      .key(derive2.policy, {
        password2: mfkdf.derive.factors.password('password2')
      })
      .should.be.rejectedWith(RangeError)
  })

  test('removeFactors', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' }),
        await mfkdf.setup.factors.password('password4', { id: 'password4' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    const derive1 = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password4: mfkdf.derive.factors.password('password4')
    })
    derive1.key.toString('hex').should.equal(key)

    const derive2 = await mfkdf.derive.key(setup.policy, {
      password2: mfkdf.derive.factors.password('password2'),
      password3: mfkdf.derive.factors.password('password3')
    })
    derive2.key.toString('hex').should.equal(key)

    await setup.removeFactors(['password1', 'password4'])

    await mfkdf.derive
      .key(setup.policy, {
        password1: mfkdf.derive.factors.password('password1'),
        password4: mfkdf.derive.factors.password('password4')
      })
      .should.be.rejectedWith(RangeError)

    const derive3 = await mfkdf.derive.key(setup.policy, {
      password2: mfkdf.derive.factors.password('password2'),
      password3: mfkdf.derive.factors.password('password3')
    })
    derive3.key.toString('hex').should.equal(key)
  })

  test('addFactor', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    await setup.addFactor(
      await mfkdf.setup.factors.password('password3', { id: 'password3' })
    )

    const derive = await mfkdf.derive.key(setup.policy, {
      password2: mfkdf.derive.factors.password('password2'),
      password3: mfkdf.derive.factors.password('password3')
    })
    derive.key.toString('hex').should.equal(key)
  })

  test('addFactors', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    await setup.addFactors([
      await mfkdf.setup.factors.password('password3', { id: 'password3' }),
      await mfkdf.setup.factors.password('password4', { id: 'password4' })
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      password3: mfkdf.derive.factors.password('password3'),
      password4: mfkdf.derive.factors.password('password4')
    })
    derive.key.toString('hex').should.equal(key)
  })

  test('recoverFactor', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    await setup.recoverFactor(
      await mfkdf.setup.factors.password('differentPassword3', {
        id: 'password3'
      })
    )

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('password1'),
      password3: mfkdf.derive.factors.password('differentPassword3')
    })
    derive.key.toString('hex').should.equal(key)
  })

  test('recoverFactors', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    await setup.recoverFactors([
      await mfkdf.setup.factors.password('differentPassword3', {
        id: 'password3'
      }),
      await mfkdf.setup.factors.password('otherPassword1', { id: 'password1' })
    ])

    const derive = await mfkdf.derive.key(setup.policy, {
      password1: mfkdf.derive.factors.password('otherPassword1'),
      password3: mfkdf.derive.factors.password('differentPassword3')
    })
    derive.key.toString('hex').should.equal(key)
  })

  test('reconstitute', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 3 }
    )
    const key = setup.key.toString('hex')

    await setup.reconstitute(
      ['password1'],
      [
        await mfkdf.setup.factors.password('otherPassword2', {
          id: 'password2'
        })
      ],
      2
    )

    const derive = await mfkdf.derive.key(setup.policy, {
      password2: mfkdf.derive.factors.password('otherPassword2'),
      password3: mfkdf.derive.factors.password('password3')
    })
    derive.key.toString('hex').should.equal(key)
  })

  test('defaults', async () => {
    const setup = await mfkdf.setup.key(
      [
        await mfkdf.setup.factors.password('password1', { id: 'password1' }),
        await mfkdf.setup.factors.password('password2', { id: 'password2' }),
        await mfkdf.setup.factors.password('password3', { id: 'password3' })
      ],
      { threshold: 2 }
    )
    const key = setup.key.toString('hex')

    await setup.reconstitute()

    const derive = await mfkdf.derive.key(setup.policy, {
      password2: mfkdf.derive.factors.password('password2'),
      password3: mfkdf.derive.factors.password('password3')
    })
    derive.key.toString('hex').should.equal(key)
  })

  suite('errors', () => {
    test('removeFactors/factor/type', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          [12345],
          [
            await mfkdf.setup.factors.password('otherPassword2', {
              id: 'password2'
            })
          ],
          2
        )
        .should.be.rejectedWith(TypeError)
    })

    test('removeFactors/factor/range', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          ['password4'],
          [
            await mfkdf.setup.factors.password('otherPassword2', {
              id: 'password2'
            })
          ],
          2
        )
        .should.be.rejectedWith(RangeError)
    })

    test('removeFactors/factor/id/unique', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 2 }
      )

      await setup
        .reconstitute(
          ['password3'],
          [
            await mfkdf.setup.factors.password('otherPassword2', {
              id: 'password2'
            }),
            await mfkdf.setup.factors.password('diffPassword2', {
              id: 'password2'
            })
          ],
          2
        )
        .should.be.rejectedWith(RangeError)
    })

    test('removeFactors/type', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          'hello',
          [
            await mfkdf.setup.factors.password('otherPassword2', {
              id: 'password2'
            })
          ],
          2
        )
        .should.be.rejectedWith(TypeError)
    })

    test('addFactors/type', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute([], '12345', 2)
        .should.be.rejectedWith(TypeError)
    })

    test('threshold/type', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute([], [], '12345')
        .should.be.rejectedWith(TypeError)
    })

    test('threshold/range', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup.reconstitute([], [], -1).should.be.rejectedWith(RangeError)
    })

    test('factor/type/type', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          [],
          [
            {
              type: 12345,
              id: 'password4',
              data: Buffer.from('password4', 'utf-8'),
              params: async () => {
                return {}
              },
              output: async () => {
                return {}
              }
            }
          ],
          3
        )
        .should.be.rejectedWith(TypeError)
    })

    test('factor/type/range', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          [],
          [
            {
              type: '',
              id: 'password4',
              data: Buffer.from('password4', 'utf-8'),
              params: async () => {
                return {}
              },
              output: async () => {
                return {}
              }
            }
          ],
          3
        )
        .should.be.rejectedWith(RangeError)
    })

    test('factor/id/type', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          [],
          [
            {
              type: 'password',
              id: 12345,
              data: Buffer.from('password4', 'utf-8'),
              params: async () => {
                return {}
              },
              output: async () => {
                return {}
              }
            }
          ],
          3
        )
        .should.be.rejectedWith(TypeError)
    })

    test('factor/id/range', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          [],
          [
            {
              type: 'password',
              id: '',
              data: Buffer.from('password4', 'utf-8'),
              params: async () => {
                return {}
              },
              output: async () => {
                return {}
              }
            }
          ],
          3
        )
        .should.be.rejectedWith(RangeError)
    })

    test('factor/data/type', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          [],
          [
            {
              type: 'password',
              id: 'password4',
              data: 12345,
              params: async () => {
                return {}
              },
              output: async () => {
                return {}
              }
            }
          ],
          3
        )
        .should.be.rejectedWith(TypeError)
    })

    test('factor/data/range', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          [],
          [
            {
              type: 'password',
              id: 'password4',
              data: Buffer.from(''),
              params: async () => {
                return {}
              },
              output: async () => {
                return {}
              }
            }
          ],
          3
        )
        .should.be.rejectedWith(RangeError)
    })

    test('factor/params/type', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          [],
          [
            {
              type: 'password',
              id: 'password4',
              data: Buffer.from('password4'),
              params: 12345,
              output: async () => {
                return {}
              }
            }
          ],
          3
        )
        .should.be.rejectedWith(TypeError)
    })

    test('factor/output/type', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup
        .reconstitute(
          [],
          [
            {
              type: 'password',
              id: 'password4',
              data: Buffer.from('password4'),
              params: async () => {
                return {}
              },
              output: 12345
            }
          ],
          3
        )
        .should.be.rejectedWith(TypeError)
    })

    test('threshold/range', async () => {
      const setup = await mfkdf.setup.key(
        [
          await mfkdf.setup.factors.password('password1', { id: 'password1' }),
          await mfkdf.setup.factors.password('password2', { id: 'password2' }),
          await mfkdf.setup.factors.password('password3', { id: 'password3' })
        ],
        { threshold: 3 }
      )

      await setup.reconstitute([], [], 4).should.be.rejectedWith(RangeError)
    })
  })
})
