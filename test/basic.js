const Hyperswarm = require('hyperswarm')
const createTestnet = require('@hyperswarm/testnet')
const test = require('brittle')
const BlindPairing = require('../index.js')

test('basic - simple', async t => {
  t.plan(6)

  const testnet = await createTestnet(3)
  const bootstrap = testnet.bootstrap
  const key = Buffer.alloc(32).fill('the-autobase-key')

  t.teardown(() => testnet.destroy())

  const [a, b] = create(2, t, { bootstrap })

  await a.ready()
  await b.ready()

  const { invite, publicKey, id, discoveryKey } = BlindPairing.createInvite(key)

  const userData = Buffer.alloc(32).fill('i am a candidate')

  const member = a.addMember({
    discoveryKey,
    onadd (request) {
      request.open(publicKey)

      t.alike(request.inviteId, id)
      t.alike(request.publicKey, publicKey)
      t.alike(request.userData, userData)
      t.absent(request.response)

      request.confirm({ key })

      t.ok(request.response)
    }
  })

  await member.ready()
  await member.flushed()

  const candidate = b.addCandidate({
    invite,
    userData,
    onadd (response) {
      t.alike(response.key, key)
    }
  })

  await candidate.ready()
})

test('basic - multiple request', async t => {
  t.plan(2)

  const testnet = await createTestnet()
  const bootstrap = testnet.bootstrap
  const key = Buffer.alloc(32).fill('the-autobase-key')

  t.teardown(() => testnet.destroy())

  const [a, b, c] = create(3, t, { bootstrap })

  const { invite, publicKey, discoveryKey } = BlindPairing.createInvite(key)

  const userData1 = Buffer.alloc(32).fill(1)
  const userData2 = Buffer.alloc(32).fill(2)

  const member = a.addMember({
    discoveryKey,
    async onadd (candidate) {
      candidate.open(publicKey)
      candidate.confirm({ key })
    }
  })

  await member.flushed()

  b.addCandidate({
    invite,
    userData: userData1,
    async onadd (response) {
      t.alike(response.key, key)
    }
  })

  c.addCandidate({
    invite,
    userData: userData2,
    async onadd (response) {
      t.alike(response.key, key)
    }
  })
})

test('basic - multiple members', async t => {
  t.plan(2)

  const testnet = await createTestnet()
  const bootstrap = testnet.bootstrap
  const key = Buffer.alloc(32).fill('the-autobase-key')

  t.teardown(() => testnet.destroy())

  const [a, b, c] = create(3, t, { bootstrap })

  const { invite, publicKey, discoveryKey } = BlindPairing.createInvite(key)

  const userData = Buffer.alloc(32).fill(1)

  let added = 0

  const member1 = a.addMember({
    discoveryKey,
    async onadd (candidate) {
      added++
      candidate.open(publicKey)
      candidate.confirm({ key })
    }
  })

  const member2 = b.addMember({
    discoveryKey,
    async onadd (candidate) {
      added++
      candidate.open(publicKey)
      candidate.confirm({ key })
    }
  })

  await member1.flushed()
  await member2.flushed()

  c.addCandidate({
    invite,
    userData,
    async onadd (response) {
      t.alike(response.key, key)
    }
  })

  setTimeout(() => {
    t.is(added, 1)
  }, 10000)
})

test('basic - multiple members, one is slow', async t => {
  t.plan(2)

  const testnet = await createTestnet()
  const bootstrap = testnet.bootstrap
  const key = Buffer.alloc(32).fill('the-autobase-key')

  t.teardown(() => testnet.destroy())

  const [a, b, c] = create(3, t, { bootstrap })

  const { invite, publicKey, discoveryKey } = BlindPairing.createInvite(key)

  const userData = Buffer.alloc(32).fill(1)

  let added = 0

  const member1 = a.addMember({
    discoveryKey,
    async onadd (candidate) {
      if (added++ === 0) await new Promise(resolve => setTimeout(resolve, 5000))
      candidate.open(publicKey)
      candidate.confirm({ key })
    }
  })

  const member2 = b.addMember({
    discoveryKey,
    async onadd (candidate) {
      if (added++ === 0) await new Promise(resolve => setTimeout(resolve, 5000))
      candidate.open(publicKey)
      candidate.confirm({ key })
    }
  })

  await member1.flushed()
  await member2.flushed()

  c.addCandidate({
    invite,
    userData,
    async onadd (response) {
      t.alike(response.key, key)
    }
  })

  setTimeout(() => {
    t.is(added, 2)
  }, 10000)
})

function createPairing (t, { bootstrap, poll } = {}) {
  const swarm = new Hyperswarm({ bootstrap })
  const pairing = new BlindPairing(swarm, { poll })

  t.teardown(() => {
    pairing.close()
    swarm.destroy()
  })

  return pairing
}

function create (n, t, opts = {}) {
  const p = []
  for (let i = 0; i < n; i++) p.push(createPairing(t, opts))

  return p
}
