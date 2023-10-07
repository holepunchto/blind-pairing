/*
ish ish protocol
member (a), candidate (b)

1) a sends b an invite out of band, random-key=r, invite={r.publicKey}
2) b uses the invite to generate the topic, keyPair(r.publicKey + 'protopair')
   b generates an emphemeral keypair, k and adds k.publicKey to the set in the dht
   b generates a reply keypair=keyPair(autobase_member_key + r.publicKey + 'reply'),
   and stores in the dht k.publicKey -> assymmetric_enc(autobase_member_key, publicKey=r.publicKey)
3) a polls the topic, on new entry a does:
     read k.publicKey -> decrypt the payload -> add autobase_member -> write reply (encryption-key + autobase-key) assymmetric_enc to the reply keypair
4) b polls the reply keypair, on new entry it checks the validity and the pairing is done
*/

const sodium = require('sodium-native')
const crypto = require('hypercore-crypto')
const b4a = require('b4a')
const safetyCatch = require('safety-catch')
const c = require('compact-encoding')
const ReadyResource = require('ready-resource')
const Xache = require('xache')

const Proof = {
  preencode (state, m) {
    c.fixed32.preencode(state, m.id)
    c.fixed32.preencode(state, m.key)
    c.fixed64.preencode(state, m.signature)
  },
  encode (state, m) {
    c.fixed32.encode(state, m.id)
    c.fixed32.encode(state, m.key)
    c.fixed64.encode(state, m.signature)
  },
  decode (state) {
    return {
      id: c.fixed32.decode(state),
      key: c.fixed32.decode(state),
      signature: c.fixed64.decode(state)
    }
  }
}

const Result = {
  preencode (state, m) {
    state.end++ // flags
    c.fixed32.preencode(state, m.key)
    if (m.encryptionKey) c.fixed32.preencode(state, m.encryptionKey)
  },
  encode (state, m) {
    c.uint.encode(state, m.encryptionKey ? 1 : 0)
    c.fixed32.encode(state, m.key)
    if (m.encryptionKey) c.fixed32.encode(state, m.encryptionKey)
  },
  decode (state) {
    const flags = c.uint.decode(state)
    return {
      key: c.fixed32.decode(state),
      encryptionKey: (flags & 1) !== 0 ? c.fixed32.decode(state) : null
    }
  }
}

class TimeoutPromise {
  constructor (ms) {
    this.ms = ms
    this.resolve = null
    this.timeout = null

    this._resolveBound = this._resolve.bind(this)
    this._ontimerBound = this._ontimer.bind(this)
  }

  wait () {
    if (this.timeout) this._resolve()
    return new Promise(this._ontimerBound)
  }

  destroy () {
    if (this.resolve) this._resolve(false)
  }

  _ontimer (resolve) {
    this.resolve = resolve
    this.timeout = setTimeout(this._resolveBound, this.ms)
  }

  _resolve () {
    clearTimeout(this.timeout)

    const resolve = this.resolve
    this.timeout = null
    this.resolve = null

    resolve()
  }
}

class Member extends ReadyResource {
  constructor (dht, { invite, id = getReceipt(invite), topic = getTopic(id), onadd = noop }) {
    super()

    const pollTime = 5000 + (5000 * 0.5 * Math.random()) | 0

    this.dht = dht
    this.id = id
    this.blindingKey = deriveBlindingKey(this.id)
    this.topic = topic
    this.timeout = new TimeoutPromise(pollTime)
    this.started = null
    this.onadd = onadd
    this.skip = new Xache({ maxSize: 512 })

    this.ready()
  }

  async start () {
    if (this.started === null) this.started = this._start()
    return this.started
  }

  _open () {
    if (this.started === null) this.start().catch(safetyCatch)
  }

  _close () {
    this.timeout.destroy()
  }

  async _start () {
    while (!this.closing) {
      await this.poll()
      await this.timeout.wait()
    }
  }

  async poll () {
    const visited = new Set()

    for await (const data of this.dht.lookup(this.topic)) {
      for (const peer of data.peers) {
        const id = b4a.toString(peer.publicKey, 'hex')

        if (visited.has(id) || this.skip.get(id)) continue
        visited.add(id)

        try {
          await this._add(peer.publicKey, id)
        } catch (err) {
          safetyCatch(err)
        }
      }
    }
  }

  async _add (publicKey, id) {
    const node = await this.dht.mutableGet(publicKey, { latest: false })
    if (!node) return false

    this.skip.set(id, true)

    const msg = blindThrowaway(node.value, this.blindingKey, publicKey)
    const candidate = c.decode(Proof, msg)

    if (!verifyInvite(candidate)) {
      return false
    }

    const result = await this.onadd(candidate)
    if (!result) {
      return false
    }

    const buf = c.encode(Result, result)
    const replyKeyPair = getReplyKeyPair(candidate.id, candidate.key)
    await this.dht.mutablePut(replyKeyPair, blind(buf, getReplyBlindingKey(candidate.id, candidate.key)))

    return true
  }
}

class Candidate extends ReadyResource {
  constructor (dht, { key, invite, seed = crypto.randomBytes(32), id = getReceipt(invite), topic = getTopic(id), onadd = noop }) {
    super()

    const pollTime = 5000 + (5000 * 0.5 * Math.random()) | 0

    this.dht = dht
    this.key = key
    this.seed = seed
    this.invite = invite
    this.id = id
    this.blindingKey = deriveBlindingKey(this.id)
    this.topic = topic
    this.timeout = new TimeoutPromise(pollTime)
    this.started = null
    this.gcing = null
    this.onadd = onadd
  }

  async start () {
    if (this.started === null) this.started = this._start()
    return this.started
  }

  _gcBackground () {
    if (!this.gcing) this.gcing = this.gc()
  }

  _open () {
    if (this.started === null) this.start().catch(safetyCatch)
  }

  async _close () {
    this.timeout.destroy()
    this._gcBackground()
    await this.gcing
  }

  async _start () {
    await this.announce()

    while (!this.closing) {
      const reply = await this.poll()
      if (reply) {
        this._gcBackground()
        await this.onadd(reply)
        return reply
      }

      await this.timeout.wait()
    }

    return null
  }

  async announce () {
    const eph = deriveEphemeralKeyPair(this.id, this.key, this.seed)

    // TODO: ask chm-diederichs if the signature is fully determisticly generated (requirement here for the throwaway)
    const signature = crypto.sign(this.key, this.invite)
    const msg = c.encode(Proof, { id: this.id, key: this.key, signature })

    const blindedMsg = blindThrowaway(msg, this.blindingKey, eph.publicKey)

    await this.dht.mutablePut(eph, blindedMsg)
    await this.dht.announce(this.topic, eph).finished()
  }

  async gc () {
    const eph = deriveEphemeralKeyPair(this.id, this.key, this.seed)

    try {
      await this.dht.unannounce(this.topic, eph)
    } catch (err) {
      safetyCatch(err) // just gc, whatevs
    }
  }

  async poll () {
    const replyKeyPair = getReplyKeyPair(this.id, this.key)
    const node = await this.dht.mutableGet(replyKeyPair.publicKey, { latest: false })
    if (!node) return null

    const buf = unblind(node.value, getReplyBlindingKey(this.id, this.key))
    return c.decode(Result, buf)
  }
}

module.exports = {
  Member,
  Candidate,
  generateInvite,
  verifyInvite,
  getReceipt
}

function verifyInvite (candidate) {
  return crypto.verify(candidate.key, candidate.signature, candidate.id)
}

function generateInvite ({ expires = 0, app = null } = {}) {
  const kp = crypto.keyPair()

  return {
    version: 1,
    invite: kp.secretKey,
    id: kp.publicKey,
    expires
  }
}

function noop () {}

function getTopic (id) {
  return crypto.hash([id, b4a.from('invite-topic')])
}

function getReceipt (invite) {
  const publicKey = b4a.allocUnsafe(32)
  sodium.crypto_sign_ed25519_sk_to_pk(publicKey, invite)
  return publicKey
}

function getReplyKeyPair (id, memberKey) {
  const replySeed = crypto.hash([id, memberKey, b4a.from('invite-reply')])
  return crypto.keyPair(replySeed)
}

function getReplyBlindingKey (id, memberKey) {
  return crypto.hash([id, memberKey, b4a.from('invite-reply-blinding-key')])
}

function deriveBlindingKey (id) {
  return crypto.hash([id, b4a.from('invite-encryption-key')])
}

function deriveEphemeralKeyPair (id, memberKey, seed) {
  return crypto.keyPair(crypto.hash([id, memberKey, seed, b4a.from('invite-ephemeral-key-pair')]))
}

function blind (msg, secretKey) {
  const result = b4a.allocUnsafe(msg.byteLength + sodium.crypto_stream_NONCEBYTES)
  const nonce = result.subarray(0, sodium.crypto_stream_NONCEBYTES)
  const cipher = result.subarray(nonce.byteLength)

  sodium.randombytes_buf(nonce)
  sodium.crypto_stream_xor(cipher, msg, nonce, secretKey)

  return result
}

function unblind (result, secretKey) {
  const nonce = result.subarray(0, sodium.crypto_stream_NONCEBYTES)
  const cipher = result.subarray(nonce.byteLength)
  const msg = b4a.allocUnsafe(cipher.byteLength)

  sodium.crypto_stream_xor(msg, cipher, nonce, secretKey)

  return msg
}

function blindThrowaway (msg, blindingKey, publicKey) {
  const nonce = publicKey.subarray(0, sodium.crypto_stream_NONCEBYTES)
  const cipher = b4a.allocUnsafe(msg.byteLength)

  sodium.crypto_stream_xor(cipher, msg, nonce, blindingKey)

  return cipher
}
