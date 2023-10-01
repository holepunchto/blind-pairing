/*
ish ish protocol
inviter (a), candidate (b)

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

const Proof = {
  preencode (state, m) {
    c.fixed32.preencode(state, m.key)
    c.fixed64.preencode(state, m.signature)
  },
  encode (state, m) {
    c.fixed32.encode(state, m.key)
    c.fixed64.encode(state, m.signature)
  },
  decode (state) {
    return {
      key: c.fixed32.decode(state),
      signature: c.fixed64.decode(state)
    }
  }
}

class TimeoutPromise {
  constructor (ms) {
    this.ms = ms
    this.resolve = null
    this.timeout = null

    this._resolveBound = this._resolve.bind(this, true)
    this._ontimerBound = this._ontimer.bind(this)
  }

  wait () {
    if (this.timeout) this._resolve(false)
    return new Promise(this._ontimerBound)
  }

  destroy () {
    this._resolve(false)
  }

  _ontimer (resolve) {
    this.resolve = resolve
    this.timeout = setTimeout(this._resolveBound, this.ms)
  }

  _resolve (bool) {
    clearTimeout(this.timeout)

    const resolve = this.resolve
    this.timeout = null
    this.resolve = null

    resolve(bool)
  }
}

class Inviter extends ReadyResource {
  constructor (dht, { invite, id = getReceipt(invite), topic = getTopic(id), onadd = noop }) {
    super()

    const pollTime = (5000 * 1.5 * Math.random()) | 0

    this.dht = dht
    this.id = id
    this.blindingKey = deriveBlindingKey(this.id)
    this.topic = topic
    this.timeout = new TimeoutPromise(pollTime)
    this.started = null
    this.onadd = onadd

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

        if (visited.has(id)) continue
        visited.add(id)

        try {
          await this._add(peer.publicKey)
        } catch (err) {
          safetyCatch(err)
        }
      }
    }
  }

  async _add (publicKey) {
    const node = await this.dht.mutableGet(publicKey, { latest: false })
    if (!node) return false

    const msg = blindThrowaway(node.value, this.blindingKey, publicKey)
    const { key, signature } = c.decode(Proof, msg)

    if (!crypto.verify(key, signature, this.id)) return false

    const secret = await this.onadd(key)
    if (!secret) return false

    const replyKeyPair = getReplyKeyPair(this.id, key)
    await this.dht.mutablePut(replyKeyPair, blind(secret, getReplyBlindingKey(this.id, key)))
    return true
  }
}

class Candidate extends ReadyResource {
  constructor (dht, { key, invite, id = getReceipt(invite), topic = getTopic(id), onadd = noop }) {
    super()

    const pollTime = (5000 * 1.5 * Math.random()) | 0

    this.dht = dht
    this.key = key
    this.invite = invite
    this.id = id
    this.blindingKey = deriveBlindingKey(this.id)
    this.topic = topic
    this.timeout = new TimeoutPromise(pollTime)
    this.started = null
    this.onadd = onadd
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
    await this.announce()

    while (!this.closing) {
      const reply = await this.poll()
      if (reply) {
        await this.onadd(reply)
        return reply
      }

      await this.timeout.wait()
    }

    return null
  }

  async announce () {
    const eph = crypto.keyPair(this.key)

    // TODO: ask chm-diederichs if the signature is fully determisticly generated (requirement here for the throwaway)
    const signature = crypto.sign(this.key, this.invite)
    const msg = c.encode(Proof, { key: this.key, signature })
    const blindedMsg = blindThrowaway(msg, this.blindingKey, eph.publicKey)

    await this.dht.mutablePut(eph, blindedMsg)
    await this.dht.announce(this.topic, eph).finished()
  }

  async poll () {
    const replyKeyPair = getReplyKeyPair(this.id, this.key)
    const node = await this.dht.mutableGet(replyKeyPair.publicKey, { latest: false })
    if (!node) return null

    return unblind(node.value, getReplyBlindingKey(this.id, this.key))
  }
}

module.exports = {
  Inviter,
  Candidate,
  generateInvite
}

function generateInvite () {
  const kp = crypto.keyPair()

  return {
    version: 1,
    invite: kp.secretKey,
    id: kp.publicKey
  }
}

function noop () {}

function getTopic (id) {
  return crypto.hash([id, Buffer.from('invite-topic')])
}

function getReceipt (invite) {
  const publicKey = Buffer.allocUnsafe(32)
  sodium.crypto_sign_ed25519_sk_to_pk(publicKey, invite)
  return publicKey
}

function getReplyKeyPair (id, memberKey) {
  const replySeed = crypto.hash([id, memberKey, Buffer.from('invite-reply')])
  return crypto.keyPair(replySeed)
}

function getReplyBlindingKey (id, memberKey) {
  return crypto.hash([id, memberKey, Buffer.from('invite-reply-blinding-key')])
}

function deriveBlindingKey (id) {
  return crypto.hash([id, Buffer.from('invite-encryption-key')])
}

function blind (msg, secretKey) {
  const result = Buffer.allocUnsafe(msg.byteLength + sodium.crypto_stream_NONCEBYTES)
  const nonce = result.subarray(0, sodium.crypto_stream_NONCEBYTES)
  const cipher = result.subarray(nonce.byteLength)

  sodium.randombytes_buf(nonce)
  sodium.crypto_stream_xor(cipher, msg, nonce, secretKey)

  return result
}

function unblind (result, secretKey) {
  const nonce = result.subarray(0, sodium.crypto_stream_NONCEBYTES)
  const cipher = result.subarray(nonce.byteLength)
  const msg = Buffer.allocUnsafe(cipher.byteLength)

  sodium.crypto_stream_xor(msg, cipher, nonce, secretKey)

  return msg
}

function blindThrowaway (msg, blindingKey, publicKey) {
  const nonce = publicKey.subarray(0, sodium.crypto_stream_NONCEBYTES)
  const cipher = Buffer.allocUnsafe(msg.byteLength)

  sodium.crypto_stream_xor(cipher, msg, nonce, blindingKey)

  return cipher
}
