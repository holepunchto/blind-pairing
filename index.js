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

const crypto = require('hypercore-crypto')
const b4a = require('b4a')
const safetyCatch = require('safety-catch')
const ReadyResource = require('ready-resource')
const Xache = require('xache')
const { MemberRequest, createInvite } = require('@holepunchto/blind-pairing-core')

const DEFAULT_POLL = 7 * 60 * 1000

class TimeoutPromise {
  constructor (ms) {
    this.ms = ms
    this.resolve = null
    this.timeout = null
    this.destroyed = false

    this._resolveBound = this._resolve.bind(this)
    this._ontimerBound = this._ontimer.bind(this)
  }

  wait () {
    if (this.destroyed) return Promise.resolve()

    if (this.timeout) this._resolve()
    return new Promise(this._ontimerBound)
  }

  destroy () {
    this.destroyed = true
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
  constructor (swarm, { poll = DEFAULT_POLL, invite, topic = invite && (invite.discoveryKey || getTopic(invite.id)), onadd = noop }) {
    if (!topic) throw new Error('Topic must be provided')
    super()

    const randomizedPollTime = poll + (poll * 0.5 * Math.random()) | 0

    this.dht = swarm.dht
    this.topic = topic
    this.timeout = new TimeoutPromise(randomizedPollTime)
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

    let request = null
    try {
      request = MemberRequest.from(node.value)
    } catch {
      return false
    }

    try {
      await this.onadd(request)
    } catch (e) {
      safetyCatch(e)
      return false
    }

    if (!request.response) {
      return false // should we post deny?
    }

    const replyKeyPair = getReplyKeyPair(request.token)
    await this.dht.mutablePut(replyKeyPair, request.response)

    return true
  }
}

// request should be keetPairing.CandidateRequest
class Candidate extends ReadyResource {
  constructor (swarm, request, { poll = DEFAULT_POLL, topic = (request.discoveryKey || getTopic(request.id)), onadd = noop } = {}) {
    super()

    const randomizedPollTime = poll + (poll * 0.5 * Math.random()) | 0

    this.dht = swarm.dht
    this.request = request
    this.key = request.userData
    this.topic = topic
    this.timeout = new TimeoutPromise(randomizedPollTime)
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
    let announced = false

    while (!this.closing) {
      const reply = await this.poll()
      if (reply) {
        this._gcBackground()
        await this.onadd(reply)
        return reply
      }
      if (!announced) {
        await this.announce()
        announced = true
      }

      await this.timeout.wait()
    }

    return null
  }

  async announce () {
    const eph = deriveEphemeralKeyPair(this.key, this.request.seed)

    await this.dht.mutablePut(eph, this.request.encode())
    await this.dht.announce(this.topic, eph).finished()
  }

  async gc () {
    const eph = deriveEphemeralKeyPair(this.key, this.request.seed)

    try {
      await this.dht.unannounce(this.topic, eph)
    } catch (err) {
      safetyCatch(err) // just gc, whatevs
    }
  }

  async poll () {
    const { publicKey } = getReplyKeyPair(this.request.token)
    const node = await this.dht.mutableGet(publicKey, { latest: false })
    if (!node) return null

    return this.request.handleResponse(node.value)
  }
}

module.exports = {
  Member,
  Candidate,
  createInvite
}

function noop () {}

function getTopic (id) {
  return crypto.hash([id, b4a.from('invite-topic')])
}

function getReplyKeyPair (token) {
  const replySeed = crypto.hash([token, b4a.from('invite-reply')])
  return crypto.keyPair(replySeed)
}

function deriveEphemeralKeyPair (memberKey, seed) {
  return crypto.keyPair(crypto.hash([memberKey, seed, b4a.from('invite-ephemeral-key-pair')]))
}
