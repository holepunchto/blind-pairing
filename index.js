const crypto = require('hypercore-crypto')
const b4a = require('b4a')
const safetyCatch = require('safety-catch')
const ReadyResource = require('ready-resource')
const Xache = require('xache')
const { MemberRequest, CandidateRequest, createInvite } = require('@holepunchto/blind-pairing-core')
const Protomux = require('protomux')
const c = require('compact-encoding')

const [NS_EPHEMERAL, NS_REPLY] = crypto.namespace('blind-pairing/dht', 2)

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

class BlindPairing extends ReadyResource {
  constructor (swarm, { poll = DEFAULT_POLL } = {}) {
    super()

    this.swarm = swarm
    this.poll = poll
    this.active = new Map()

    this._onconnectionBound = this._onconnection.bind(this)

    this.swarm.on('connection', this._onconnectionBound)
  }

  static createInvite (key) {
    return createInvite(key)
  }

  static createRequest (invite, userData) {
    return new CandidateRequest(invite, userData)
  }

  addMember (topic, opts) {
    return new Member(this, topic, opts)
  }

  addCandidate (topic, request, opts) {
    return new Candidate(this, topic, request, opts)
  }

  async _close () {
    this.swarm.removeListener('connection', this._onconnectionBound)

    const all = []

    for (const ref of this.active.values()) {
      if (ref.member) all.push(ref.member.close())
      if (ref.candidate) all.push(ref.candidate.close())
      if (ref.discovery) all.push(ref.discovery.destroy())
    }

    await Promise.allSettled(all)
  }

  _randomPoll () {
    return this.poll + (this.poll * 0.5 * Math.random()) | 0
  }

  _add (topic) {
    const id = b4a.toString(topic, 'hex')
    const t = this.active.get(id)
    if (t) return t

    const fresh = {
      id,
      topic,
      member: null,
      candidate: null,
      channels: new Set(),
      discovery: null
    }

    this.active.set(id, fresh)
    return fresh
  }

  _swarm (ref) {
    const server = !!ref.member
    const client = !!ref.candidate

    if (ref.discovery && ref.discovery.isServer === server && ref.discovery.isClient === client) {
      return
    }

    if (ref.discovery) ref.discovery.destroy().catch(safetyCatch)

    // just a sanity check, not needed but doesnt hurt
    if (!server && !client) return

    ref.discovery = this.swarm.join(ref.topic, { server, client })

    for (const conn of this.swarm.connections) {
      const mux = getMuxer(conn)
      this._attachToMuxer(mux, ref.topic, ref)
    }
  }

  _gc (ref) {
    if (ref.member || ref.candidate) {
      if (ref.discovery) this._swarm(ref) // in case it needs updating...
      return false
    }
    this.active.delete(ref.id)
    for (const ch of ref.channels) ch.close()
    for (const conn of this.swarm.connections) {
      const mux = getMuxer(conn)
      mux.unpair({ protocol: 'blind-pairing', id: ref.topic })
    }
    if (ref.discovery) ref.discovery.destroy().catch(safetyCatch)
    return true
  }

  _onconnection (conn) {
    const mux = getMuxer(conn)

    for (const ref of this.active.values()) {
      this._attachToMuxer(mux, ref.topic, ref)
    }
  }

  _attachToMuxer (mux, topic, ref) {
    if (!ref) ref = this._add(topic)

    const ch = mux.createChannel({
      protocol: 'blind-pairing',
      id: topic,
      messages: [
        { encoding: c.any, onmessage: (m) => this._onpairingrequest(ch, ref, m) },
        { encoding: c.any, onmessage: (m) => this._onpairingresponse(ch, ref, m) }
      ],
      onclose: () => {
        ref.channels.delete(ch)
      }
    })

    if (ch === null) return

    ch.open()
    mux.pair({ protocol: 'blind-pairing', id: topic }, () => this._attachToMuxer(mux, topic, null))
    ref.channels.add(ch)
    if (ref.candidate) ref.candidate._sendRequest(ch)
  }

  async _onpairingrequest (ch, ref, m) {
    if (!ref.member) return

    const request = await ref.member._addRequest(m.request)
    if (!request) return

    ch.messages[1].send({
      id: m.id,
      response: request.response
    })
  }

  async _onpairingresponse (ch, ref, m) {
    // we only support a single candidate atm, expect it to be there
    if (!ref.candidate || m.id !== 0) return

    await ref.candidate._addResponse(m.response)
  }
}

class Member extends ReadyResource {
  constructor (pairing, topic, { onadd = noop } = {}) {
    super()

    const ref = pairing._add(topic)

    if (ref.member) {
      throw new Error('Active member already exist')
    }

    ref.member = this

    this.pairing = pairing
    this.dht = pairing.swarm.dht
    this.topic = topic
    this.timeout = new TimeoutPromise(pairing._randomPoll())
    this.running = null
    this.skip = new Xache({ maxSize: 512 })
    this.ref = ref
    this.onadd = onadd

    this.ready()
  }

  async flushed () {
    if (!this.ref.discovery) return
    return this.ref.discovery.flushed()
  }

  _open () {
    this.pairing._swarm(this.ref)
    this.running = this._run()
    this.running.catch(safetyCatch)
  }

  async _close () {
    this.ref.member = null
    this.pairing._gc(this.ref)
    this.timeout.destroy()

    try {
      await this.running
    } catch {
      // ignore errors since we teardown
    }
  }

  async _run () {
    while (!this.closing) {
      await this._poll()
      await this.timeout.wait()
    }
  }

  async _poll () {
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

  async _addRequest (value) {
    let request = null
    try {
      request = MemberRequest.from(value)
    } catch {
      return null
    }

    try {
      await this.onadd(request)
    } catch (e) {
      safetyCatch(e)
      return null
    }

    if (!request.response) return null

    return request
  }

  async _add (publicKey, id) {
    const node = await this.dht.mutableGet(publicKey, { latest: false })
    if (!node) return false

    this.skip.set(id, true)

    const request = await this._addRequest(node.value)
    if (!request) return false

    const replyKeyPair = deriveReplyKeyPair(request.token)
    await this.dht.mutablePut(replyKeyPair, request.response)

    return true
  }
}

class Candidate extends ReadyResource {
  constructor (pairing, topic, request, { onadd = noop } = {}) {
    super()

    const ref = pairing._add(topic)
    if (ref.candidate) {
      throw new Error('Active candidate already exist')
    }

    ref.candidate = this

    this.pairing = pairing
    this.topic = topic
    this.dht = pairing.swarm.dht
    this.request = request
    this.token = request.token
    this.timeout = new TimeoutPromise(pairing._randomPoll())
    this.running = null
    this.announced = false
    this.gcing = null
    this.ref = ref
    this.paired = null
    this.onadd = onadd

    this.ready()
  }

  _open () {
    this.pairing._swarm(this.ref)
    this.running = this._run()
    this.running.catch(safetyCatch)
    this._broadcast()
  }

  async _close () {
    this.ref.candidate = null
    this.pairing._gc(this.ref)
    this.timeout.destroy()
    try {
      await this.running
    } catch {
      // ignore errors since we teardown
    }
    // gc never throws
    if (this.gcing) await this.gcing
  }

  async _addResponse (value) {
    if (this.paired) return

    const paired = this.request.handleResponse(value)
    if (!paired) return

    this.paired = paired
    if (this.announced && !this.gcing) this.gcing = this._gc() // gc in the background
    await this.onadd(paired)
  }

  async _run () {
    while (!this._done()) {
      const value = await this._poll()
      if (this._done()) return

      if (value) {
        await this._addResponse(value)
        if (this._done()) return
      }

      if (!this.announced) {
        this.announced = true
        await this._announce()
        if (this._done()) return
      }

      await this.timeout.wait()
    }
  }

  _done () {
    return !!(this.closing || this.paired)
  }

  async _announce () {
    const eph = deriveEphemeralKeyPair(this.token)

    await this.dht.mutablePut(eph, this.request.encode())
    if (this._done()) return

    await this.dht.announce(this.topic, eph).finished()
  }

  async _gc () {
    const eph = deriveEphemeralKeyPair(this.token)

    try {
      await this.dht.unannounce(this.topic, eph)
    } catch (err) {
      safetyCatch(err) // just gc, whatevs
    }
  }

  _sendRequest (ch) {
    ch.messages[0].send({
      id: 0, // just in case we ever wanna have multiple active candidates...
      request: this.request.encode()
    })
  }

  _broadcast () {
    for (const ch of this.ref.channels) this._sendRequest(ch)
  }

  async _poll () {
    const { publicKey } = deriveReplyKeyPair(this.token)
    const node = await this.dht.mutableGet(publicKey, { latest: false })
    if (!node) return null
    return node.value
  }
}

module.exports = BlindPairing

function noop () {}

function deriveReplyKeyPair (token) {
  return crypto.keyPair(crypto.hash([NS_REPLY, token]))
}

function deriveEphemeralKeyPair (token) {
  return crypto.keyPair(crypto.hash([NS_EPHEMERAL, token]))
}

function getMuxer (stream) {
  if (stream.userData) return stream.userData
  const protocol = Protomux.from(stream)
  stream.setKeepAlive(5000)
  stream.userData = protocol
  return protocol
}
