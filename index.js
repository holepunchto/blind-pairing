const crypto = require('hypercore-crypto')
const b4a = require('b4a')
const safetyCatch = require('safety-catch')
const ReadyResource = require('ready-resource')
const Xache = require('xache')
const { MemberRequest, CandidateRequest, createInvite, decodeInvite } = require('@holepunchto/blind-pairing-core')
const Protomux = require('protomux')
const c = require('compact-encoding')
const isOptions = require('is-options')

const [NS_EPHEMERAL, NS_REPLY, NS_DISCOVERY] = crypto.namespace('blind-pairing/dht', 3)

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

  static createInvite (key, opts) {
    return createInvite(key, opts)
  }

  static decodeInvite (invite) {
    return decodeInvite(invite)
  }

  static createRequest (invite, userData) {
    return new CandidateRequest(invite, userData)
  }

  addMember (opts) {
    return new Member(this, opts)
  }

  addCandidate (request, opts) {
    if (isOptions(request)) return this.addCandidate(null, request)
    if (!request) request = new CandidateRequest(opts.invite, opts.userData)
    return new Candidate(this, request, opts)
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

  _add (discoveryKey) {
    const id = b4a.toString(discoveryKey, 'hex')
    const t = this.active.get(id)
    if (t) return t

    const fresh = {
      id,
      discoveryKey,
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

    ref.discovery = this.swarm.join(ref.discoveryKey, { server, client })

    for (const conn of this.swarm.connections) {
      const mux = getMuxer(conn)
      this._attachToMuxer(mux, ref.discoveryKey, ref)
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
      mux.unpair({ protocol: 'blind-pairing', id: ref.discoveryKey })
    }
    if (ref.discovery) ref.discovery.destroy().catch(safetyCatch)
    return true
  }

  _onconnection (conn) {
    const mux = getMuxer(conn)

    for (const ref of this.active.values()) {
      this._attachToMuxer(mux, ref.discoveryKey, ref)
    }
  }

  _attachToMuxer (mux, discoveryKey, ref) {
    if (!ref) ref = this._add(discoveryKey)

    const ch = mux.createChannel({
      protocol: 'blind-pairing',
      id: discoveryKey,
      messages: [
        { encoding: c.buffer, onmessage: (req) => this._onpairingrequest(ch, ref, req) },
        { encoding: c.buffer, onmessage: (res) => this._onpairingresponse(ch, ref, res) }
      ],
      onclose: () => {
        ref.channels.delete(ch)
      }
    })

    if (ch === null) return

    ch.open()
    mux.pair({ protocol: 'blind-pairing', id: discoveryKey }, () => this._attachToMuxer(mux, discoveryKey, null))
    ref.channels.add(ch)
    if (ref.candidate) ref.candidate._sendRequest(ch)
  }

  async _onpairingrequest (ch, ref, req) {
    if (!ref.member) return

    const request = await ref.member._addRequest(req)
    if (!request) return

    ch.messages[1].send(request.response)
  }

  async _onpairingresponse (ch, ref, res) {
    if (!ref.candidate) return

    await ref.candidate._addResponse(res, false)
  }
}

class Member extends ReadyResource {
  constructor (blind, { discoveryKey, onadd = noop } = {}) {
    super()

    if (!discoveryKey) {
      throw new Error('Must provide discoveryKey')
    }

    const ref = blind._add(discoveryKey)

    if (ref.member) {
      throw new Error('Active member already exist')
    }

    ref.member = this

    this._pendingRequests = new Map()

    this.blind = blind
    this.dht = blind.swarm.dht
    this.discoveryKey = discoveryKey
    this.pairingDiscoveryKey = deriveDiscoveryKey(discoveryKey)
    this.timeout = new TimeoutPromise(blind._randomPoll())
    this.pairing = null
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
    this.blind._swarm(this.ref)
    this.pairing = this._run()
    this.pairing.catch(safetyCatch)
  }

  async _close () {
    this.ref.member = null
    this.blind._gc(this.ref)
    this.timeout.destroy()

    try {
      await this.pairing
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

    for await (const data of this.dht.lookup(this.pairingDiscoveryKey)) {
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

    request.discoveryKey = this.discoveryKey

    const session = b4a.toString(request.requestData.session, 'hex')

    if (!this._pendingRequests.has(session)) {
      this._pendingRequests.set(session, {
        request,
        promise: this.onadd(request)
      })
    }

    // laod existing request if it exists
    const pending = this._pendingRequests.get(session)

    try {
      await pending.promise
    } catch (e) {
      safetyCatch(e)
      return null
    }

    this._pendingRequests.delete(session)

    if (!pending.request.response) return null

    return pending.request
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
  constructor (blind, request, { discoveryKey = request.discoveryKey, onadd = noop } = {}) {
    super()

    const ref = blind._add(discoveryKey)
    if (ref.candidate) {
      throw new Error('Active candidate already exist')
    }

    ref.candidate = this

    this.blind = blind
    this.discoveryKey = discoveryKey
    this.pairingDiscoveryKey = deriveDiscoveryKey(discoveryKey)
    this.dht = blind.swarm.dht
    this.request = request
    this.token = request.token
    this.timeout = new TimeoutPromise(blind._randomPoll())
    this.announced = false
    this.gcing = null
    this.ref = ref
    this.paired = null
    this.pairing = null
    this.onadd = onadd

    this.ready()
  }

  _open () {
    this.blind._swarm(this.ref)
    this.pairing = this._run()
    this.pairing.catch(safetyCatch)
    this._broadcast()
  }

  async _close () {
    this.ref.candidate = null
    this.blind._gc(this.ref)
    this.timeout.destroy()
    try {
      await this.pairing
    } catch {
      // ignore errors since we teardown
    }
    // gc never throws
    if (this.gcing) await this.gcing
  }

  async _addResponse (value, gc) {
    if (this.paired) return

    const paired = this.request.handleResponse(value)
    if (!paired) return

    this.paired = paired

    if ((gc || this.announced) && !this.gcing) this.gcing = this._gc() // gc in the background
    await this.onadd(paired)
    this.timeout.destroy()
  }

  async _run () {
    while (!this._done()) {
      const value = await this._poll()
      if (this._done()) break

      if (value) {
        await this._addResponse(value, true)
        if (this._done()) break
      }

      if (!this.announced) {
        this.announced = true
        await this._announce()
        if (this._done()) break
      }

      await this.timeout.wait()
    }

    this.close().catch(safetyCatch)
    return this.paired
  }

  _done () {
    return !!(this.closing || this.paired)
  }

  async _announce () {
    const eph = deriveEphemeralKeyPair(this.token)

    await this.dht.mutablePut(eph, this.request.encode())
    if (this._done()) return

    await this.dht.announce(this.pairingDiscoveryKey, eph).finished()
    this.emit('announce')
  }

  async _gc () {
    const eph = deriveEphemeralKeyPair(this.token)

    try {
      await this.dht.unannounce(this.pairingDiscoveryKey, eph)
    } catch (err) {
      safetyCatch(err) // just gc, whatevs
    }
  }

  _sendRequest (ch) {
    ch.messages[0].send(this.request.encode())
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

function deriveDiscoveryKey (discoveryKey) {
  return crypto.hash([NS_DISCOVERY, discoveryKey])
}

function getMuxer (stream) {
  if (stream.userData) return stream.userData
  const protocol = Protomux.from(stream)
  stream.setKeepAlive(5000)
  stream.userData = protocol
  return protocol
}
