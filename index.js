const crypto = require('hypercore-crypto')
const b4a = require('b4a')
const safetyCatch = require('safety-catch')
const ReadyResource = require('ready-resource')
const Xache = require('xache')
const { MemberRequest, CandidateRequest, createInvite, decodeInvite, verifyReceipt, Invite } = require('blind-pairing-core')
const Protomux = require('protomux')
const c = require('compact-encoding')
const debounce = require('debounceify')
const isOptions = require('is-options')

const [NS_EPHEMERAL, NS_REPLY, NS_DISCOVERY] = crypto.namespace('blind-pairing/dht', 3)

const DEFAULT_POLL = 7 * 60 * 1000
const PEER_INTERVAL = 1000

class TimeoutPromise {
  constructor (ms) {
    this.ms = ms
    this.resolve = null
    this.timeout = null
    this.destroyed = false
    this.suspended = false

    this._resolveBound = this._resolve.bind(this)
    this._ontimerBound = this._ontimer.bind(this)
  }

  wait () {
    if (this.destroyed) return Promise.resolve()
    if (this.resolve) this._resolve()
    return new Promise(this._ontimerBound)
  }

  suspend () {
    this.suspended = true
    if (this.timeout !== null) clearTimeout(this.timeout)
    this.timeout = null
  }

  resume () {
    this.suspended = false
    if (this.resolve) this._resolve()
  }

  destroy () {
    this.destroyed = true
    if (this.resolve) this._resolve()
  }

  _ontimer (resolve) {
    this.resolve = resolve
    if (!this.suspended) this.timeout = setTimeout(this._resolveBound, this.ms)
  }

  _resolve () {
    if (this.timeout !== null) clearTimeout(this.timeout)

    const resolve = this.resolve
    this.timeout = null
    this.resolve = null

    resolve()
  }
}

class BlindPairing extends ReadyResource {
  constructor (swarm, { poll = DEFAULT_POLL, onincoming = noop } = {}) {
    super()

    this.swarm = swarm
    this.poll = poll
    this.active = new Map()
    this.suspended = false

    this._onincoming = onincoming
    this._onconnectionBound = this._onconnection.bind(this)
    this._refreshBound = this.refresh.bind(this)
    this._refreshing = null

    this.swarm.on('connection', this._onconnectionBound)
    this.swarm.dht.on('network-change', this._refreshBound)
  }

  static Invite = Invite

  static createInvite (key, opts) {
    return createInvite(key, opts)
  }

  static decodeInvite (invite) {
    return decodeInvite(invite)
  }

  static verifyReceipt (receipt, publicKey) {
    return verifyReceipt(receipt, publicKey)
  }

  static createRequest (invite, userData) {
    return new CandidateRequest(invite, userData)
  }

  async suspend () {
    if (this.suspended) return
    this.suspended = true

    const all = []

    for (const ref of this.active.values()) {
      if (ref.candidate) all.push(ref.candidate._suspend())
      if (ref.member) all.push(ref.member._suspend())
    }

    await Promise.allSettled(all)
  }

  resume () {
    if (!this.suspended) return
    this.suspended = false
    this.refresh().catch(safetyCatch) // no need to wait for the refreshes
  }

  async refresh () {
    if (this._refreshing) {
      await this._refreshing
      return
    }

    if (this.closing || this.suspended) return

    const r = this._refreshing = this._refresh()

    try {
      await r
    } finally {
      if (r === this._refreshing) this._refreshing = null
    }
  }

  async _refresh () {
    if (this.closing || this.suspended) return

    const all = []

    for (const ref of this.active.values()) {
      if (ref.candidate) all.push(ref.candidate.refresh())
      if (ref.member) all.push(ref.member.refresh())
    }

    await Promise.allSettled(all)
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
    this.swarm.dht.removeListener('network-change', this._refreshBound)

    const all = []

    for (const conn of this.swarm.connections) {
      const mux = getMuxer(conn)
      mux.unpair({ protocol: 'blind-pairing' })
      for (const ref of this.active.values()) mux.unpair({ protocol: 'blind-pairing', id: ref.discoveryKey })
    }

    for (const ref of this.active.values()) {
      if (ref.member) all.push(ref.member.close())
      if (ref.candidate) all.push(ref.candidate.close())
      if (ref.discovery) all.push(ref.discovery.destroy())
    }

    await Promise.allSettled(all)
  }

  _randomPoll () {
    return randomInterval(this.poll)
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
      alwaysServer: false,
      alwaysClient: false,
      discovery: null
    }

    this.active.set(id, fresh)
    return fresh
  }

  _swarm (ref) {
    const server = ref.alwaysServer || !!ref.member
    const client = ref.alwaysClient || !!ref.candidate

    if (ref.discovery && ref.discovery.isServer === server && ref.discovery.isClient === client) {
      return
    }

    if (ref.discovery) ref.discovery.destroy().catch(safetyCatch)

    // just a sanity check, not needed but doesnt hurt
    if (!server && !client) return

    ref.discovery = this.swarm.join(ref.discoveryKey, { server, client })
    this._attachToSwarm(ref)
  }

  _attachToSwarm (ref) {
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

    mux.pair({ protocol: 'blind-pairing' }, this._onincoming)

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
        if (ref.candidate) ref.candidate.visited.delete(ch)
      }
    })

    if (ch === null) return

    ch.open()
    mux.pair({ protocol: 'blind-pairing', id: discoveryKey }, () => this._attachToMuxer(mux, discoveryKey, null))
    ref.channels.add(ch)

    if (ref.candidate) ref.candidate.broadcast()
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
  constructor (blind, { announce = true, discoveryKey, onadd = noop } = {}) {
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

    this._activeQuery = null
    this._activePoll = null
    this._closestNodes = null
    this._autoAnnounce = announce

    this.ready()
  }

  announce () {
    if (this.pairing) return this.pairing

    this.blind._swarm(this.ref)
    this.pairing = this._run()
    this.pairing.catch(safetyCatch)

    return this.pairing
  }

  async flushed () {
    if (!this.ref.discovery) return
    return this.ref.discovery.flushed()
  }

  _open () {
    if (this._autoAnnounce) this.announce()
    else this.blind._attachToSwarm(this.ref)
  }

  _suspend () {
    this.timeout.suspend()
    return this._abort()
  }

  async _abort () {
    if (this._activeQuery) this._activeQuery.destroy()
    while (this._activePoll !== null) await this._activePoll
  }

  async refresh () {
    await this._abort()
    this.timeout.resume()
  }

  async _close () {
    this.ref.member = null
    this.blind._gc(this.ref)
    this.timeout.destroy()
    await this._abort()

    try {
      await this.pairing
    } catch {
      // ignore errors since we teardown
    }
  }

  async _run () {
    while (!this.closing) {
      this._activePoll = this._poll()
      await this._activePoll
      this._activePoll = null
      await this.timeout.wait()
    }
  }

  async _poll () {
    const visited = new Set()
    let alwaysClient = false

    if (this._activeQuery) this._activeQuery.destroy()

    const query = this._activeQuery = this.dht.lookup(this.pairingDiscoveryKey, { closestNodes: this._closestNodes })

    try {
      for await (const data of this._activeQuery) {
        if (this.closing || this.blind.suspended) return

        for (const peer of data.peers) {
          const id = b4a.toString(peer.publicKey, 'hex')

          if (visited.has(id) || this.skip.get(id)) continue
          visited.add(id)

          try {
            if (await this._add(peer.publicKey, id)) alwaysClient = true
          } catch (err) {
            safetyCatch(err)
          }

          if (this.closing || this.blind.suspended) return

          if (alwaysClient && !this.ref.alwaysClient) {
            this.ref.alwaysClient = true
            this.blind._swarm(this.ref)
          }
        }
      }
    } catch {
      // do nothing
    } finally {
      const nodes = this._activeQuery.closestNodes
      if (this._activeQuery === query) this._activeQuery = null
      if (nodes && nodes.length > 0) this._closestNodes = nodes
    }

    if (alwaysClient) this._revertClientAfterFlush() // safe to do in bg
  }

  async _revertClientAfterFlush () {
    try {
      await this.blind.swarm.flush()
    } catch {
      return
    }
    if (this.closing || this.blind.suspended) return

    this.ref.alwaysClient = false
    this.blind._swarm(this.ref)
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

    this.signal = null
    this.visited = new Set()
    this.broadcast = debounce(this._broadcast.bind(this))

    this._activePoll = null

    this.ready()
  }

  _open () {
    this.blind._swarm(this.ref)
    this.pairing = this._run()
    this.broadcast()
  }

  _suspend () {
    this.timeout.suspend()
    // no good way to suspend the mut gets atm unfortunately so we just rely on the polls timing out
  }

  async refresh () {
    while (this._activePoll !== null) await this._activePoll
    this.announced = false
    this.timeout.resume()
  }

  async _close () {
    this.ref.candidate = null
    this.blind._gc(this.ref)
    this.timeout.destroy()
    this.visited.clear()
    await this.pairing
    // gc never throws
    if (this.gcing) await this.gcing
  }

  async _addResponse (value, gc) {
    if (this.paired) return

    const paired = this.request.handleResponse(value)
    if (!paired) return

    this.paired = paired
    if (this.signal) this.signal.destroy()

    if ((gc || this.announced) && !this.gcing) this.gcing = this._gc() // gc in the background
    await this.onadd(paired)
    this.timeout.destroy()
  }

  async _run () {
    while (!this._done()) {
      this._activePoll = this._poll()
      await this._activePoll
      this._activePoll = null
      if (this._done()) break
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
    if (this._done()) return

    if (!this.paired) {
      this.ref.alwaysServer = true
      this.blind._swarm(this.ref)
    }

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
    this.visited.add(ch)
  }

  async _broadcast () {
    for (const channel of this.closestPeers()) {
      this.signal = new TimeoutPromise(randomInterval(PEER_INTERVAL))
      if (channel) this._sendRequest(channel)

      await this.signal.wait() // resolves on destroy

      if (this.paired || this.suspended) break
    }
  }

  * closestPeers () {
    while (!this.paired) {
      const closest = Infinity
      let channel = null

      for (const ch of this.ref.channels) {
        if (this.visited.has(ch)) continue

        const { rtt } = ch._mux.stream.rawStream
        if (rtt < closest) channel = ch
      }

      if (!channel) return

      yield channel
    }
  }

  async _poll () {
    try {
      const value = await this._getReply()
      if (this._done() || this.blind.suspended) return

      if (value) {
        await this._addResponse(value, true)
        if (this._done() || this.blind.suspended) return
      }

      if (!this.announced) {
        this.announced = true
        await this._announce()
      }
    } catch {
      // can run in bg, should never crash it
    }
  }

  async _getReply () {
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

function randomInterval (n) {
  return n + (n * 0.5 * Math.random()) | 0
}
