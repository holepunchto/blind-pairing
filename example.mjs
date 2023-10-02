import DHT from 'hyperdht'
import createTestnet from 'hyperdht/testnet.js'
import { CandidateRequest, createInvite } from 'keet-pairing-core'
import { Member, Candidate } from './index.js'

const t = await createTestnet()
const autobaseKey = Buffer.alloc(32).fill('the-autobase-key')

const { invite, id, publicKey } = createInvite(autobaseKey)

console.log(invite, id)

console.log('spin up member')
const a = new Member(new DHT({ bootstrap: t.bootstrap }), {
  invite: { id, publicKey },
  async onadd (candidate) {
    console.log('add candidate:', candidate)
    candidate.confirm(autobaseKey)
  }
})

const userData = Buffer.alloc(32).fill('i am a candidate')
const request = new CandidateRequest(invite, userData)

const b = new Candidate(new DHT({ bootstrap: t.bootstrap }), request, {
  async onadd (result) {
    console.log('got the result!', result)
  }
})

console.time('paired')
b.start()
await new Promise(resolve => request.on('accepted', resolve))
console.timeEnd('paired')

await a.close()
await b.close()

await a.dht.destroy()
await b.dht.destroy()
