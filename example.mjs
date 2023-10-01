import DHT from 'hyperdht'
import createTestnet from 'hyperdht/testnet.js'
import { Member, Candidate, generateInvite } from './index.js'

// const t = await createTestnet()
const secret = Buffer.alloc(32).fill('the-secret')

const { invite, id } = generateInvite()

console.log(invite, id)

console.log('spin up member')
const a = new Member(new DHT(), {
  id,
  async onadd (memberKey) {
    console.log('add member:', memberKey)
    return secret
  }
})

console.log('spin up candidate')
const b = new Candidate(new DHT(), {
  key: Buffer.alloc(32).fill('i am a member'),
  invite,
  async onadd (secret) {
    console.log('got the secret!')
  }
})

console.time('paired')
const recv = await b.start()
console.timeEnd('paired')

await a.close()
await b.close()

await a.dht.destroy()
await b.dht.destroy()
