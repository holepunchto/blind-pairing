import DHT from 'hyperdht'
import createTestnet from 'hyperdht/testnet.js'
import { Member, Candidate, generateInvite } from './index.js'

// const t = await createTestnet()
const autobaseKey = Buffer.alloc(32).fill('the-autobase-key')

const { invite, id } = generateInvite()

console.log(invite, id)

console.log('spin up member')
const a = new Member(new DHT(), {
  id,
  async onadd (candiate) {
    console.log('add candidate:', candiate)
    return { key: autobaseKey, encryptionKey: null }
  }
})

console.log('spin up candidate')
const b = new Candidate(new DHT(), {
  key: Buffer.alloc(32).fill('i am a candidate'),
  invite,
  async onadd (result) {
    console.log('got the result!', result)
  }
})

console.time('paired')
const recv = await b.start()
console.timeEnd('paired')

await a.close()
await b.close()

await a.dht.destroy()
await b.dht.destroy()
