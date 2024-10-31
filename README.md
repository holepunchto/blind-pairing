# blind-pairing

Blind pairing over HyperDHT

```
npm install blind-pairing
```

## Usage

``` js
import createTestnet from 'hyperdht/testnet.js'
import Hyperswarm from 'hyperswarm'
import BlindPairing from './index.js'

const t = await createTestnet()
const autobaseKey = Buffer.alloc(32).fill('the-autobase-key')

const { invite, publicKey, discoveryKey } = BlindPairing.createInvite(autobaseKey)

const a = new BlindPairing(new Hyperswarm({ bootstrap: t.bootstrap }), { poll: 5000 })

const m = a.addMember({
  discoveryKey,
  async onadd (candidate) {
    console.log('candiate id is', candidate.inviteId)
    candidate.open(publicKey)
    console.log('add candidate:', candidate.userData)
    candidate.confirm({ key: autobaseKey })
  }
})

await m.flushed()

const userData = Buffer.alloc(32).fill('i am a candidate')

const b = new BlindPairing(new Hyperswarm({ bootstrap: t.bootstrap }), {
  poll: 5000
})

const c = b.addCandidate({
  invite,
  userData,
  async onadd (result) {
    console.log('got the result!', result)
  }
})

console.time('paired')
await c.pairing
console.timeEnd('paired')
console.log('paired:', c.paired)

await a.close()
await b.close()

console.log('closed')

await a.swarm.destroy()
await b.swarm.destroy()

console.log('fully closed')

await t.destroy()
```

## License

Apache-2.0
