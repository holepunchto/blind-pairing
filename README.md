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

// Create an invite to share
const { invite, publicKey, discoveryKey } = BlindPairing.createInvite(autobaseKey)

const a = new BlindPairing(new Hyperswarm({ bootstrap: t.bootstrap }), { poll: 5000 })

// Prepare to receive candidates with invites
const m = a.addMember({
  discoveryKey,
  async onadd (candidate) {
    console.log('candiate id is', candidate.inviteId)
    candidate.open(publicKey)
    console.log('add candidate:', candidate.userData)

    // Confirm the candidate is good
    candidate.confirm({ key: autobaseKey })
  }
})

await m.flushed()

// Candidate (aka using the invite)
const userData = Buffer.alloc(32).fill('i am a candidate')

const b = new BlindPairing(new Hyperswarm({ bootstrap: t.bootstrap }), {
  poll: 5000
})

const c = b.addCandidate({
  invite,
  userData,
  async onadd (result) {
    // Our invite has been processed
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

### Usage with Additional Nodes provided

Invites may contain additional nodes for you to use. These are known Peers allowing you to connect without DHT connectivity being required.

```js
import DHT from 'dht-rpc'
import { decodeInvite } from 'blind-pairing-core'

// Candidate (aka using the invite) - sets up like normal
const userData = Buffer.alloc(32).fill('i am a candidate')

// Initialize DHT
const dht = new DHT()

// Get the additional nodes from the invite
const { additionalNodes } = decodeInvite(invite)

// Add the additional nodes to the DHT
if(additionalNodes){
  additionalNodes.forEach(node => {
    dht.addNode(node)
  })
}

// In this is example we're passing DHT in
const b = new BlindPairing(new Hyperswarm({ dht }), {
  poll: 5000
})

// continue as normal
```

## License

Apache-2.0
