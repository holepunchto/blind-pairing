# blind-pairing

Blind pairing over HyperDHT

```
npm install @holepunchto/blind-pairing
```

## Usage

``` js
const { Member, Candidate, generateInvite } = require('@holepunchto/blind-pairing')

const { invite, id } = generateInvite()

const m = new Member(dht, {
  id,
  async onadd (key) {
    return secret
  }
})

const c = new Candidate(dht, {
  invite,
  async onadd (secret) {
    console.log('we were told we were added')
  }
})

c.start()
```

## License

MIT
