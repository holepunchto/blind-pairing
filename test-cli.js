const Hyperswarm = require('hyperswarm')
const BlindPairing = require('@holepunchto/blind-pairing')
const z32 = require('z32')
const os = require('os')

if (process.argv[2] !== 'member' && process.argv[2] !== 'candidate') {
  console.error('Usage: node cli.js member|candidate invite?')
  process.exit(1)
}

const swarm = new Hyperswarm()
const pairer = new BlindPairing(swarm)
const invite = process.argv[3] && z32.decode(process.argv[3])

if (process.argv[2] === 'member') onmember()
else if (process.argv[2] === 'candidate') oncandidate()

async function onmember () {
  const key = Buffer.alloc(32).fill('key-from-' + os.hostname())
  const inv = invite
    ? BlindPairing.createInvite(key, BlindPairing.decodeInvite(invite))
    : BlindPairing.createInvite(key)

  console.log('share this invite:', z32.encode(invite || inv.invite))

  pairer.addMember({
    discoveryKey: inv.discoveryKey,
    onadd (request) {
      console.log('inviteId:', request.inviteId)
      request.open(inv.publicKey)
      console.log('should add candidate:', request.userData.toString())
      console.log('confirming with key')
      request.confirm({ key })
    }
  })
}

async function oncandidate () {
  const c = pairer.addCandidate({
    invite,
    userData: Buffer.alloc(32).fill('i-am-a-candidate'),
    onadd ({ key }) {
      console.log('pairing completed!', key.toString())
    }
  })

  c.on('announce', function () {
    console.log('fully announced to the dht also...')
  })
}

process.once('SIGINT', function () {
  console.log('closing...')
  Promise.all([swarm.destroy(), pairer.close()]).then(() => {
    console.log('closed!')
  })
})
