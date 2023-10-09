const Hyperswarm = require('hyperswarm')
const BlindPairing = require('@holepunchto/blind-pairing')
const z32 = require('z32')
const minimist = require('minimist')
const args = minimist(process.argv.slice(2), { alias: { invite: 'i', key: 'k', 'user-data': 'u' } })
const cmd = args._[0]

if (cmd !== 'member' && cmd !== 'candidate') {
  console.error('Usage: node cli.js member|candidate [--invite=invite, --key=key, --user-data=user-data]')
  process.exit(1)
}

const swarm = new Hyperswarm()
const pairer = new BlindPairing(swarm)
const invite = args.invite && z32.decode(args.invite)

if (cmd === 'member') onmember()
else if (cmd === 'candidate') oncandidate()

async function onmember () {
  const key = Buffer.alloc(32).fill(args.key || 'key')
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
    userData: Buffer.alloc(32).fill(args['user-data'] || 'user-data'),
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
