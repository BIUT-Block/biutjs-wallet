const SecWallet = require('../src/index')

let fixturekey = Buffer.from('efca4cdd31923b50f4214af5d2ae10e7ac45a5019e9431cc195482d707485378', 'hex')
const Wallet = new SecWallet(fixturekey)
// Wallet.init(fixturekey)
// let Wallet = Wallet.fromPrivateKey(fixturekey)

console.log(Wallet)

let privateKey = Wallet.getPrivateKey().toString('hex')
let privateKeyString = Wallet.getPrivateKeyString()

console.log(`Private Key: ${privateKey} Length: ${privateKey.length}`)
console.log(`Private Key to String: ${privateKeyString} Length: ${privateKeyString.length}`)
console.log('*********************************************************************')

let publicKey = Wallet.getPublicKey().toString('hex')
let publicKeyString = Wallet.getPublicKeyString()

console.log(`Public Key: ${publicKey} Length: ${publicKey.length}`)
console.log(`Public Key to String: ${publicKeyString} Length: ${publicKeyString.length}`)
console.log('*********************************************************************')

let address = Wallet.getAddress().toString('hex')
let addressString = Wallet.getAddressString()
let addressChecksum = Wallet.getAddressChecksumString()

console.log(`Address: ${address} Length: ${address.length}`)
console.log(`Address to String: ${addressString} Length: ${addressString.length}`)
console.log(`Checksum Address: ${addressChecksum} Length: ${addressChecksum.length}`)
console.log('*********************************************************************')
