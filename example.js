const SecWallet = require('./sec_wallet_lib')
let TestWallet = new SecWallet()

console.log(`PrivateKey: ${TestWallet.getPrivateKey()}`)
console.log(`secWifFinal: ${TestWallet.getsecWifFinal()}`)
console.log(`PublicKey: ${TestWallet.getPublicKey()}`)
console.log(`Address: ${TestWallet.getAddress()}`)

for (let i = 0; i < 10; i++) {
  console.log(`\n\n########################## Time: ${i} ##########################\n`)
  let TestWallet = new SecWallet()
  console.log(`PrivateKey: ${TestWallet.getPrivateKey()} Length: ${TestWallet.getPrivateKey().length}`)
  console.log(`secWifFinal: ${TestWallet.getsecWifFinal()} Length: ${TestWallet.getsecWifFinal().length}`)
  console.log(`PublicKey: ${TestWallet.getPublicKey()} Length: ${TestWallet.getPublicKey().length}`)
  console.log(`Address: ${TestWallet.getAddress()} Length: ${TestWallet.getAddress().length}`)
}
