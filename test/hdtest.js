const HDKey = require('../src/indexHd')
const Buffer = require('safe-buffer').Buffer

const SecHDKey = new HDKey()
let fixtureseed = Buffer.from('747f302d9c916698912d5f70be53a6cf53bc495803a5523d3a7c3afa2afba94ec3803f838b3e1929ab5481f9da35441372283690fdcf27372c38f40ba134fe03', 'hex')
let SecHd = SecHDKey.fromMasterSeed(fixtureseed)

let masterSeed = SecHDKey.fromMasterSeed(fixtureseed)
console.log(masterSeed)
console.log('*******************************************************************************************************')

let privExtendedKey = SecHd.privateExtendedKey()
console.log(privExtendedKey)
console.log('*******************************************************************************************************')

let pubExtendedKey = SecHd.publicExtendedKey()
console.log(pubExtendedKey)
console.log('*******************************************************************************************************')

let hdPubNode = SecHDKey.fromExtendedKey(pubExtendedKey)
console.log(hdPubNode)
console.log('*******************************************************************************************************')

let pubNodeExtendedKey = hdPubNode.publicExtendedKey()
console.log(pubNodeExtendedKey)

let hdPrivNode = SecHDKey.fromExtendedKey(privExtendedKey)
console.log(hdPrivNode)
console.log('*******************************************************************************************************')

let pubNodeExtendedKeyTwo = hdPrivNode.publicExtendedKey()
let privNodeExtendedKey = hdPrivNode.privateExtendedKey()
console.log(pubNodeExtendedKeyTwo)
console.log(privNodeExtendedKey)
console.log('*******************************************************************************************************')

let hdChild = SecHd.deriveChild(1)
let childTest = hdChild.privateExtendedKey()
console.log(childTest)
console.log('*******************************************************************************************************')

let hdPath = SecHd.derivePath('m')
let pathTest = hdPath.privateExtendedKey()
console.log(pathTest)

let hdPathTwo = SecHd.derivePath('m/44\'/0\'/0/1')
let pathTestTwo = hdPathTwo.privateExtendedKey()
console.log(pathTestTwo)
console.log('*******************************************************************************************************')

let walletPriv = SecHd.getWallet().getPrivateKeyString()
let walletPub = SecHd.getWallet().getPublicKeyString()
console.log(walletPriv)
console.log(walletPub)

let walletPubTwo = hdPubNode.getWallet().getPublicKeyString()
console.log(walletPubTwo)
