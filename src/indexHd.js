const SecWallet = require('./index')
const HDKey = require('hdkey')

class SecHDKey {
  fromHDKey (hdkey) {
    let ret = new SecHDKey()
    ret._hdkey = hdkey
    return ret
  }

  fromMasterSeed (seedBuffer) {
    let seed = HDKey.fromMasterSeed(seedBuffer)
    return this.fromHDKey(seed)
  }

  fromExtendedKey (base58Key) {
    let base = HDKey.fromExtendedKey(base58Key)
    return this.fromHDKey(base)
  }

  privateExtendedKey () {
    if (!this._hdkey.privateExtendedKey) {
      throw new Error('This is a public key only wallet')
    }
    return this._hdkey.privateExtendedKey
  }

  publicExtendedKey () {
    return this._hdkey.publicExtendedKey
  }

  derivePath (path) {
    let secPath = this._hdkey.derive(path)
    return this.fromHDKey(secPath)
  }

  deriveChild (index) {
    let secChild = this._hdkey.deriveChild(index)
    return this.fromHDKey(secChild)
  }

  getWallet () {
    if (this._hdkey._privateKey) {
      return SecWallet.fromPrivateKey(this._hdkey._privateKey)
    } else {
      return SecWallet.fromPublicKey(this._hdkey._publicKey, true)
    }
  }
}
module.exports = SecHDKey
