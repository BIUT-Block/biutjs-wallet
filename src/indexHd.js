const _SecWallet = require('./index.js')
const HDKey = require('hdkey')

/**
 * Generate BIP32 wallets
 * For the seed we suggest to use BIP39 to create one from a BIP39 mnemonic
 */
class SecHDKey {
  fromHDKey (hdkey) {
    let ret = new SecHDKey()
    ret._hdkey = hdkey
    return ret
  }
  /**
   * -create an instance based on seed
   * @param  {String} seedBuffer
   */
  fromMasterSeed (seedBuffer) {
    let seed = HDKey.fromMasterSeed(seedBuffer)
    return this.fromHDKey(seed)
  }
  /**
   * -create an instance based on a BIP32 extended private or public key
   * @param  {String} base58Key
   */
  fromExtendedKey (base58Key) {
    let base = HDKey.fromExtendedKey(base58Key)
    return this.fromHDKey(base)
  }
  /**
   * -return a BIP32 extended private key (xprv)
   */
  privateExtendedKey () {
    if (!this._hdkey.privateExtendedKey) {
      throw new Error('This is a public key only wallet')
    }
    return this._hdkey.privateExtendedKey
  }
  /**
   * -return a BIP32 extended public key(xpub)
   */
  publicExtendedKey () {
    return this._hdkey.publicExtendedKey
  }
  /**
   * -derive a node based on a path (e.g. m/44'/0'/0/1)
   * @param  {} path
   */
  derivePath (path) {
    let secPath = this._hdkey.derive(path)
    return this.fromHDKey(secPath)
  }
  /**
   * -derive a node based on a child index
   * @param  {} index
   */
  deriveChild (index) {
    let secChild = this._hdkey.deriveChild(index)
    return this.fromHDKey(secChild)
  }
  /**
   * -return a wallet instance as seen above
   */
  getWallet () {
    const SecWallet = new _SecWallet()
    if (this._hdkey._privateKey) {
      return SecWallet.fromPrivateKey(this._hdkey._privateKey)
    } else {
      return SecWallet.fromPublicKey(this._hdkey._publicKey, true)
    }
  }
}
module.exports = SecHDKey
