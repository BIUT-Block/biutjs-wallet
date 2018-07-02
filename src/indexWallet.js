var Buffer = require('safe-buffer').Buffer
var ethUtil = require('ethereumjs-util')
var crypto = require('crypto')
var scryptsy = require('scrypt.js')
var uuidv4 = require('uuid/v4')
var bs58check = require('bs58check')
/**
 * Generate a lightweight wallet, At th moment it supports key creation and conversion between various formats
 * It is complemented by the following packages:
 * secjs-tx
 * secjs-icap
 */

class SecWallet {
  /**
   * the constructor of the class, private key and publick key will be as property
   * @param  {String} priv
   * @param  {String} pub
   */
  constructor (priv, pub) {
    if (priv && pub) {
      throw new Error('Cant supply both a private key and a public key to the constructor')
    }

    if (priv && !ethUtil.isValidPrivate(priv)) {
      throw new Error('Private key does not satisfy the curve requirements (ie. it is invalid)')
    }

    if (pub && !ethUtil.isValidPublic(pub)) {
      throw new Error('Invalid public key')
    }
    this._privKey = priv
    this._pubKey = pub
  }
  /**
   * verify error
   * @param  {} val
   * @param  {} msg
   */
  assert (val, msg) {
    if (!val) {
      throw new Error(msg || 'Assertion failed')
    }
  }

  decipherBuffer (decipher, data) {
    return Buffer.concat([decipher.update(data), decipher.final()])
  }
  /**
   * get private key and return this._privKey
   */
  get privKey () {
    this.assert(this._privKey, 'This is a public key only wallet')
    return this._privKey
  }
  /**
   * get publickey through util function and return this._pubKey
   */
  get pubKey () {
    if (!this._pubKey) {
      this._pubKey = ethUtil.privateToPublic(this.privKey)
    }
    return this._pubKey
  }
  /**
   * @param  {Buffer} icapGenerate
   * -create an instance based on a new random key,
   *  setting icap to true will generate an address suitable
   * for the ICAP Direct mode.
   */
  generate (icapGenerate) {
    if (icapGenerate) {
      let max = new ethUtil.BN('088f924eeceeda7fe92e1f5b0fffffffffffffff', 16)
      while (true) {
        let privKey = crypto.randomBytes(32)
        if (new ethUtil.BN(ethUtil.privateToAddress(privKey)).lte(max)) {
          return new SecWallet(privKey)
        }
      }
    } else {
      return new SecWallet(crypto.randomBytes(32))
    }
  }
  /**
   * -create an instance where the address is valid against the supplied pattern
   * (this will be very slow)
   * @param  {String} pattern
   */
  generateVantiyaAddress (pattern) {
    if (typeof pattern !== 'object') {
      pattern = new RegExp(pattern)
    }

    while (true) {
      let privKey = crypto.randomBytes(32)
      let address = ethUtil.privateToAddress(privKey)

      if (pattern.test(address.toString('hex'))) {
        return new SecWallet(privKey)
      }
    }
  }
  /**
   * -return the private key
   */
  getPrivateKey () {
    return this.privKey
  }
  /**
   * -return the private key to string mode
   */
  getPrivateKeyString () {
    return ethUtil.bufferToHex(this.getPrivateKey())
  }
  /**
   * -return the public key
   */
  getPublicKey () {
    return this.pubKey
  }
  /**
   * -return the public key to string mode
   */
  getPublicKeyString () {
    return ethUtil.bufferToHex(this.getPublicKey())
  }
  /**
   * -return the address
   */
  getAddress () {
    return ethUtil.publicToAddress(this.pubKey)
  }
  /**
   * return the address to the string mode
   */
  getAddressString () {
    return ethUtil.bufferToHex(this.getAddress())
  }
  /**
   * -return the address with checksum
   */
  getAddressChecksumString () {
    return ethUtil.toChecksumAddress(this.getAddressString())
  }
  /**
   * -create an instance based on a raw private key
   * you can generate the raw pribate key by secjs-util
   * @param  {String} priv
   */
  fromPrivateKey (priv) {
    return new SecWallet(priv)
  }
  /**
   * -create an instance based on a BIP32 extended private key(xprv)
   * @param  {String} priv
   */
  fromExtendedPrivateKey (priv) {
    this.assert(priv.slice(0, 4) === 'xprv', 'Not an extended private key')
    let tmp = bs58check.decode(priv)
    this.assert(tmp[45] === 0, 'Invalid extended private key')
    return this.fromPrivateKey(tmp.slice(46))
  }
  /**
   * -create an instance based on a public key
   * @param  {String} pub
   * @param  {Buffer} nonStrict
   */
  fromPublicKey (pub, nonStrict) {
    if (nonStrict) {
      pub = ethUtil.importPublic(pub)
    }
    return new SecWallet(null, pub)
  }
  /**
   * -create an instance based on a BIP32 extended public key(xpub)
   * @param  {String} pub
   */
  fromExtendedPublicKey (pub) {
    this.assert(pub.slice(0, 4) === 'xpub', 'Not an extended public key')
    pub = bs58check.decode(pub).slice(45)
    return this.fromPublicKey(pub, true)
  }
}
module.exports = SecWallet
