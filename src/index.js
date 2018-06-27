var Buffer = require('safe-buffer').Buffer
var ethUtil = require('ethereumjs-util')
var crypto = require('crypto')
var scryptsy = require('scrypt.js')
var uuidv4 = require('uuid/v4')
var bs58check = require('bs58check')

class SecWallet {
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

  assert (val, msg) {
    if (!val) {
      throw new Error(msg || 'Assertion failed')
    }
  }

  decipherBuffer (decipher, data) {
    return Buffer.concat([decipher.update(data), decipher.final()])
  }

  get privKey () {
    this.assert(this._privKey, 'This is a public key only wallet')
    return this._privKey
  }
  get pubKey () {
    if (!this._pubKey) {
      this._pubKey = ethUtil.privateToPublic(this.privKey)
    }
    return this._pubKey
  }

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

  getPrivateKey () {
    return this.privKey
  }

  getPrivateKeyString () {
    return ethUtil.bufferToHex(this.getPrivateKey())
  }
  getPublicKey () {
    return this.pubKey
  }

  getPublicKeyString () {
    return ethUtil.bufferToHex(this.getPublicKey())
  }

  getAddress () {
    return ethUtil.publicToAddress(this.pubKey)
  }

  getAddressString () {
    return ethUtil.bufferToHex(this.getAddress())
  }

  getAddressChecksumString () {
    return ethUtil.toChecksumAddress(this.getAddressString())
  }

  fromPrivateKey (priv) {
    return new SecWallet(priv)
  }

  fromExtendedPrivateKey (priv) {
    this.assert(priv.slice(0, 4) === 'sprv', 'Not an extended private key')
    let tmp = bs58check.decode(priv)
    this.assert(tmp[45] === 0, 'Invalid extended private key')
    return this.fromPrivateKey(tmp.slice(46))
  }

  fromPublicKey (pub, nonStrict) {
    if (nonStrict) {
      pub = ethUtil.importPublic(pub)
    }
    return new SecWallet(null, pub)
  }

  fromExtendedPublicKey (pub) {
    this.assert(pub.slice(0, 4) === 'spub', 'Not an extended public key')
    pub = bs58check.decode(pub).slice(45)
    return this.fromPublicKey(pub, true)
  }
}
module.exports = SecWallet
