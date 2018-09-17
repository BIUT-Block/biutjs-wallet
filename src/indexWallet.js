const Buffer = require('safe-buffer').Buffer
const crypto = require('crypto')
const scryptsy = require('scrypt.js')
const uuidv4 = require('uuid/v4')
const bs58check = require('bs58check')
const Util = require('@sec-block/secjs-util')

let secUtil = new Util()
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

    if (priv && !secUtil.isValidPrivate(priv)) {
      throw new Error('Private key does not satisfy the curve requirements (ie. it is invalid)')
    }

    if (pub && !secUtil.isValidPublic(pub)) {
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
      this._pubKey = secUtil.privateToPublic(this.privKey)
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
      let max = new secUtil.BN('088f924eeceeda7fe92e1f5b0fffffffffffffff', 16)
      while (true) {
        let privKey = crypto.randomBytes(32)
        if (new secUtil.BN(secUtil.privateToAddress(privKey)).lte(max)) {
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
  generateVanityAddress (pattern) {
    if (typeof pattern !== 'object') {
      pattern = new RegExp(pattern)
    }

    while (true) {
      let privKey = crypto.randomBytes(32)
      let address = secUtil.privateToAddress(privKey)

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
    return secUtil.bufferToHex(this.getPrivateKey())
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
    return secUtil.bufferToHex(this.getPublicKey())
  }
  /**
   * -return the address
   */
  getAddress () {
    return secUtil.publicToAddress(this.pubKey)
  }
  /**
   * return the address to the string mode
   */
  getAddressString () {
    return secUtil.bufferToHex(this.getAddress())
  }
  /**
   * -return the address with checksum
   */
  getAddressChecksumString () {
    return secUtil.toChecksumAddress(this.getAddressString())
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
      pub = secUtil.importPublic(pub)
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

  toV3 (password, opts) {
    this.assert(this._privKey, 'This is a public key only wallet')

    opts = opts || {}
    let salt = opts.salt || crypto.randomBytes(32)
    let iv = opts.iv || crypto.randomBytes(16)

    let derivedKey
    let kdf = opts.kdf || 'scrypt'
    let kdfparams = {
      dklen: opts.dklen || 32,
      salt: salt.toString('hex')
    }

    if (kdf === 'pbkdf2') {
      kdfparams.c = opts.c || 262144
      kdfparams.prf = 'hmac-sha256'
      derivedKey = crypto.pbkdf2Sync(Buffer.from(password), salt, kdfparams.c, kdfparams.dklen, 'sha256')
    } else if (kdf === 'scrypt') {
      /**
       *  FIXME: support progress reporting callback
       */
      kdfparams.n = opts.n || 262144
      kdfparams.r = opts.r || 8
      kdfparams.p = opts.p || 1
      derivedKey = scryptsy(Buffer.from(password), salt, kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen)
    } else {
      throw new Error('Unsupported kdf')
    }

    let cipher = crypto.createCipheriv(opts.cipher || 'aes-128-ctr', derivedKey.slice(0, 16), iv)
    if (!cipher) {
      throw new Error('Unsupported cipher')
    }

    let ciphertext = Buffer.concat([cipher.update(this.privKey), cipher.final()])
    let mac = secUtil.sha3(Buffer.concat([derivedKey.slice(16, 32), Buffer.from(ciphertext, 'hex')]))

    return {
      version: 3,
      id: uuidv4({ random: opts.uuid || crypto.randomBytes(16) }),
      address: this.getAddress().toString('hex'),
      crypto: {
        ciphertext: ciphertext.toString('hex'),
        cipherparams: {
          iv: iv.toString('hex')
        },
        cipher: opts.cipher || 'aes-128-ctr',
        kdf: kdf,
        kdfparams: kdfparams,
        mac: mac.toString('hex')
      }
    }
  }

  toV3String (password, opts) {
    return JSON.stringify(this.toV3(password, opts))
  }

  /*
   * We want a timestamp like 2016-03-15T17-11-33.007598288Z. Date formatting
   * is a pain in Javascript, everbody knows that. We could use moment.js,
   * but decide to do it manually in order to save space.
   *
   * toJSON() returns a pretty close version, so let's use it. It is not UTC though,
   * but does it really matter?
   */
  getV3Filename (timestamp) {
    let ts = timestamp ? new Date(timestamp) : new Date()
    return [
      'UTC--',
      ts.toJSON().replace(/:/g, '-'),
      '--',
      this.getAddress().toString('hex')
    ].join('')
  }

  fromV1 (input, password) {
    this.assert(typeof password === 'string')
    let json = (typeof input === 'object') ? input : JSON.parse(input)

    if (json.Version !== '1') {
      throw new Error('Not a V1 wallet')
    }

    if (json.Crypto.KeyHeader.Kdf !== 'scrypt') {
      throw new Error('Unsupported key derivation scheme')
    }

    let kdfparams = json.Crypto.KeyHeader.KdfParams
    let derivedKey = scryptsy(Buffer.from(password), Buffer.from(json.Crypto.Salt, 'hex'), kdfparams.N, kdfparams.R, kdfparams.P, kdfparams.DkLen)

    let ciphertext = Buffer.from(json.Crypto.CipherText, 'hex')

    let mac = secUtil.sha3(Buffer.concat([derivedKey.slice(16, 32), ciphertext]))

    if (mac.toString('hex') !== json.Crypto.MAC) {
      throw new Error('Key derivation failed - possibly wrong passphrase')
    }

    let decipher = crypto.createDecipheriv('aes-128-cbc', secUtil.sha3(derivedKey.slice(0, 16)).slice(0, 16), Buffer.from(json.Crypto.IV, 'hex'))
    let seed = this.decipherBuffer(decipher, ciphertext)

    return new SecWallet(seed)
  }

  fromV3 (input, password, nonStrict) {
    this.assert(typeof password === 'string')
    let json = (typeof input === 'object') ? input : JSON.parse(nonStrict ? input.toLowerCase() : input)

    if (json.version !== 3) {
      throw new Error('Not a V3 wallet')
    }
    let derivedKey
    let kdfparams

    if (json.crypto.kdf === 'scrypt') {
      kdfparams = json.crypto.kdfparams

      /**
       * FIXME: support progress reporting callback
       */
      derivedKey = scryptsy(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen)
    } else if (json.crypto.kdf === 'pbkdf2') {
      kdfparams = json.crypto.kdfparams

      if (kdfparams.prf !== 'hmac-sha256') {
        throw new Error('Unsupported parameters to PBKDF2')
      }

      derivedKey = crypto.pbkdf2Sync(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256')
    } else {
      throw new Error('Unsupported key derivation scheme')
    }

    let ciphertext = Buffer.from(json.crypto.ciphertext, 'hex')

    let mac = secUtil.sha3(Buffer.concat([derivedKey.slice(16, 32), ciphertext]))
    if (mac.toString('hex') !== json.crypto.mac) {
      throw new Error('Key derivation failed - possibly wrong passphrase')
    }

    let decipher = crypto.createDecipheriv(json.crypto.cipher, derivedKey.slice(0, 16), Buffer.from(json.crypto.cipherparams.iv, 'hex'))
    let seed = this.decipherBuffer(decipher, ciphertext, 'hex')

    return new SecWallet(seed)
  }

  fromSecSale (input, password) {
    this.assert(typeof password === 'string')
    let json = (typeof input === 'object') ? input : JSON.parse(input)

    let encseed = Buffer.from(json.encseed, 'hex')

    let derivedKey = crypto.pbkdf2Sync(password, password, 2000, 32, 'sha256').slice(0, 16)

    let decipher = crypto.createDecipheriv('aes-128-cbc', derivedKey, encseed.slice(0, 16))
    let seed = this.decipherBuffer(decipher, encseed.slice(16))

    let wallet = new SecWallet(secUtil.sha3(seed))
    if (wallet.getAddress().toString('hex') !== json.ethaddr) {
      throw new Error('Decoded key mismatch - possibly wrong passphrase')
    }
    return wallet
  }
}

module.exports = SecWallet
