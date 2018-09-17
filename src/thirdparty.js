const SecWallet = require('./indexWallet.js')
const crypto = require('crypto')
const scryptsy = require('scrypt.js')
const utf8 = require('utf8')
const aesjs = require('aes-js')
const Buffer = require('safe-buffer').Buffer
const Util = require('@sec-block/secjs-util')

let secUtil = new Util()

class thirdParty {
  assert (val, msg) {
    if (!val) {
      throw new Error(msg || 'Assertion failed')
    }
  }

  decipherBuffer (decipher, data) {
    return Buffer.concat([ decipher.update(data), decipher.final() ])
  }

  evp_kdf (data, salt, opts) {
    let iter = (block) => {
      let hash = crypto.createHash(opts.digest || 'md5')
      hash.update(block)
      hash.update(data)
      hash.update(salt)
      block = hash.digest()

      for (let i = 1; i < (opts.count || 1); i++) {
        hash = crypto.createHash(opts.digest || 'md5')
        hash.update(block)
        block = hash.digest()
      }

      return block
    }
    let keysize = opts.keysize || 16
    let ivsize = opts.ivsize || 16

    let ret = []

    let i = 0
    while (Buffer.concat(ret).length < (keysize + ivsize)) {
      ret[i] = iter((i === 0) ? Buffer.alloc(0) : ret[i - 1])
      i++
    }

    let tmp = Buffer.concat(ret)

    return {
      key: tmp.slice(0, keysize),
      iv: tmp.slice(keysize, keysize + ivsize)
    }
  }

  decodeCryptojsSalt (input) {
    let ciphertext = Buffer.from(input, 'base64')
    if (ciphertext.slice(0, 8).toString() === 'Salted__') {
      return {
        salt: ciphertext.slice(8, 16),
        ciphertext: ciphertext.slice(16)
      }
    } else {
      return {
        ciphertext: ciphertext
      }
    }
  }

  fromSecWallet (input, password) {
    let json = (typeof input === 'object') ? input : JSON.parse(input)

    let privKey
    if (!json.locked) {
      if (json.private.length !== 64) {
        throw new Error('Invalid private key length')
      }

      privKey = Buffer.from(json.private, 'hex')
    } else {
      if (typeof password !== 'string') {
        throw new Error('Password required')
      }
      if (password.length < 7) {
        throw new Error('Password must be at least 7 characters')
      }

      let cipher = json.encrypted ? json.private.slice(0, 128) : json.private

      // decode openssl ciphertext + salt encoding
      cipher = this.decodeCryptojsSalt(cipher)

      if (!cipher.salt) {
        throw new Error('Unsupported EtherWallet key format')
      }

      // derive key/iv using OpenSSL EVP as implemented in CryptoJS
      let evp = this.evp_kdf(Buffer.from(password), cipher.salt, { keysize: 32, ivsize: 16 })

      let decipher = crypto.createDecipheriv('aes-256-cbc', evp.key, evp.iv)
      privKey = this.decipherBuffer(decipher, Buffer.from(cipher.ciphertext))

      // NOTE: yes, they've run it through UTF8
      privKey = Buffer.from(utf8.decode(privKey.toString()), 'hex')
    }

    const wallet = new SecWallet(privKey)
    if (wallet.getAddressString() !== json.address) {
      throw new Error('Invalid private key or address')
    }

    return wallet
  }

  fromSecCamp (passphrase) {
    return new SecWallet(secUtil.sha3(Buffer.from(passphrase)))
  }

  fromKryptoKit (entropy, password) {
    let kryptoKitBrokenScryptSeed = (buf) => {
      let decodeUtf8Char = (str) => {
        try {
          return decodeURIComponent(str)
        } catch (err) {
          return String.fromCharCode(0xFFFD) // UTF 8 invalid char
        }
      }

      let res = ''
      let tmp = ''

      for (let i = 0; i < buf.length; i++) {
        if (buf[i] <= 0x7F) {
          res += decodeUtf8Char(tmp) + String.fromCharCode(buf[i])
          tmp = ''
        } else {
          tmp += '%' + buf[i].toString(16)
        }
      }

      return Buffer.from(res + decodeUtf8Char(tmp))
    }

    if (entropy[0] === '#') {
      entropy = entropy.slice(1)
    }

    let type = entropy[0]
    entropy = entropy.slice(1)

    let privKey
    if (type === 'd') {
      privKey = secUtil.sha256(entropy)
    } else if (type === 'q') {
      if (typeof password !== 'string') {
        throw new Error('Password required')
      }

      let encryptedSeed = secUtil.sha256(Buffer.from(entropy.slice(0, 30)))
      let checksum = entropy.slice(30, 46)

      let salt = kryptoKitBrokenScryptSeed(encryptedSeed)
      let aesKey = scryptsy(Buffer.from(password, 'utf8'), salt, 16384, 8, 1, 32)

      /* FIXME: try to use `crypto` instead of `aesjs`
      // NOTE: ECB doesn't use the IV, so it can be anything
      let decipher = crypto.createDecipheriv("aes-256-ecb", aesKey, Buffer.from(0))
      // FIXME: this is a clear abuse, but seems to match how ECB in aesjs works
      privKey = Buffer.concat([
        decipher.update(encryptedSeed).slice(0, 16),
        decipher.update(encryptedSeed).slice(0, 16),
      ])
      */

      /* eslint-disable new-cap */
      let decipher = new aesjs.ModeOfOperation.ecb(aesKey)
      /* eslint-enable new-cap */
      /* decrypt returns an Uint8Array, perhaps there is a better way to concatenate */
      privKey = Buffer.concat([
        Buffer.from(decipher.decrypt(encryptedSeed.slice(0, 16))),
        Buffer.from(decipher.decrypt(encryptedSeed.slice(16, 32)))
      ])

      if (checksum.length > 0) {
        if (checksum !== secUtil.sha256(secUtil.sha256(privKey)).slice(0, 8).toString('hex')) {
          throw new Error('Failed to decrypt input - possibly invalid passphrase')
        }
      }
    } else {
      throw new Error('Unsupported or invalid entropy type')
    }
    return new SecWallet(privKey)
  }

  fromQuorumWallet (passphrase, userid) {
    this.assert(passphrase.length >= 10)
    this.assert(userid.length >= 10)

    let seed = passphrase + userid
    seed = crypto.pbkdf2Sync(seed, seed, 2000, 32, 'sha256')

    return new SecWallet(seed)
  }
}
module.exports = thirdParty
