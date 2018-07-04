var _SecWallet = require('./indexWallet.js')
var ethUtil = require('ethereumjs-util')
var crypto = require('crypto')
var scryptsy = require('scrypt.js')
var utf8 = require('utf8')
var aesjs = require('aes-js')
var Buffer = require('safe-buffer').Buffer

class thirdParty {
  assert (val, msg) {
    if (!val) {
      throw new Error(msg || 'Assertion failed')
    }
  }

  decipherBuffer (decipher, data) {
    return Buffer.concat([decipher.updata(data), decipher.final()])
  }
}
module.exports = thirdParty
