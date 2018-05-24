var crypto = require("crypto");
var eccrypto = require("eccrypto");

/**
 * using EC crypto generate privat key and public key
 * testing sign and verify
 */


/**
 * A new random 32-byte private key.
 */
var privateKey = crypto.randomBytes(32);

/**
 * Corresponding uncompressed (65-byte) public key.
 */

var publicKey = eccrypto.getPublic(privateKey);

 
var str = "message to sign";
/** 
 *Always hash you message to sign!
 */
var msg = crypto.createHash("sha256").update(str).digest();



/**
 * testing sign and verify
 */ 
eccrypto.sign(privateKey, msg).then(function(sig) {

	console.log("Signature in DER format:", sig);

  	eccrypto.verify(publicKey, msg, sig).then(function() {

    console.log("Signature is OK");

  	}).catch(function() {

    console.log("Signature is BAD");

  	});
});




 /**
  * testiing encrypto and decrypto
  */


var cryptoMsg = "hello world";
 
/**
 * Encrypting the message with public key for user.
 */
eccrypto.encrypt(publicKey, Buffer(cryptoMsg)).then(function(encrypted) {

	console.log("#####################################################################################################");
	console.log("cipher to part user:", encrypted);

  	/**
  	 * user decrypting the message with privat key.
  	 */
  	eccrypto.decrypt(privateKey, encrypted).then(function(plaintext) {
 		console.log("Message to part user:", plaintext.toString());
  });
});


 
