const crypto = require('crypto');
const EC = require('elliptic').ec;
const RIPEMD160 = require('ripemd160');
const bs58 = require('bs58');
const buffer = require('buffer');
const ec = new EC('secp256k1');

/**
 * A small function created as there is a lot of sha256 hashing. 
 */
function hasha256(data) {

    return crypto.createHash('sha256').update(data).digest();

} 



/** 
 * 0x00 P2PKH Mainnet, 0x6f P2PKH Testnet
 * 0x80 Mainnet, 0xEF Testnet （or Test Network: 0x6f and Namecoin Net:0x34）
 */
const addrVer = Buffer.alloc(1, 0x00); 
const wifByte = Buffer.alloc(1, 0x80); 



/**
 * generate private key through sha256 random values. and translate to hex
 */
var key = ec.genKeyPair();
var privKey = key.getPrivate().toString('hex');



/**
 * get usedful private key. It will be used for secp256k1
 */
var bufPrivKey = Buffer.from(privKey, 'hex');
var wifBufPriv = Buffer.concat([wifByte, bufPrivKey], wifByte.length + bufPrivKey.length);


/**
 * generate check code. two times SHA256 at privatKey.
 */
var wifHashFirst = hasha256(wifBufPriv);
var wifHashSecond = hasha256(wifHashFirst);



var wifHashSig = wifHashSecond.slice(0, 4);
var wifBuf = Buffer.concat([wifBufPriv, wifHashSig], wifBufPriv.length + wifHashSig.length);



/**
 * base58(privat key + the version number + check code).
 * it is used as WIF(Wallet import Format) privatKey
 */
var wifFinal = bs58.encode(wifBuf); 



/**
 * set elliptic point and x,y axis
 */
var pubPoint = key.getPublic();
var x = pubPoint.getX(); 
var y = pubPoint.getY(); 



/**
 * use secp256k1. generate public key
 * structe public key: 1(network ID) + 32bytes(from x axis) + 32bytes(from y axis)
 * ripemd160(sha256(public key))
 */
var publicKey = pubPoint.encode('hex');
var publicKeyInitialHash = hasha256(Buffer.from(publicKey, 'hex'));
var publicKeyRIPEHash = new RIPEMD160().update(Buffer.from(publicKeyInitialHash, 'hex')).digest('hex');



var hashBuffer = Buffer.from(publicKeyRIPEHash, 'hex');
var concatHash = Buffer.concat([addrVer, hashBuffer], addrVer.length + hashBuffer.length);



/**
 * double sha256 generate hashExtRipe2. sha256(sha256(version number + hashBuffer)).
 * the first 4 bytes of hashExtRipe2 are used as a checksum and placed at the end of 
 * the 21 byte array. structe secBinary: 1(network ID) + concatHash + 4 byte(checksum)
 */
var hashExtRipe = hasha256(concatHash);
var hashExtRipe2 = hasha256(hashExtRipe);
var hashSig = hashExtRipe2.slice(0, 4);
var secBinaryStr = Buffer.concat([concatHash, hashSig], concatHash.length + hashSig.length);


/**
 * generate WIF private key and translate to hex
 * generate SEC Address and translate to hex
 */
var secWifAddress = wifFinal.toString('hex');
var secAddress = bs58.encode(Buffer.from(secBinaryStr));


console.log("Private Key : %s", privKey.toString('hex'));
console.log("Public Key : %s", publicKey.toString('hex'));
console.log();
console.log("SEC WIF Private Key : %s", secWifAddress.toString('hex'));
console.log("SEC User Address : %s", secAddress.toString('hex'));



