"strict mode"
const crypto = require('crypto');
const EC = require('elliptic').ec;
const RIPEMD160 = require('ripemd160');
const bs58 = require('bs58');
const buffer = require('buffer');
const ec = new EC('secp256k1');

class secWallet{

	constructor(){
		this.privKey="";
		this.publicKey="";
		this.secWifAddress="";
		this.secAddress="";
		this.generatePrivateKey();
	}

	/**
	 * A small function created as there is a lot of sha256 hashing. 
 	 */
	hasha256(data) {
	    return crypto.createHash('sha256').update(data).digest();
	} 

    generatePrivateKey() {
	   	/** 
	     * 0x00 P2PKH Mainnet, 0x6f P2PKH Testnet
	     * 0x80 Mainnet, 0xEF Testnet （or Test Network: 0x6f and Namecoin Net:0x34）
	     */
	    let addrVer = Buffer.alloc(1, 0x00); 
	    let wifByte = Buffer.alloc(1, 0x80); 

	    /**
	     * generate private key through sha256 random values. and translate to hex
	     */
	    let key = ec.genKeyPair();
	    this.privKey = key.getPrivate().toString('hex');

	    /**
	     * get usedful private key. It will be used for secp256k1
	     */
	    let bufPrivKey = Buffer.from(this.privKey, 'hex');
	    let wifBufPriv = Buffer.concat([wifByte, bufPrivKey], wifByte.length + bufPrivKey.length);
	    
	    /**
	     * generate check code. two times SHA256 at privatKey.
	     */
	    let wifHashFirst = this.hasha256(wifBufPriv);
	    let wifHashSecond = this.hasha256(wifHashFirst);
	    
	    let wifHashSig = wifHashSecond.slice(0, 4);
	    let wifBuf = Buffer.concat([wifBufPriv, wifHashSig], wifBufPriv.length + wifHashSig.length);
	    
	    /**
	     * base58(privat key + the version number + check code).
	     * it is used as WIF(Wallet import Format) privatKey
	     */
	    let wifFinal = bs58.encode(wifBuf); 
	    this.secWifAddress = wifFinal.toString('hex');
	   	this.generatePublicKey(key,addrVer);
    }

    generatePublicKey(key, addrVer){
	    /**
	     * set elliptic point and x,y axis
	     */
	    let pubPoint = key.getPublic();
	    let x = pubPoint.getX(); 
	    let y = pubPoint.getY(); 

	    /**
	     * use secp256k1. generate public key
	     * structe public key: 1(network ID) + 32bytes(from x axis) + 32bytes(from y axis)
	     * ripemd160(sha256(public key))
	     */
	    this.publicKey = pubPoint.encode('hex');
	   	this.generateAddress(this.publicKey, addrVer);
    }

	generateAddress(publicKey, addrVer){
	    let publicKeyInitialHash = this.hasha256(Buffer.from(publicKey, 'hex'));
	    var publicKeyRIPEHash = new RIPEMD160().update(Buffer.from(publicKeyInitialHash, 'hex')).digest('hex');

	    var hashBuffer = Buffer.from(publicKeyRIPEHash, 'hex');
	    var concatHash = Buffer.concat([addrVer, hashBuffer], addrVer.length + hashBuffer.length);

	    /**
	     * double sha256 generate hashExtRipe2. sha256(sha256(version number + hashBuffer)).
	     * the first 4 bytes of hashExtRipe2 are used as a checksum and placed at the end of 
	     * the 21 byte array. structe secBinary: 1(network ID) + concatHash + 4 byte(checksum)
	     */
	    var hashExtRipe = this.hasha256(concatHash);
	    var hashExtRipe2 = this.hasha256(hashExtRipe);
	    var hashSig = hashExtRipe2.slice(0, 4);
	    var secBinaryStr = Buffer.concat([concatHash, hashSig], concatHash.length + hashSig.length);


	    /**
	     * generate WIF private key and translate to hex
	     * generate SEC Address and translate to hex
	     */

	    this.secAddress = bs58.encode(Buffer.from(secBinaryStr));
    }

 	/**
 	* return four private key, wif private key,public key
 	* and sec address
 	*/ 
    getPrivateKey() {
        return this.privKey;
    }

    getsecWifFinal() {
    	return this.secWifAddress;
    }

    getPublicKey() {
    	return this.publicKey;
    }

    getAddress() {
   	    return this.secAddress;
    }

}

module.exports = secWallet;