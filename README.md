<a name="SecWallet"></a>
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard) 

[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)] 

## SecWallet
Generate a lightweight wallet, At th moment it supports key creation and conversion between various formats
It is complemented by the following packages:
secjs-tx
secjs-icap

**Kind**: global class  

* [SecWallet](#SecWallet)
    * [new SecWallet(priv, pub)](#new_SecWallet_new)
    * [.privKey](#SecWallet+privKey)
    * [.pubKey](#SecWallet+pubKey)
    * [.assert(val, msg)](#SecWallet+assert)
    * [.generate(icapGenerate)](#SecWallet+generate)
    * [.generateVantiyaAddress(pattern)](#SecWallet+generateVantiyaAddress)
    * [.getPrivateKey()](#SecWallet+getPrivateKey)
    * [.getPrivateKeyString()](#SecWallet+getPrivateKeyString)
    * [.getPublicKey()](#SecWallet+getPublicKey)
    * [.getPublicKeyString()](#SecWallet+getPublicKeyString)
    * [.getAddress()](#SecWallet+getAddress)
    * [.getAddressString()](#SecWallet+getAddressString)
    * [.getAddressChecksumString()](#SecWallet+getAddressChecksumString)
    * [.fromPrivateKey(priv)](#SecWallet+fromPrivateKey)
    * [.fromExtendedPrivateKey(priv)](#SecWallet+fromExtendedPrivateKey)
    * [.fromPublicKey(pub, nonStrict)](#SecWallet+fromPublicKey)
    * [.fromExtendedPublicKey(pub)](#SecWallet+fromExtendedPublicKey)

<a name="new_SecWallet_new"></a>

### new SecWallet(priv, pub)
the constructor of the class, private key and publick key will be as property


| Param | Type |
| --- | --- |
| priv | <code>String</code> | 
| pub | <code>String</code> | 

<a name="SecWallet+privKey"></a>

### secWallet.privKey
get private key and return this._privKey

**Kind**: instance property of [<code>SecWallet</code>](#SecWallet)  
<a name="SecWallet+pubKey"></a>

### secWallet.pubKey
get publickey through util function and return this._pubKey

**Kind**: instance property of [<code>SecWallet</code>](#SecWallet)  
<a name="SecWallet+assert"></a>

### secWallet.assert(val, msg)
verify error

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  

| Param |
| --- |
| val | 
| msg | 

<a name="SecWallet+generate"></a>

### secWallet.generate(icapGenerate)
**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  

| Param | Type | Description |
| --- | --- | --- |
| icapGenerate | <code>Buffer</code> | -create an instance based on a new random key,  setting icap to true will generate an address suitable for the ICAP Direct mode. |

<a name="SecWallet+generateVantiyaAddress"></a>

### secWallet.generateVantiyaAddress(pattern)
-create an instance where the address is valid against the supplied pattern
(this will be very slow)

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  

| Param | Type |
| --- | --- |
| pattern | <code>String</code> | 

<a name="SecWallet+getPrivateKey"></a>

### secWallet.getPrivateKey()
-return the private key

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  
<a name="SecWallet+getPrivateKeyString"></a>

### secWallet.getPrivateKeyString()
-return the private key to string mode

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  
<a name="SecWallet+getPublicKey"></a>

### secWallet.getPublicKey()
-return the public key

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  
<a name="SecWallet+getPublicKeyString"></a>

### secWallet.getPublicKeyString()
-return the public key to string mode

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  
<a name="SecWallet+getAddress"></a>

### secWallet.getAddress()
-return the address

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  
<a name="SecWallet+getAddressString"></a>

### secWallet.getAddressString()
return the address to the string mode

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  
<a name="SecWallet+getAddressChecksumString"></a>

### secWallet.getAddressChecksumString()
-return the address with checksum

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  
<a name="SecWallet+fromPrivateKey"></a>

### secWallet.fromPrivateKey(priv)
-create an instance based on a raw private key
you can generate the raw pribate key by secjs-util

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  

| Param | Type |
| --- | --- |
| priv | <code>String</code> | 

<a name="SecWallet+fromExtendedPrivateKey"></a>

### secWallet.fromExtendedPrivateKey(priv)
-create an instance based on a BIP32 extended private key(xprv)

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  

| Param | Type |
| --- | --- |
| priv | <code>String</code> | 

<a name="SecWallet+fromPublicKey"></a>

### secWallet.fromPublicKey(pub, nonStrict)
-create an instance based on a public key

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  

| Param | Type |
| --- | --- |
| pub | <code>String</code> | 
| nonStrict | <code>Buffer</code> | 

<a name="SecWallet+fromExtendedPublicKey"></a>

### secWallet.fromExtendedPublicKey(pub)
-create an instance based on a BIP32 extended public key(xpub)

**Kind**: instance method of [<code>SecWallet</code>](#SecWallet)  

| Param | Type |
| --- | --- |
| pub | <code>String</code> | 

<a name="SecHDKey"></a>

## SecHDKey
Generate BIP32 wallets
For the seed we suggest to use BIP39 to create one from a BIP39 mnemonic

**Kind**: global class  

* [SecHDKey](#SecHDKey)
    * [.fromMasterSeed(seedBuffer)](#SecHDKey+fromMasterSeed)
    * [.fromExtendedKey(base58Key)](#SecHDKey+fromExtendedKey)
    * [.privateExtendedKey()](#SecHDKey+privateExtendedKey)
    * [.publicExtendedKey()](#SecHDKey+publicExtendedKey)
    * [.derivePath(path)](#SecHDKey+derivePath)
    * [.deriveChild(index)](#SecHDKey+deriveChild)
    * [.getWallet()](#SecHDKey+getWallet)

<a name="SecHDKey+fromMasterSeed"></a>

### secHDKey.fromMasterSeed(seedBuffer)
-create an instance based on seed

**Kind**: instance method of [<code>SecHDKey</code>](#SecHDKey)  

| Param | Type |
| --- | --- |
| seedBuffer | <code>String</code> | 

<a name="SecHDKey+fromExtendedKey"></a>

### secHDKey.fromExtendedKey(base58Key)
-create an instance based on a BIP32 extended private or public key

**Kind**: instance method of [<code>SecHDKey</code>](#SecHDKey)  

| Param | Type |
| --- | --- |
| base58Key | <code>String</code> | 

<a name="SecHDKey+privateExtendedKey"></a>

### secHDKey.privateExtendedKey()
-return a BIP32 extended private key (xprv)

**Kind**: instance method of [<code>SecHDKey</code>](#SecHDKey)  
<a name="SecHDKey+publicExtendedKey"></a>

### secHDKey.publicExtendedKey()
-return a BIP32 extended public key(xpub)

**Kind**: instance method of [<code>SecHDKey</code>](#SecHDKey)  
<a name="SecHDKey+derivePath"></a>

### secHDKey.derivePath(path)
-derive a node based on a path (e.g. m/44'/0'/0/1)

**Kind**: instance method of [<code>SecHDKey</code>](#SecHDKey)  

| Param |
| --- |
| path | 

<a name="SecHDKey+deriveChild"></a>

### secHDKey.deriveChild(index)
-derive a node based on a child index

**Kind**: instance method of [<code>SecHDKey</code>](#SecHDKey)  

| Param |
| --- |
| index | 

<a name="SecHDKey+getWallet"></a>

### secHDKey.getWallet()
-return a wallet instance as seen above

**Kind**: instance method of [<code>SecHDKey</code>](#SecHDKey)  

