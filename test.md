<a name="secWallet"></a>

## secWallet
using EC crypto generate sec private key public key and wif addressgenerate sec wallet

**Kind**: global class  

* [secWallet](#secWallet)
    * [.hasha256(data)](#secWallet+hasha256)
    * [.generatePrivateKey()](#secWallet+generatePrivateKey)
    * [.generatePublicKey(key, addrVer)](#secWallet+generatePublicKey)
    * [.generateAddress(publicKey, addrVer)](#secWallet+generateAddress)
    * [.getPrivateKey()](#secWallet+getPrivateKey)

<a name="secWallet+hasha256"></a>

### secWallet.hasha256(data)
A small function created as there is a lot of sha256 hashing.

**Kind**: instance method of [<code>secWallet</code>](#secWallet)  

| Param | Type | Description |
| --- | --- | --- |
| data | <code>Buffer</code> | creat sha256 hash buffer |

<a name="secWallet+generatePrivateKey"></a>

### secWallet.generatePrivateKey()
0x00 P2PKH Mainnet, 0x6f P2PKH Testnet0x80 Mainnet, 0xEF Testnet （or Test Network: 0x6f and Namecoin Net:0x34）generate private key through sha256 random values. and translate to hexget usedful private key. It will be used for secp256k1generate check code. two times SHA256 at privatKey.base58(privat key + the version number + check code).it is used as WIF(Wallet import Format) privatKey

**Kind**: instance method of [<code>secWallet</code>](#secWallet)  
<a name="secWallet+generatePublicKey"></a>

### secWallet.generatePublicKey(key, addrVer)
generate public key

**Kind**: instance method of [<code>secWallet</code>](#secWallet)  

| Param | Type | Description |
| --- | --- | --- |
| key | <code>Buffer</code> |  |
| addrVer | <code>Buffer</code> | input addVer from generatePrivateKey() set elliptic point and x,y axis not sure whether useful let x = pubPoint.getX() let y = pubPoint.getY() use secp256k1. generate public key structe public key: 1(network ID) + 32bytes(from x axis) + 32bytes(from y axis) ripemd160(sha256(public key)) |

<a name="secWallet+generateAddress"></a>

### secWallet.generateAddress(publicKey, addrVer)
double sha256 generate hashExtRipe2. sha256(sha256(version number + hashBuffer)).the first 4 bytes of hashExtRipe2 are used as a checksum and placed at the end ofthe 21 byte array. structe secBinary: 1(network ID) + concatHash + 4 byte(checksum)

**Kind**: instance method of [<code>secWallet</code>](#secWallet)  

| Param | Type | Description |
| --- | --- | --- |
| publicKey | <code>Buffer</code> | input public key from generatePublicKey() |
| addrVer | <code>Buffer</code> | input addVer from generatePrivateKey() generate WIF private key and translate to hex generate SEC Address and translate to hex |

<a name="secWallet+getPrivateKey"></a>

### secWallet.getPrivateKey()
return four private key, wif private key, public keyand sec address

**Kind**: instance method of [<code>secWallet</code>](#secWallet)  
