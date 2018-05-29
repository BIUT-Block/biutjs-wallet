<a name="secWallet"></a>

## secWallet
using EC crypto generate sec private key public key and wif address

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
0x00 P2PKH Mainnet, 0x6f P2PKH Testnet

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
double sha256 generate hashExtRipe2. sha256(sha256(version number + hashBuffer)).

**Kind**: instance method of [<code>secWallet</code>](#secWallet)  

| Param | Type | Description |
| --- | --- | --- |
| publicKey | <code>Buffer</code> | input public key from generatePublicKey() |
| addrVer | <code>Buffer</code> | input addVer from generatePrivateKey() generate WIF private key and translate to hex generate SEC Address and translate to hex |

<a name="secWallet+getPrivateKey"></a>

### secWallet.getPrivateKey()
return four private key, wif private key, public key

**Kind**: instance method of [<code>secWallet</code>](#secWallet)  