<a name="secWallet"></a>
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard) 

[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)] 

## secWallet
using EC crypto generate sec private key public key and wif address
generate sec wallet

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
0x80 Mainnet, 0xEF Testnet （or Test Network: 0x6f and Namecoin Net:0x34）
generate private key through sha256 random values. and translate to hex
get usedful private key. It will be used for secp256k1
generate check code. two times SHA256 at privatKey.
base58(privat key + the version number + check code).
it is used as WIF(Wallet import Format) privatKey

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
the first 4 bytes of hashExtRipe2 are used as a checksum and placed at the end of
the 21 byte array. structe secBinary: 1(network ID) + concatHash + 4 byte(checksum)

**Kind**: instance method of [<code>secWallet</code>](#secWallet)  

| Param | Type | Description |
| --- | --- | --- |
| publicKey | <code>Buffer</code> | input public key from generatePublicKey() |
| addrVer | <code>Buffer</code> | input addVer from generatePrivateKey() generate WIF private key and translate to hex generate SEC Address and translate to hex |

<a name="secWallet+getPrivateKey"></a>

### secWallet.getPrivateKey()
return four private key, wif private key, public key
and sec address

**Kind**: instance method of [<code>secWallet</code>](#secWallet)  

## SEC 地址
-----------------------------------------------
得到SEC公钥以后，需要通过公钥得到地址。由于椭圆曲线算法生成的公钥信息比较长，压缩格式的有33字节，非压缩的则有65字节。

地址是为了减少接收方所需标识的字节数。SEC地址（secAddress）的生成步骤如下：

1. 将公钥通过SHA256哈希算法处理得到32字节的哈希值，
2. 后对得到的哈希值通过RIPEMD-160算法来得到20字节的哈希值 —— Hash160  即ripemd160（sha256（publicKey））
3. 把版本号[2]+Hash160组成的21字节数组进行双次SHA256哈希运算，得到的哈希值的头4个字节作为校验和，放置21字节数组的末尾。
4. 对组成25位数组进行Base58编码，就得到地址。