<a name="secWallet"></a>
[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard) 

[![JavaScript Style Guide](https://img.shields.io/badge/code_style-standard-brightgreen.svg)] 

## secWallet


## SEC 地址
-----------------------------------------------
得到SEC公钥以后，需要通过公钥得到地址。由于椭圆曲线算法生成的公钥信息比较长，压缩格式的有33字节，非压缩的则有65字节。

地址是为了减少接收方所需标识的字节数。SEC地址（secAddress）的生成步骤如下：

1. 将公钥通过SHA256哈希算法处理得到32字节的哈希值，
2. 后对得到的哈希值通过RIPEMD-160算法来得到20字节的哈希值 —— Hash160  即ripemd160（sha256（publicKey））
3. 把版本号[2]+Hash160组成的21字节数组进行双次SHA256哈希运算，得到的哈希值的头4个字节作为校验和，放置21字节数组的末尾。
4. 对组成25位数组进行Base58编码，就得到地址。