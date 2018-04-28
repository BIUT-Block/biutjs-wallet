# SEC钱包
----------------------------------------------
## SEC 私钥和公钥
----------------------------------------------
  SEC私钥（privKey）其实是使用SHA-256生成的32字节（256位）的随机数，有效私钥的范围则取决于我们使用的secp256k1 椭圆曲线数字签名标准。
在私钥的前面加上版本号，后面添加压缩标志和附加校验码，校验码即sha256（sha256（privKey））的前四个字节
然后再对其进行Base58编码，就可以得到常见的WIF（Wallet import Format)格式的私钥（secWifAddress）。
<br>
<br>
<br>
  私钥经过椭圆曲线乘法运算，可以得到公钥(publicKey)。公钥是椭圆曲线上的点(pubPoint)，并具有x和y坐标。
由于数学原理，从私钥推算公钥是可行的，从公钥逆推私钥是不可能的。
<br>
<br>
<br>
## SEC 地址
-----------------------------------------------
得到SEC公钥以后，需要通过公钥得到地址。由于椭圆曲线算法生成的公钥信息比较长，压缩格式的有33字节，非压缩的则有65字节。
地址是为了减少接收方所需标识的字节数。SEC地址（secAddress）的生成步骤如下：
<br>

1. 将公钥通过SHA256哈希算法处理得到32字节的哈希值，
2. 后对得到的哈希值通过RIPEMD-160算法来得到20字节的哈希值 —— Hash160  即ripemd160（sha256（publicKey））
3. 把版本号[2]+Hash160组成的21字节数组进行双次SHA256哈希运算，得到的哈希值的头4个字节作为校验和，放置21字节数组的末尾。
4. 对组成25位数组进行Base58编码，就得到地址。