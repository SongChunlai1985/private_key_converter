# BIP39 Mnemonic Private Key Converter

基于 Qt 的 BIP39 助记词与比特币私钥/地址格式转换工具。

> 仅用于学习、研究和测试网。请勿用于任何非法用途。

## 功能
- BIP39 熵 <-> 助记词
- PBKDF2-HMAC-SHA512 种子生成
- 主私钥/链码提取
- secp256k1 公钥计算、压缩/非压缩
- 地址生成 (Hash160 + Base58Check)
- WIF 编码/解码，压缩 WIF 转换
- ECDSA 签名/验签
- Base58/Base64 编解码
- WIF/地址候选扫描演示
...

## 依赖
- Qt 5/6 (core, gui, widgets) 5.12.2
- OpenSSL (libssl, libcrypto) 0.9.8
- libsecp256k1
- C++11 编译器

## 构建
修改 bip39.pro 中的 OpenSSL 和 libsecp256k1 路径...
qmake
make

## 运行
./bip39

## 文件结构
...

## 安全警告
- 私钥/助记词敏感
- 随机数 rand() 不安全
- 不要输入真实资产
- 扫描功能可能违法
- 第三方代码版权

## 许可
MIT/X11，第三方组件...

## 致谢
Satoshi Nakamoto, Crypto++, trezor, bitcoin-core/secp256k1

## 捐赠
BTC: 13SongiriQuWoFhoimsVS21CyaTxozKBVA
