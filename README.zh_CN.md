# Perfect-Crypto 加密函数库

<p align="center">
    <a href="http://perfect.org/get-involved.html" target="_blank">
        <img src="http://perfect.org/assets/github/perfect_github_2_0_0.jpg" alt="Get Involed with Perfect!" width="854" />
    </a>
</p>

<p align="center">
    <a href="https://github.com/PerfectlySoft/Perfect" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_1_Star.jpg" alt="Star Perfect On Github" />
    </a>  
    <a href="http://stackoverflow.com/questions/tagged/perfect" target="_blank">
        <img src="http://www.perfect.org/github/perfect_gh_button_2_SO.jpg" alt="Stack Overflow" />
    </a>  
    <a href="https://twitter.com/perfectlysoft" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_3_twit.jpg" alt="Follow Perfect on Twitter" />
    </a>  
    <a href="http://perfect.ly" target="_blank">
        <img src="http://www.perfect.org/github/Perfect_GH_button_4_slack.jpg" alt="Join the Perfect Slack" />
    </a>
</p>

<p align="center">
    <a href="https://developer.apple.com/swift/" target="_blank">
        <img src="https://img.shields.io/badge/Swift-3.0-orange.svg?style=flat" alt="Swift 3.0">
    </a>
    <a href="https://developer.apple.com/swift/" target="_blank">
        <img src="https://img.shields.io/badge/Platforms-OS%20X%20%7C%20Linux%20-lightgray.svg?style=flat" alt="Platforms OS X | Linux">
    </a>
    <a href="http://perfect.org/licensing.html" target="_blank">
        <img src="https://img.shields.io/badge/License-Apache-lightgrey.svg?style=flat" alt="License Apache">
    </a>
    <a href="http://twitter.com/PerfectlySoft" target="_blank">
        <img src="https://img.shields.io/badge/Twitter-@PerfectlySoft-blue.svg?style=flat" alt="PerfectlySoft Twitter">
    </a>
    <a href="http://perfect.ly" target="_blank">
        <img src="http://perfect.ly/badge.svg" alt="Slack Status">
    </a>
</p>

Perfect 摘要、加密和编解码函数库

### 问题报告、内容贡献和客户支持

我们目前正在过渡到使用JIRA来处理所有源代码资源合并申请、修复漏洞以及其它有关问题。因此，GitHub 的“issues”问题报告功能已经被禁用了。

如果您发现了问题，或者希望为改进本文提供意见和建议，[请在这里指出](http://jira.perfect.org:8080/servicedesk/customer/portal/1).

在您开始之前，请参阅[目前待解决的问题清单](http://jira.perfect.org:8080/projects/ISS/issues).

## 编译

请在您的Package.swift文件中增加下列依存关系：

```
.Package(url: "https://github.com/PerfectlySoft/Perfect-Crypto.git", majorVersion: 1)
```

## Linux 编译说明

请确保您的系统上已经安装了 libssl-dev 函数库

```
sudo apt-get install libssl-dev
```

## 概述

本函数库将OpenSSL的部分功能进行了封装并在Swift基本类型上进行了扩展，主要内容包括：

* 对于字符串、[UInt8] 和 UnsafeRawBufferPointer 指针增加了基本的编解码、摘要码和加密操作。
* 针对于非零结尾指针创建UTF-8字符串的方法
* 对OpenSSL BIO函数类的封装，提供可过滤的链式操作。

## 使用范例

### 16进制编解码

```swift
let testStr = "Hello, world!"
guard let hexBytes = testStr.encode(.hex) else {
	return
}

String(validatingUTF8: hexBytes) == "48656c6c6f2c20776f726c6421"

guard let unHex = hexBytes.decode(.hex) else {
	return
}

String(validatingUTF8: unHex) == testStr

```

### Base 64 编解码

```swift
let testStr = "Hello, world!"
guard let baseBytes = testStr.encode(.base64) else {
	return
}

String(validatingUTF8: baseBytes) == "SGVsbG8sIHdvcmxkIQ=="

guard let unBase = baseBytes.decode(.base64) else {
	return
}

String(validatingUTF8: unBase) == testStr
```

### 摘要码

```swift
let testStr = "Hello, world!"
let testAnswer = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
guard let enc = testStr.digest(.sha256)?.encode(.hex) else {
	return
}

String(validatingUTF8: enc) == testAnswer
```

### API参考

``` swift
public extension String {
	/// 从UTF8数组创建字符串，数组长度决定了转换内容长度；如果数据无效则字符串为空
	init?(validatingUTF8 a: [UInt8])
	/// 从指针构造字符串。指针可以不是零值结尾，而是由缓冲区长度决定转换内容长度
	/// 输入内容无效则返回为空
	init?(validatingUTF8 ptr: UnsafeRawBufferPointer?)
	/// 从字符串内获得缓冲区指针。
	func withBufferPointer<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) rethrows -> Result
}

public extension String {
	/// 将字符串转换为指定编码类型的线性表。
	func encode(_ encoding: Encoding) -> [UInt8]?
	/// 将字符串解码为制定编码类型的线性表。
	func decode(_ encoding: Encoding) -> [UInt8]?
	/// 摘要计算
	func digest(_ digest: Digest) -> [UInt8]?
}

public protocol Octal {}
extension UInt8: Octal {}

public extension Array where Element: Octal {
	/// 将数组转换为指定编码类型的线性表。
	func encode(_ encoding: Encoding) -> [UInt8]?
	/// 将数组解码为制定编码类型的线性表。
	func decode(_ encoding: Encoding) -> [UInt8]?
	/// 摘要计算
	func digest(_ digest: Digest) -> [UInt8]?
}

public extension UnsafeRawBufferPointer {
	/// 使用缓冲区生成编码内容，返回结果使用完后必须自行释放
	func encode(_ encoding: Encoding) -> UnsafeMutableRawBufferPointer?
	/// 使用缓冲区生成解码内容，返回结果使用完后必须自行释放
	func decode(_ encoding: Encoding) -> UnsafeMutableRawBufferPointer?
	/// 生成摘要内容，生成结果必须手工释放
	func digest(_ digest: Digest) -> UnsafeMutableRawBufferPointer?
}
```

### 算法清单

```swift
/// Available encoding methods.
public enum Encoding {
	case base64
	case hex
}

/// Available digest methods.
public enum Digest {
	case md4
	case md5
	case sha
	case sha1
	case dss
	case dss1
	case ecdsa
	case sha224
	case sha256
	case sha384
	case sha512
	case ripemd160
	case whirlpool
	
	case custom(String)
}

/// Available ciphers.
public enum Cipher {
	case des_ecb
	case des_ede
	case des_ede3
	case des_ede_ecb
	case des_ede3_ecb
	case des_cfb64
	case des_cfb1
	case des_cfb8
	case des_ede_cfb64
	case des_ede3_cfb1
	case des_ede3_cfb8
	case des_ofb
	case des_ede_ofb
	case des_ede3_ofb
	case des_cbc
	case des_ede_cbc
	case des_ede3_cbc
	case desx_cbc
	case des_ede3_wrap
	case rc4
	case rc4_40
	case rc4_hmac_md5
	case rc2_ecb
	case rc2_cbc
	case rc2_40_cbc
	case rc2_64_cbc
	case rc2_cfb64
	case rc2_ofb
	case bf_ecb
	case bf_cbc
	case bf_cfb64
	case bf_ofb
	case cast5_ecb
	case cast5_cbc
	case cast5_cfb64
	case cast5_ofb
	case aes_128_ecb
	case aes_128_cbc
	case aes_128_cfb1
	case aes_128_cfb8
	case aes_128_cfb128
	case aes_128_ofb
	case aes_128_ctr
	case aes_128_ccm
	case aes_128_gcm
	case aes_128_xts
	case aes_128_wrap
	case aes_192_ecb
	case aes_192_cbc
	case aes_192_cfb1
	case aes_192_cfb8
	case aes_192_cfb128
	case aes_192_ofb
	case aes_192_ctr
	case aes_192_ccm
	case aes_192_gcm
	case aes_192_wrap
	case aes_256_ecb
	case aes_256_cbc
	case aes_256_cfb1
	case aes_256_cfb8
	case aes_256_cfb128
	case aes_256_ofb
	case aes_256_ctr
	case aes_256_ccm
	case aes_256_gcm
	case aes_256_xts
	case aes_256_wrap
	case aes_128_cbc_hmac_sha1
	case aes_256_cbc_hmac_sha1
	case aes_128_cbc_hmac_sha256
	case aes_256_cbc_hmac_sha256
	case camellia_128_ecb
	case camellia_128_cbc
	case camellia_128_cfb1
	case camellia_128_cfb8
	case camellia_128_cfb128
	case camellia_128_ofb
	case camellia_192_ecb
	case camellia_192_cbc
	case camellia_192_cfb1
	case camellia_192_cfb8
	case camellia_192_cfb128
	case camellia_192_ofb
	case camellia_256_ecb
	case camellia_256_cbc
	case camellia_256_cfb1
	case camellia_256_cfb8
	case camellia_256_cfb128
	case camellia_256_ofb
	case seed_ecb
	case seed_cbc
	case seed_cfb128
	case seed_ofb
	
	case custom(String)
}
```
