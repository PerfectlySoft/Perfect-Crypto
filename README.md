# Perfect-Crypto [简体中文](README.zh_CN.md)

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


Digest, cipher and encoding support for Perfect.

## Issues

We are transitioning to using JIRA for all bugs and support related issues, therefore the GitHub issues has been disabled.

If you find a mistake, bug, or any other helpful suggestion you'd like to make on the docs please head over to [http://jira.perfect.org:8080/servicedesk/customer/portal/1](http://jira.perfect.org:8080/servicedesk/customer/portal/1) and raise it.

A comprehensive list of open issues can be found at [http://jira.perfect.org:8080/projects/ISS/issues](http://jira.perfect.org:8080/projects/ISS/issues)

## Building

Add this project as a dependency in your Package.swift file.

```
.Package(url: "https://github.com/PerfectlySoft/Perfect-Crypto.git", majorVersion: 1)
```

## Linux Build Notes

Ensure that you have installed libssl-dev. OpenSSL 1.0.2+ is required for this package. On Ubuntu 14 or some Debian distributions you will need to update your OpenSSL before this package will build.

```
sudo apt-get install libssl-dev
```

## Overview

This package wraps up some of the functionality provided by OpenSSL and adds a Swift layer on top of it. The main features are:

* Extensions for String, [UInt8] and UnsafeRawBufferPointer that provide simple encode, decode, digest and cipher operations.
* Convenience functions for creating Strings given non-null terminated UTF8 containing UnsafeRawBufferPointer or [UInt8] objects.
* Swift wrappers around OpenSSL BIOs, providing chainable, filterable byte IO sinks and sources.

## Usage Exmaples

### Encode/Decode Hex

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

### Encode/Decode Base 64

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

### Digest

```swift
let testStr = "Hello, world!"
let testAnswer = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
guard let enc = testStr.digest(.sha256)?.encode(.hex) else {
	return
}

String(validatingUTF8: enc) == testAnswer
```

### Public API

```swift
public extension String {
	/// Construct a string from a UTF8 character pointer.
	/// Character data does not need to be null terminated.
	/// The buffer's count indicates how many characters are to be converted.
	/// Returns nil if the data is invalid.
	init?(validatingUTF8 ptr: UnsafeRawBufferPointer?)
	/// Construct a string from a UTF8 character array.
	/// The array's count indicates how many characters are to be converted.
	/// Returns nil if the data is invalid.
	init?(validatingUTF8 a: [UInt8])
	/// Obtain a buffer pointer for the String's UTF8 characters.
	func withBufferPointer<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) rethrows -> Result
}

public extension String {
	/// Decode the String into an array of bytes using the indicated encoding.
	/// The string's UTF8 characters are decoded.
	func decode(_ encoding: Encoding) -> [UInt8]?
	/// Encode the String into an array of bytes using the indicated encoding.
	/// The string's UTF8 characters are decoded.
	func encode(_ encoding: Encoding) -> [UInt8]?
	/// Perform the digest algorithm on the String's UTF8 bytes
	func digest(_ digest: Digest) -> [UInt8]?
}

public protocol Octal {}
extension UInt8: Octal {}

public extension Array where Element: Octal {
	/// Encode the Array into An array of bytes using the indicated encoding.
	func encode(_ encoding: Encoding) -> [UInt8]?
	/// Decode the Array into an array of bytes using the indicated encoding.
	func decode(_ encoding: Encoding) -> [UInt8]?
	/// Digest the Array data into an array of bytes using the indicated algorithm.
	func digest(_ digest: Digest) -> [UInt8]?
}

public extension UnsafeRawBufferPointer {
	/// Encode the buffer using the indicated encoding.
	/// The return value must be deallocated by the caller.
	func encode(_ encoding: Encoding) -> UnsafeMutableRawBufferPointer?
	/// Decode the buffer using the indicated encoding.
	/// The return value must be deallocated by the caller.
	func decode(_ encoding: Encoding) -> UnsafeMutableRawBufferPointer?
	/// Digest the buffer using the indicated algorithm.
	/// The return value must be deallocated by the caller.
	func digest(_ digest: Digest) -> UnsafeMutableRawBufferPointer?
}
```

### Supported encodings, digests and ciphers

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
