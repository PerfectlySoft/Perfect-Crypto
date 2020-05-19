# Perfect-Crypto [简体中文](README.zh_CN.md)

<p align="center">
    <a href="http://perfect.org/get-involved.html" target="_blank">
        <img src="http://perfect.org/assets/github/perfect_github_2_0_0.jpg" alt="Get Involed with Perfect!" width="854" />
    </a>
</p>

<p align="center">
    <a href="https://developer.apple.com/swift/" target="_blank">
        <img src="https://img.shields.io/badge/Swift-5.2-orange.svg?style=flat" alt="Swift 5.2">
    </a>
    <a href="https://developer.apple.com/swift/" target="_blank">
        <img src="https://img.shields.io/badge/Platforms-OS%20X%20%7C%20Linux%20-lightgray.svg?style=flat" alt="Platforms OS X | Linux">
    </a>
    <a href="http://perfect.org/licensing.html" target="_blank">
        <img src="https://img.shields.io/badge/License-Apache-lightgrey.svg?style=flat" alt="License Apache">
    </a>
</p>


Digest, cipher and encoding support for Perfect.

## Building

Add this project as a dependency in your Package.swift file.

```
.package(url: "https://github.com/PerfectlySoft/Perfect-Crypto.git", from: "4.0.0")
```

## Linux Build Notes

Ensure that you have installed libssl-dev. OpenSSL 1.0.2+ is required for this package. On Ubuntu 14 or some Debian distributions you will need to update your OpenSSL before this package will build.

```
sudo apt-get install openssl libssl-dev
```

## Overview

This package wraps up some of the functionality provided by OpenSSL and adds a Swift layer on top of it. The main features are:

* Extensions for String, [UInt8] and UnsafeRawBufferPointer that provide simple encode, decode, digest and cipher operations.
* JWT (JSON Web Token) generation and validation.
* Generation of arbitrary amounts of random data.
* Swift wrappers around OpenSSL BIOs, providing chainable, filterable byte IO sinks and sources.
* Convenience functions for creating Strings given non-null terminated UTF8 containing UnsafeRawBufferPointer or [UInt8] objects.

## Usage Examples

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

### HMAC Sign/Verify

The following snippet will HMAC-SHA1 sign, encode as base64, then decode, and verify a data string. Replace usages of .sha1 or .base64 depending on your requirements.

```swift
let password = "this is a good pw"
let data = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	
if let signed = data.sign(.sha1, key: HMACKey(password))?.encode(.base64),
	let base64Str = String(validatingUTF8: signed),
	
	let reRawData = base64Str.decode(.base64) {
	
	let verifyResult = data.verify(.sha1, signature: reRawData, key: HMACKey(password))
	XCTAssert(verifyResult)
} else {
	XCTAssert(false, "Failed signing")
}
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
	/// Sign the String data into an array of bytes using the indicated algorithm and key.
	func sign(_ digest: Digest, key: Key) -> [UInt8]?
	/// Verify the signature against the String data.
	/// Returns true if the signature is verified. Returns false otherwise.
	func verify(_ digest: Digest, signature: [UInt8], key: Key) -> Bool
	/// Encrypt this buffer using the indicated cipher, password, and salt.
	/// The string's UTF8 characters are encoded.
	/// Resulting data is in PEM encoded CMS format.
	func encrypt(_ cipher: Cipher,
	             password: String,
	             salt: String,
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> String?
	/// Decrypt this PEM encoded CMS buffer using the indicated password and salt.
	/// Resulting decrypted data must be valid UTF-8 characters or the operation will fail.
	func decrypt(_ cipher: Cipher,
	             password: String,
	             salt: String,
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> String?
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
	/// Sign the Array data into an array of bytes using the indicated algorithm and key.
	func sign(_ digest: Digest, key: Key) -> [UInt8]?
	/// Verify the array against the signature.
	/// Returns true if the signature is verified. Returns false otherwise.
	func verify(_ digest: Digest, signature: [UInt8], key: Key) -> Bool
	/// Decrypt this buffer using the indicated cipher, key an iv (initialization vector).
	func encrypt(_ cipher: Cipher, key: [UInt8], iv: [UInt8]) -> [UInt8]?
	/// Decrypt this buffer using the indicated cipher, key an iv (initialization vector).
	func decrypt(_ cipher: Cipher, key: [UInt8], iv: [UInt8]) -> [UInt8]?
	/// Encrypt this buffer using the indicated cipher, password, and salt.
	/// Resulting data is PEM encoded CMS format.
	func encrypt(_ cipher: Cipher,
	             password: [UInt8],
	             salt: [UInt8],
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> [UInt8]?
	/// Decrypt this PEM encoded CMS buffer using the indicated password and salt.
	func decrypt(_ cipher: Cipher,
	             password: [UInt8],
	             salt: [UInt8],
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> [UInt8]?
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
	/// Sign the buffer using the indicated algorithm and key.
	/// The return value must be deallocated by the caller.
	func sign(_ digest: Digest, key: Key) -> UnsafeMutableRawBufferPointer?
	/// Verify the signature against the buffer.
	/// Returns true if the signature is verified. Returns false otherwise.
	func verify(_ digest: Digest, signature: UnsafeRawBufferPointer, key: Key) -> Bool
	/// Encrypt this buffer using the indicated cipher, key and iv (initialization vector).
	/// Returns a newly allocated buffer which must be freed by the caller.
	func encrypt(_ cipher: Cipher, key: UnsafeRawBufferPointer, iv: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer?
	/// Decrypt this buffer using the indicated cipher, key and iv (initialization vector).
	/// Returns a newly allocated buffer which must be freed by the caller.
	func decrypt(_ cipher: Cipher, key: UnsafeRawBufferPointer, iv: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer?
	/// Encrypt this buffer to PEM encoded CMS format using the indicated cipher, password, and salt.
	/// Returns a newly allocated buffer which must be freed by the caller.
	func encrypt(_ cipher: Cipher,
	             password: UnsafeRawBufferPointer,
	             salt: UnsafeRawBufferPointer,
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> UnsafeMutableRawBufferPointer?
   	/// Decrypt this PEM encoded CMS buffer using the indicated password and salt.
	/// Returns a newly allocated buffer which must be freed by the caller.
	func decrypt(_ cipher: Cipher,
	             password: UnsafeRawBufferPointer,
	             salt: UnsafeRawBufferPointer,
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> UnsafeMutableRawBufferPointer?
}

public extension UnsafeRawBufferPointer {
	/// Allocate memory for `size` bytes with word alignment from the encryption library's
	///	random number generator.
	///
	/// - Postcondition: The memory is allocated and initialized to random bits.
	static func allocateRandom(count size: Int) -> UnsafeRawBufferPointer? 
}

public extension FixedWidthInteger {
  /// get a random integer, i.e., signed or unsigned int8/16/32/64
  public static var random: Self
}
public extension Float {
  /// get a random float
  public static var random: Float
}
public extension Double {
  /// get a random double
  public static var random: Double 
}
```

### JSON Web Tokens (JWT)

This crypto package provides an means for creating new JWT tokens and validating existing tokens.

JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed. JWTs can be signed using a secret (with the HMAC algorithm) or a public/private key pair using RSA. Source: [JWT](https://jwt.io/introduction/).

New JWT tokens are created through the `JWTCreator` object.

```swift
/// Creates and signs new JWT tokens.
public struct JWTCreator {
	/// Creates a new JWT token given a payload.
	/// The payload can then be signed to generate a JWT token string.
	public init?(payload: [String:Any])
	/// Sign and return a new JWT token string using an HMAC key.
	/// Additional headers can be optionally provided.
	/// Throws a JWT.Error.signingError if there is a problem generating the token string.
	public func sign(alg: JWT.Alg, key: String, headers: [String:Any] = [:]) throws -> String
	/// Sign and return a new JWT token string using the given key.
	/// Additional headers can be optionally provided.
	/// The key type must be compatible with the indicated `algo`.
	/// Throws a JWT.Error.signingError if there is a problem generating the token string.
	public func sign(alg: JWT.Alg, key: Key, headers: [String:Any] = [:]) throws -> String
}
```

Existing JWT tokens can be validated through the `JWTVerifier` object.

```swift
/// Accepts a JWT token string and verifies its structural validity and signature.
public struct JWTVerifier {
	/// The headers obtained from the token.
	public var header: [String:Any]
	/// The payload carried by the token.
	public var payload: [String:Any]
	/// Create a JWTVerifier given a source string in the "aaaa.bbbb.cccc" format.
	/// Returns nil if the given string is not a valid JWT.
	/// *Does not perform verification in this step.* Call `verify` with your key to validate.
	/// If verification succeeds then the `.headers` and `.payload` properties can be safely accessed.
	public init?(_ jwt: String)
	/// Verify the token based on the indicated algorithm and HMAC key.
	/// Throws a JWT.Error.verificationError if any aspect of the token is incongruent.
	/// Returns without any error if the token was able to be verified.
	/// The parameter `algo` must match the token's "alg" header.
	public func verify(algo: JWT.Alg, key: String) throws
	/// Verify the token based on the indicated algorithm and key.
	/// Throws a JWT.Error.verificationError if any aspect of the token is incongruent.
	/// Returns without any error if the token was able to be verified.
	/// The parameter `algo` must match the token's "alg" header.
	/// The key type must be compatible with the indicated `algo`.
	public func verify(algo: JWT.Alg, key: Key) throws
}
```

The following example will create and then verify a token using the "HS256" alg scheme.

```swift
let name = "John Doe"
let tstPayload = ["sub": "1234567890", "name": name, "admin": true] as [String : Any]
let secret = "secret"
guard let jwt1 = JWTCreator(payload: tstPayload) else {
	return // fatal error
}
let token = try jwt1.sign(alg: .hs256, key: secret)
guard let jwt = JWTVerifier(token) else {
  return // fatal error
}
try jwt.verify(algo: .hs256, key: HMACKey(secret))
let fndName = jwt.payload["name"] as? String
// name == fndName!
```

It's important to note that the JWTVerifier will verify that the token is cryptographically sound, but it **does not** validate payload claims such as iss(uer) or exp(iration). You can obtain these from the payload dictionary and validate according to the needs of your application. 

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

## Further Information

For more documentation, please visit [perfect.org](http://www.perfect.org/docs/crypto.html).
