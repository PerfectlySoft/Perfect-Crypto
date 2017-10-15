//
//  Extensions.swift
//  PerfectCrypto
//
//  Created by Kyle Jessup on 2017-02-07.
//	Copyright (C) 2017 PerfectlySoft, Inc.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2017 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//
//

import Foundation

public extension String {
	/// Construct a string from a UTF8 character array.
	/// The array's count indicates how many characters are to be converted.
	/// Returns nil if the data is invalid.
	init?(validatingUTF8 a: [UInt8]) {
		self = UTF8Encoding.encode(generator: a.makeIterator())
	}
	/// Construct a string from a UTF8 character pointer.
	/// Character data does not need to be null terminated.
	/// The buffer's count indicates how many characters are to be converted.
	/// Returns nil if the data is invalid.
	init?(validatingUTF8 ptr: UnsafeRawBufferPointer?) {
		guard let ptr = ptr else {
			return nil
		}
		self = UTF8Encoding.encode(generator: ptr.makeIterator())
	}
	/// Obtain a buffer pointer for the String's UTF8 characters.
	func withBufferPointer<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) rethrows -> Result {
		let chars = [UInt8](self.utf8)
		let count = chars.count
		return try body(UnsafeRawBufferPointer(start: UnsafePointer(chars), count: count))
	}
}

public typealias EncodingS = Encoding

public extension String {
	/// Decode the String into an array of bytes using the indicated encoding.
	/// The string's UTF8 characters are decoded.
	func decode(_ encoding: EncodingS) -> [UInt8]? {
		return Array(utf8).decode(encoding)
	}
	/// Encode the String into an array of bytes using the indicated encoding.
	/// The string's UTF8 characters are encoded.
	func encode(_ encoding: EncodingS) -> [UInt8]? {
		return Array(utf8).encode(encoding)
	}
	/// Perform the digest algorithm on the String's UTF8 bytes.
	func digest(_ digest: Digest) -> [UInt8]? {
		return Array(utf8).digest(digest)
	}
	/// Sign the String data into an array of bytes using the indicated algorithm and key.
	func sign(_ digest: Digest, key: Key) -> [UInt8]? {
		return Array(utf8).sign(digest, key: key)
	}
	/// Verify the signature against the String data.
	/// Returns true if the signature is verified. Returns false otherwise.
	func verify(_ digest: Digest, signature: [UInt8], key: Key) -> Bool {
		return Array(utf8).verify(digest, signature: signature, key: key)
	}
	/// Encrypt this buffer using the indicated cipher, password, and salt.
	/// The string's UTF8 characters are encoded.
	/// Resulting data is in PEM encoded CMS format.
	func encrypt(_ cipher: Cipher,
	             password: String,
	             salt: String,
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> String? {
		guard let v = Array(utf8).encrypt(cipher, password: Array(password.utf8), salt: Array(salt.utf8), keyIterations: keyIterations, keyDigest: keyDigest) else {
			return nil
		}
		return String(validatingUTF8: v)
	}
	/// Decrypt this PEM encoded CMS buffer using the indicated password and salt.
	/// Resulting decrypted data must be valid UTF-8 characters or the operation will fail.
	func decrypt(_ cipher: Cipher,
	             password: String,
	             salt: String,
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> String? {
		guard let v = Array(utf8).decrypt(cipher, password: Array(password.utf8), salt: Array(salt.utf8), keyIterations: keyIterations, keyDigest: keyDigest) else {
			return nil
		}
		return String(validatingUTF8: v)
	}
}

public protocol Octal {}
extension UInt8: Octal {}

public extension Array where Element: Octal {
	/// Creates a new array containing the specified number of a single random values.
	init(randomCount count: Int) {
		self.init(repeating: UInt8(0) as! Element, count: count)
		let p = UnsafeMutableRawBufferPointer(mutating: UnsafeRawBufferPointer(start: &self, count: count))
		p.initializeRandom()
	}
}

public extension Array where Element: Octal {
	/// Encode the Array into An array of bytes using the indicated encoding.
	func encode(_ encoding: Encoding) -> [UInt8]? {
		let ptr = UnsafeRawBufferPointer(start: self, count: self.count)
		guard let newPtr = ptr.encode(encoding) else {
			return nil
		}
		defer { newPtr.deallocate() }
		return newPtr.map { $0 }
	}
	/// Decode the Array into an array of bytes using the indicated encoding.
	func decode(_ encoding: Encoding) -> [UInt8]? {
		let ptr = UnsafeRawBufferPointer(start: self, count: self.count)
		guard let newPtr = ptr.decode(encoding) else {
			return nil
		}
		defer { newPtr.deallocate() }
		return newPtr.map { $0 }
	}
	/// Digest the Array data into an array of bytes using the indicated algorithm.
	func digest(_ digest: Digest) -> [UInt8]? {
		let ptr = UnsafeRawBufferPointer(start: self, count: self.count)
		guard let newPtr = ptr.digest(digest) else {
			return nil
		}
		defer { newPtr.deallocate() }
		return newPtr.map { $0 }
	}
	/// Sign the Array data into an array of bytes using the indicated algorithm and key.
	func sign(_ digest: Digest, key: Key) -> [UInt8]? {
		let ptr = UnsafeRawBufferPointer(start: self, count: self.count)
		guard let newPtr = ptr.sign(digest, key: key) else {
			return nil
		}
		defer { newPtr.deallocate() }
		return newPtr.map { $0 }
	}
	/// Verify the array against the signature.
	/// Returns true if the signature is verified. Returns false otherwise.
	func verify(_ digest: Digest, signature: [UInt8], key: Key) -> Bool {
		let ptr = UnsafeRawBufferPointer(start: self, count: self.count)
		let sigPtr = UnsafeRawBufferPointer(start: signature, count: signature.count)
		return ptr.verify(digest, signature: sigPtr, key: key)
	}
	/// Decrypt this buffer using the indicated cipher, key an iv (initialization vector).
	func encrypt(_ cipher: Cipher, key: [UInt8], iv: [UInt8]) -> [UInt8]? {
		let sv = UnsafeRawBufferPointer(start: self, count: self.count)
		let keyv = UnsafeRawBufferPointer(start: key, count: key.count)
		let ivv = UnsafeRawBufferPointer(start: iv, count: iv.count)
		guard let v = cipher.encrypt(sv, key: keyv, iv: ivv) else {
			return nil
		}
		defer {
			v.deallocate()
		}
		return v.map { UInt8($0) }
	}
	/// Decrypt this buffer using the indicated cipher, key an iv (initialization vector).
	func decrypt(_ cipher: Cipher, key: [UInt8], iv: [UInt8]) -> [UInt8]? {
		let sv = UnsafeRawBufferPointer(start: self, count: self.count)
		let keyv = UnsafeRawBufferPointer(start: key, count: key.count)
		let ivv = UnsafeRawBufferPointer(start: iv, count: iv.count)
		guard let v = cipher.decrypt(sv, key: keyv, iv: ivv) else {
			return nil
		}
		defer {
			v.deallocate()
		}
		return v.map { UInt8($0) }
	}
	/// Encrypt this buffer using the indicated cipher, password, and salt.
	/// Resulting data is PEM encoded CMS format.
	func encrypt(_ cipher: Cipher,
	             password: [UInt8],
	             salt: [UInt8],
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> [UInt8]? {
		let sv = UnsafeRawBufferPointer(start: self, count: self.count)
		let pwv = UnsafeRawBufferPointer(start: password, count: password.count)
		let saltv = UnsafeRawBufferPointer(start: salt, count: salt.count)
		guard let v = sv.encrypt(cipher, password: pwv, salt: saltv, keyIterations: keyIterations, keyDigest: keyDigest) else {
			return nil
		}
		defer {
			v.deallocate()
		}
		return v.map { UInt8($0) }
	}
	/// Decrypt this PEM encoded CMS buffer using the indicated password and salt.
	func decrypt(_ cipher: Cipher,
	             password: [UInt8],
	             salt: [UInt8],
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> [UInt8]? {
		let sv = UnsafeRawBufferPointer(start: self, count: self.count)
		let pwv = UnsafeRawBufferPointer(start: password, count: password.count)
		let saltv = UnsafeRawBufferPointer(start: salt, count: salt.count)
		guard let v = sv.decrypt(cipher, password: pwv, salt: saltv, keyIterations: keyIterations, keyDigest: keyDigest) else {
			return nil
		}
		defer {
			v.deallocate()
		}
		return v.map { UInt8($0) }
	}
}

public extension UnsafeMutableRawBufferPointer {
	/// Allocate memory for `size` bytes with word alignment from the encryption library's
	///	random number generator.
	///
	/// - Postcondition: The memory is allocated and initialized to random bits.
	static func allocateRandom(count size: Int) -> UnsafeMutableRawBufferPointer? {
		let ret = UnsafeMutableRawBufferPointer.allocate(count: size)
		guard 1 == internal_RAND_bytes(into: ret) else {
			ret.deallocate()
			return nil
		}
		return ret
	}
	
	/// Initialize the buffer with random bytes.
	func initializeRandom() {
		_ = internal_RAND_bytes(into: self)
	}
}

public extension UnsafeRawBufferPointer {
	/// Allocate memory for `size` bytes with word alignment from the encryption library's
	///	random number generator.
	///
	/// - Postcondition: The memory is allocated and initialized to random bits.
	static func allocateRandom(count size: Int) -> UnsafeRawBufferPointer? {
		let ret = UnsafeMutableRawBufferPointer.allocate(count: size)
		guard 1 == internal_RAND_bytes(into: ret) else {
			ret.deallocate()
			return nil
		}
		return UnsafeRawBufferPointer(ret)
	}
	/// Encode the buffer using the indicated encoding.
	/// The return value must be deallocated by the caller.
	func encode(_ encoding: Encoding) -> UnsafeMutableRawBufferPointer? {
		return encoding.encodeBytes(self)
	}
	/// Decode the buffer using the indicated encoding.
	/// The return value must be deallocated by the caller.
	func decode(_ encoding: Encoding) -> UnsafeMutableRawBufferPointer? {
		return encoding.decodeBytes(self)
	}
	/// Digest the buffer using the indicated algorithm.
	/// The return value must be deallocated by the caller.
	func digest(_ digest: Digest) -> UnsafeMutableRawBufferPointer? {
		let filter = DigestFilter(digest)
		let chain = filter.chain(NullIO())
		do {
			_ = try chain.write(bytes: self)
			try chain.flush()
			let validLength = digest.length
			let ret = UnsafeMutableRawBufferPointer.allocate(count: validLength)
			guard try filter.get(ret) == validLength else {
				ret.deallocate()
				return nil
			}
			return ret
		} catch {
			return nil
		}
	}
	/// Sign the buffer using the indicated algorithm and key.
	/// The return value must be deallocated by the caller.
	func sign(_ digest: Digest, key: Key) -> UnsafeMutableRawBufferPointer? {
		return digest.sign(self, privateKey: key)
	}
	/// Verify the signature against the buffer.
	/// Returns true if the signature is verified. Returns false otherwise.
	func verify(_ digest: Digest, signature: UnsafeRawBufferPointer, key: Key) -> Bool {
		return digest.verify(self, signature: signature, publicKey: key)
	}
	/// Encrypt this buffer using the indicated cipher, key and iv (initialization vector).
	/// Returns a newly allocated buffer which must be freed by the caller.
	func encrypt(_ cipher: Cipher, key: UnsafeRawBufferPointer, iv: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		return cipher.encrypt(self, key: key, iv: iv)
	}
	/// Decrypt this buffer using the indicated cipher, key and iv (initialization vector).
	/// Returns a newly allocated buffer which must be freed by the caller.
	func decrypt(_ cipher: Cipher, key: UnsafeRawBufferPointer, iv: UnsafeRawBufferPointer) -> UnsafeMutableRawBufferPointer? {
		return cipher.decrypt(self, key: key, iv: iv)
	}
	/// Encrypt this buffer to PEM encoded CMS format using the indicated cipher, password, and salt.
	/// Returns a newly allocated buffer which must be freed by the caller.
	func encrypt(_ cipher: Cipher,
	             password: UnsafeRawBufferPointer,
	             salt: UnsafeRawBufferPointer,
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> UnsafeMutableRawBufferPointer? {
		return cipher.encrypt(self, password: password, salt: salt, keyIterations: keyIterations, keyDigest: keyDigest)
	}
	/// Decrypt this PEM encoded CMS buffer using the indicated password and salt.
	/// Returns a newly allocated buffer which must be freed by the caller.
	func decrypt(_ cipher: Cipher,
	             password: UnsafeRawBufferPointer,
	             salt: UnsafeRawBufferPointer,
	             keyIterations: Int = 2048,
	             keyDigest: Digest = .md5) -> UnsafeMutableRawBufferPointer? {
		return cipher.decrypt(self, password: password, salt: salt, keyIterations: keyIterations, keyDigest: keyDigest)
	}
}

extension UInt8 {
	init?(hexOne c1v: UInt8, hexTwo c2v: UInt8) {
		let capA: UInt8 = 65
		let capF: UInt8 = 70
		let lowA: UInt8 = 97
		let lowF: UInt8 = 102
		let zero: UInt8 = 48
		let nine: UInt8 = 57
		
		var newChar = UInt8(0)
		
		if c1v >= capA && c1v <= capF {
			newChar = c1v - capA + 10
		} else if c1v >= lowA && c1v <= lowF {
			newChar = c1v - lowA + 10
		} else if c1v >= zero && c1v <= nine {
			newChar = c1v - zero
		} else {
			return nil
		}
		
		newChar *= 16
		
		if c2v >= capA && c2v <= capF {
			newChar += c2v - capA + 10
		} else if c2v >= lowA && c2v <= lowF {
			newChar += c2v - lowA + 10
		} else if c2v >= zero && c2v <= nine {
			newChar += c2v - zero
		} else {
			return nil
		}
		self = newChar
	}
}

// A generalized wrapper around the Unicode codec operations.
struct UEncoding {
	// Return a String given a character generator.
	static func encode<D : UnicodeCodec, G : IteratorProtocol>(codec inCodec: D, generator: G) -> String where G.Element == D.CodeUnit {
		var encodedString = ""
		var finished: Bool = false
		var mutableDecoder = inCodec
		var mutableGenerator = generator
		repeat {
			let decodingResult = mutableDecoder.decode(&mutableGenerator)
			switch decodingResult {
			case .scalarValue(let char):
				encodedString.append(String(char))
			case .emptyInput:
				finished = true
			case .error:
				finished = true
			}
		} while !finished
		return encodedString
	}
}

// Utility wrapper permitting a UTF-8 character generator to encode a String. Also permits a String to be converted into a UTF-8 byte array.
struct UTF8Encoding {
	// Use a character generator to create a String.
	static func encode<G : IteratorProtocol>(generator gen: G) -> String where G.Element == UTF8.CodeUnit {
		return UEncoding.encode(codec: UTF8(), generator: gen)
	}
	// Use a character sequence to create a String.
	static func encode<S : Sequence>(bytes byts: S) -> String where S.Iterator.Element == UTF8.CodeUnit {
		return encode(generator: byts.makeIterator())
	}
	// Use a character sequence to create a String.
	static func encode(bytes byts: [UTF8.CodeUnit]) -> String {
		return encode(generator: UnsafeRawBufferPointer(start: UnsafeMutablePointer(mutating: byts), count: byts.count).makeIterator())
	}
	// Decode a String into an array of UInt8.
	static func decode(string str: String) -> Array<UInt8> {
		return [UInt8](str.utf8)
	}
}
