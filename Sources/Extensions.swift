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

extension String {
	init?(_ ptr: UnsafeRawBufferPointer?) {
		guard let ptr = ptr else {
			return nil
		}
		self = UTF8Encoding.encode(generator: ptr.makeIterator())
	}
	
	func withBufferPointer<Result>(_ body: (UnsafeRawBufferPointer) throws -> Result) rethrows -> Result {
		let chars = [UInt8](self.utf8)
		let count = chars.count
		return try body(UnsafeRawBufferPointer(start: UnsafePointer(chars), count: count))
	}
	
	var decodeHex: [UInt8]? {
		let chars = Array(self.utf8)
		guard chars.count % 2 == 0 else {
			return nil
		}
		
		var ret = [UInt8]()
		for index in stride(from: chars.startIndex, to: chars.endIndex, by: 2) {
			guard let c = UInt8(hexOne: chars[index], hexTwo: chars[index+1]) else {
				return nil
			}
			ret.append(c)
		}
		return ret
	}
}

extension Collection where Self.Iterator.Element == UInt8 {
	var encodeHex: String {
		var s = ""
		for byte in self {
			let b = byte >> 4
			s.append(String(Character(UnicodeScalar(b > 9 ? b - 10 + 97 : b + 48))))
			let b2 = byte & 0x0F
			s.append(String(Character(UnicodeScalar(b2 > 9 ? b2 - 10 + 97 : b2 + 48))))
		}
		return s
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

/// A generalized wrapper around the Unicode codec operations.
struct UEncoding {
	
	/// Return a String given a character generator.
	static func encode<D : UnicodeCodec, G : IteratorProtocol>(codec inCodec: D, generator: G) -> String where G.Element == D.CodeUnit, G.Element == D.CodeUnit {
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
				/* ignore errors and unexpected values */
			case .error:
				finished = true
			}
		} while !finished
		return encodedString
	}
}

/// Utility wrapper permitting a UTF-8 character generator to encode a String. Also permits a String to be converted into a UTF-8 byte array.
struct UTF8Encoding {
	
	/// Use a character generator to create a String.
	static func encode<G : IteratorProtocol>(generator gen: G) -> String where G.Element == UTF8.CodeUnit {
		return UEncoding.encode(codec: UTF8(), generator: gen)
	}
	
	/// Use a character sequence to create a String.
	static func encode<S : Sequence>(bytes byts: S) -> String where S.Iterator.Element == UTF8.CodeUnit {
		return encode(generator: byts.makeIterator())
	}
	
	/// Use a character sequence to create a String.
	static func encode(bytes byts: [UTF8.CodeUnit]) -> String {
		return encode(generator: UnsafeRawBufferPointer(start: UnsafeMutablePointer(mutating: byts), count: byts.count).makeIterator())
	}
	
	/// Decode a String into an array of UInt8.
	static func decode(string str: String) -> Array<UInt8> {
		return [UInt8](str.utf8)
	}
}
