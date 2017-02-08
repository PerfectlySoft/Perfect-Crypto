//
//  Extensions.swift
//  PerfectCrypto
//
//  Created by Kyle Jessup on 2017-02-07.
//
//

extension String {
	init?(_ ptr: UnsafeRawBufferPointer?) {
		guard let ptr = ptr else {
			return nil
		}
		self = UTF8Encoding.encode(generator: ptr.makeIterator())
	}
}


/// This class permits an UnsafeMutablePointer to be used as a GeneratorType
private struct GenerateFromPointer<T> : IteratorProtocol {
	
	typealias Element = T
	
	var count = 0
	var pos = 0
	var from: UnsafeMutablePointer<T>
	
	/// Initialize given an UnsafeMutablePointer and the number of elements pointed to.
	init(from: UnsafeMutablePointer<T>, count: Int) {
		self.from = from
		self.count = count
	}
	
	/// Return the next element or nil if the sequence has been exhausted.
	mutating func next() -> Element? {
		guard count > 0 else {
			return nil
		}
		self.count -= 1
		let result = self.from[self.pos]
		self.pos += 1
		return result
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
		return encode(generator: GenerateFromPointer(from: UnsafeMutablePointer(mutating: byts), count: byts.count))
	}
	
	/// Decode a String into an array of UInt8.
	static func decode(string str: String) -> Array<UInt8> {
		return [UInt8](str.utf8)
	}
}
