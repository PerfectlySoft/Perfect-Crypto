import XCTest
@testable import PerfectCrypto

class PerfectCryptoTests: XCTestCase {
	
	override func setUp() {
		_ = PerfectCrypto.isInitialized
	}
	
	func testInitialized() {
		XCTAssert(PerfectCrypto.isInitialized)
	}
	
	func testHexEncDec1() {
		let testStr = "Hello, world!"
		guard let hexBytes = Array(testStr.utf8).encode(.hex) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: hexBytes) == "48656c6c6f2c20776f726c6421")
		guard let unHex = hexBytes.decode(.hex) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: unHex) == testStr)
	}
	
	func test64EncDec1() {
		let testStr = "Hello, world!"
		guard let baseBytes = Array(testStr.utf8).encode(.base64) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: baseBytes) == "SGVsbG8sIHdvcmxkIQ==")
		guard let unHex = baseBytes.decode(.base64) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: unHex) == testStr)
	}
	
	func testHexEncDec2() {
		let testStr = "Hello, world!"
		guard let hexBytes = Array(testStr.utf8).encode(.hex) else {
			return XCTAssert(false)
		}
		guard let s = String(validatingUTF8: hexBytes) else {
			return XCTAssert(false)
		}
		XCTAssert(s == "48656c6c6f2c20776f726c6421")
		guard let unHex = s.decode(.hex) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: unHex) == testStr)
	}
	
	func test64EncDec2() {
		let testStr = "Hello, world!"
		guard let baseBytes = Array(testStr.utf8).encode(.base64) else {
			return XCTAssert(false)
		}
		guard let s = String(validatingUTF8: baseBytes) else {
			return XCTAssert(false)
		}
		XCTAssert(s == "SGVsbG8sIHdvcmxkIQ==")
		guard let unHex = s.decode(.base64) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: unHex) == testStr)
	}
	
	func testIOPair() {
		let testStr = "Hello, world!"
		let chars = [UInt8](testStr.utf8)
		let count = chars.count
		let ptr = UnsafeRawBufferPointer(start: UnsafePointer(chars), count: count)
		let pair = IOPair()
		let write = pair.first
		let read = pair.second
		do {
			try write.pair(with: read)
			_ = try write.write(bytes: ptr)
			try write.flush()
			let dest = UnsafeMutableRawBufferPointer.allocate(count: 1024)
			defer {
				dest.deallocate()
			}
			let result = try read.read(dest)
			XCTAssert(result == count)
		} catch {
			XCTAssert(false, "\(error)")
		}
	}
	
	func testBase64Filter1() {
		let testStr = "Hello, world!"
		let chars = [UInt8](testStr.utf8)
		let count = chars.count
		let ptr = UnsafeRawBufferPointer(start: UnsafePointer(chars), count: count)
		let chain = Base64Filter().chain(MemoryIO())
		do {
			XCTAssert(try chain.write(bytes: ptr) == count)
			let dest = UnsafeMutableRawBufferPointer.allocate(count: 1024)
			defer {
				dest.deallocate()
			}
			let result = try chain.flush().read(dest)
			
			XCTAssert(String(validatingUTF8: UnsafeRawBufferPointer(start: dest.baseAddress, count: result)) == testStr)
		} catch {
			XCTAssert(false, "\(error)")
		}
	}
	
	func testBase64Filter2() {
		let testStr = "Hello, world!"
		let testAnswer = "SGVsbG8sIHdvcmxkIQ=="
		let chars = [UInt8](testStr.utf8)
		let count = chars.count
		let ptr = UnsafeRawBufferPointer(start: UnsafePointer(chars), count: count)
		let chain = Base64Filter().chain(MemoryIO())
		do {
			XCTAssert("\(chain)" == "base64 encoding<->(memory buffer)")
			let wrote = try chain.write(bytes: ptr)
			XCTAssert(wrote == count)
			let result = try chain.flush().memory
			XCTAssert(result?.count == testAnswer.utf8.count)
			let resultString = String(validatingUTF8: result)
			XCTAssert(testAnswer == resultString)
		} catch {
			XCTAssert(false, "\(error)")
		}
	}
	
	func testDigest1() {
		let testStr = "Hello, world!"
		let testAnswer = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
		
		let dest = UnsafeMutableRawBufferPointer.allocate(count: 1024)
		defer {
			dest.deallocate()
		}
		
		do {
			let digest = DigestFilter(.sha256)
			_ = try testStr.withBufferPointer {
				try digest.chain(NullIO()).write(bytes: $0)
			}
			
			let resultLen = try digest.get(dest)
			let digestBytes = UnsafeRawBufferPointer(start: dest.baseAddress, count: resultLen)
			guard let hexString = digestBytes.encode(.hex) else {
				return XCTAssert(false)
			}
			defer {
				hexString.deallocate()
			}
			XCTAssert(testAnswer == String(validatingUTF8: UnsafeRawBufferPointer(hexString)), "\(hexString)")
		} catch {
			XCTAssert(false, "\(error)")
		}
	}
	
	func testDigest2() {
		let testStr = "Hello, world!"
		let testAnswer = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3"
		guard let enc = testStr.digest(.sha256)?.encode(.hex) else {
			return XCTAssert(false)
		}
		XCTAssert(String(validatingUTF8: enc) == testAnswer)
	}
	
	static var allTests : [(String, (PerfectCryptoTests) -> () throws -> Void)] {
		return [
			("testInitialized", testInitialized),
			("testIOPair", testIOPair),
			("testHexEncDec1", testHexEncDec1),
			("test64EncDec1", test64EncDec1),
			("testHexEncDec2", testHexEncDec2),
			("test64EncDec2", test64EncDec2),
			("testIOPair", testIOPair),
			("testBase64Filter1", testBase64Filter1),
			("testBase64Filter2", testBase64Filter2),
			("testDigest1", testDigest1),
		]
	}
}
