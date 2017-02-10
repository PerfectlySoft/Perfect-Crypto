import XCTest
@testable import PerfectCrypto

class PerfectCryptoTests: XCTestCase {
	
	override func setUp() {
		_ = PerfectCrypto.isInitialized
	}
	
	func testInitialized() {
		XCTAssert(PerfectCrypto.isInitialized)
	}
	
	func testHexEncDec() {
		let testStr = "Hello, world!"
		let hexStr = testStr.withBufferPointer { $0.encodeHex }
		XCTAssert(hexStr == "48656c6c6f2c20776f726c6421")
		guard let unHex = hexStr.decodeHex else {
			return XCTAssert(false)
		}
		XCTAssert(unHex == Array(testStr.utf8))
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
			
			XCTAssert(String(UnsafeRawBufferPointer(start: dest.baseAddress, count: result)) == testStr)
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
			let resultString = String(result)
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
			let hexString = digestBytes.encodeHex
			XCTAssert(testAnswer == hexString, "\(hexString)")
		} catch {
			XCTAssert(false, "\(error)")
		}
	}
	
	static var allTests : [(String, (PerfectCryptoTests) -> () throws -> Void)] {
		return [
			("testInitialized", testInitialized),
			("testIOPair", testIOPair),
			("testBase64Filter1", testBase64Filter1),
			("testBase64Filter2", testBase64Filter2),
			("testDigest1", testDigest1),
		]
	}
}
