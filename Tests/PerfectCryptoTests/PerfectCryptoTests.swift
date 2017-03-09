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
		guard let hexBytes = testStr.encode(.hex) else {
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
	
	func test64EncDec3() {
		let testStr = "🤡 Räksmörgåsen"
		guard let baseBytes = Array(testStr.utf8).encode(.base64url) else {
			return XCTAssert(false)
		}
		let baseStr = String(validatingUTF8: baseBytes)
		XCTAssert(baseStr == "8J-koSBSw6Rrc23DtnJnw6VzZW4", "\(baseStr)")
		guard let unHex = baseBytes.decode(.base64url) else {
			return XCTAssert(false)
		}
		let unhexed = String(validatingUTF8: unHex)
		XCTAssert(unhexed == testStr, "\(unhexed)")
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
	
	func testCipherSizes() {
		let algo = Cipher.des_ede3_cbc
		let bs = algo.blockSize
		let kl = algo.keyLength
		let il = algo.ivLength
		
		XCTAssert(bs == 8)
		XCTAssert(kl == 24)
		XCTAssert(il == 8)
	}
	
	func testRandomBuffer1() {
		guard let buff = UnsafeMutableRawBufferPointer.allocateRandom(count: 2048) else {
			return XCTAssert(false)
		}
		defer {
			buff.deallocate()
		}
		XCTAssert(buff.count == 2048)
		
		guard let enc = UnsafeRawBufferPointer(buff).encode(.hex) else {
			return XCTAssert(false)
		}
		defer {
			enc.deallocate()
		}
//		print("\(String(validatingUTF8: UnsafeRawBufferPointer(enc)))")
	}
	
	func testRandomBuffer2() {
		let buff = [UInt8](randomCount: 2048)
		let buff2 = [UInt8](randomCount: 2048)
		
		XCTAssert(buff != buff2)
		
//		guard let hexd = buff.encode(.hex) else {
//			return XCTAssert(false)
//		}
//		print("\(String(validatingUTF8: hexd))")
	}
	
	func testCipher1() {
		let cipher = Cipher.aes_256_cbc
		guard let random = UnsafeRawBufferPointer.allocateRandom(count: 2048),
			  let key = UnsafeRawBufferPointer.allocateRandom(count: cipher.keyLength),
			  let iv = UnsafeRawBufferPointer.allocateRandom(count: cipher.ivLength) else {
			return XCTAssert(false)
		}
		defer {
			random.deallocate()
			key.deallocate()
			iv.deallocate()
		}
		
		guard let encrypted = random.encrypt(cipher, key: key, iv: iv) else {
			return XCTAssert(false)
		}
		defer {
			encrypted.deallocate()
		}
		
		let encryptedRaw = UnsafeRawBufferPointer(encrypted)
		guard let decrypted = encryptedRaw.decrypt(cipher, key: key, iv: iv) else {
			return XCTAssert(false)
		}
		defer {
			decrypted.deallocate()
		}
		
		XCTAssert(decrypted.count == random.count)
		for (a, b) in zip(decrypted, random) {
			XCTAssert(a == b)
		}
	}
	
	func testCipher2() {
		let cipher = Cipher.aes_256_cbc
		let random = [UInt8](randomCount: 2048)
		let key = [UInt8](randomCount: cipher.keyLength)
		let iv = [UInt8](randomCount: cipher.ivLength)
		guard let encrypted = random.encrypt(cipher, key: key, iv: iv) else {
			return XCTAssert(false)
		}
		guard let decrypted = encrypted.decrypt(cipher, key: key, iv: iv) else {
			return XCTAssert(false)
		}
		XCTAssert(decrypted.count == random.count)
		for (a, b) in zip(decrypted, random) {
			XCTAssert(a == b)
		}
	}
	
	func testKeyGen1() {
		
	}
	
	func testKeyRead1() {
		
	}
	
	static var allTests : [(String, (PerfectCryptoTests) -> () throws -> Void)] {
		return [
			("testInitialized", testInitialized),
			("testIOPair", testIOPair),
			("testHexEncDec1", testHexEncDec1),
			("test64EncDec1", test64EncDec1),
			("test64EncDec3", test64EncDec3),
			("testHexEncDec2", testHexEncDec2),
			("test64EncDec2", test64EncDec2),
			("testIOPair", testIOPair),
			("testBase64Filter1", testBase64Filter1),
			("testBase64Filter2", testBase64Filter2),
			("testDigest1", testDigest1),
			("testDigest2", testDigest2),
			("testCipherSizes", testCipherSizes),
			("testRandomBuffer1", testRandomBuffer1),
			("testRandomBuffer2", testRandomBuffer2),
			("testCipher1", testCipher1),
			("testCipher2", testCipher2)
		]
	}
}
