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
		let testStr = "Räksmörgåsen"
		guard let baseBytes = Array(testStr.utf8).encode(.base64) else {
			return XCTAssert(false)
		}
		guard let s = String(validatingUTF8: baseBytes) else {
			return XCTAssert(false)
		}
		XCTAssert(s == "UsOka3Ntw7ZyZ8Olc2Vu")
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
		XCTAssert(baseStr == "8J-koSBSw6Rrc23DtnJnw6VzZW4", "\(String(describing: baseStr))")
		guard let unHex = baseBytes.decode(.base64url) else {
			return XCTAssert(false)
		}
		let unhexed = String(validatingUTF8: unHex)
		XCTAssert(unhexed == testStr, "\(String(describing: unhexed))")
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
		
		do {
			let testStr = "Hello, world!"
			if let digestBytes = testStr.digest(.sha256),
				let hexBytes = digestBytes.encode(.hex),
				let hexBytesStr = String(validatingUTF8: hexBytes) {
				print(hexBytesStr)
			}
		}
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
	
	func testJWTVerify() {
		let tstJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
		let secret = "secret"
		let name = "John Doe"
		guard let jwt = JWTVerifier(tstJwt) else {
			return XCTAssert(false)
		}
		do {
			try jwt.verify(algo: .hs256, key: secret)
			
			let fndName = jwt.payload["name"] as? String
			XCTAssert(name == fndName!)
		} catch {
			XCTAssert(false, "\(error)")
		}
	}
	
	func testJWTCreate1() {
		let tstPayload = ["sub": "1234567890", "name": "John Doe", "admin": true] as [String : Any]
		let secret = "secret"
		let name = "John Doe"
		for _ in 0..<30 {
		  guard let jwt1 = JWTCreator(payload: tstPayload) else {
			  return XCTAssert(false)
		  }
		  do {
			  let token = try jwt1.sign(alg: .hs256, key: secret)
			  
			  guard let jwt = JWTVerifier(token) else {
				  return XCTAssert(false)
			  }
			  try jwt.verify(algo: .hs256, key: HMACKey(secret))
				  
			  let fndName = jwt.payload["name"] as? String
			  XCTAssert(name == fndName!)
		  } catch {
			  XCTAssert(false, "\(error)")
		  }
		}
	}
	
	func testJWTCreate2() {
		let tstPayload = ["sub": "1234567890", "name": "John Doe", "admin": true] as [String : Any]
		let name = "John Doe"
		let pubKey = "-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n-----END PUBLIC KEY-----\n"
		let privKey = "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQABAoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5CpuGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0KSu5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aPFaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n-----END RSA PRIVATE KEY-----\n"
		for _ in 0..<30 {
		  guard let jwt1 = JWTCreator(payload: tstPayload) else {
			  return XCTAssert(false)
		  }
		  do {
			  let key = try PEMKey(source: privKey)
			  let token = try jwt1.sign(alg: .rs256, key: key)
			  guard let jwt = JWTVerifier(token) else {
				  return XCTAssert(false)
			  }
			  let key2 = try PEMKey(source: pubKey)
			  try jwt.verify(algo: .rs256, key: key2)			
			  let fndName = jwt.payload["name"] as? String
			  XCTAssert(name == fndName!)
		  } catch {
			  XCTAssert(false, "\(error)")
		  }
		}
	}
	
	func testJWTCreate3() {
		let tstPayload = ["sub": "1234567890", "name": "John Doe", "admin": true] as [String : Any]
		let name = "John Doe"
		let pubKey = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENyTiyHJTNSQU3UqvzGxKe9ztD08SeBKWRfdvFi5Dp3hGXTgQE3Hb6v0jHZV62R0T1Uu4b+R3IZV6DeozO7JpSQ==\n-----END PUBLIC KEY-----"
		let privKey = "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgW3Yv7y/niwo3xaG/Hzq8s+Jnil0jnsMCguCeKKTxG3OgCgYIKoZIzj0DAQehRANCAAQ3JOLIclM1JBTdSq/MbEp73O0PTxJ4EpZF928WLkOneEZdOBATcdvq/SMdlXrZHRPVS7hv5HchlXoN6jM7smlJ\n-----END PRIVATE KEY-----"
		for _ in 0..<30 {
		  guard let jwt1 = JWTCreator(payload: tstPayload) else {
			  return XCTAssert(false)
		  }
		  do {
			  let key = try PEMKey(source: privKey)
			  let token = try jwt1.sign(alg: .es256, key: key)
			  guard let jwt = JWTVerifier(token) else {
				  return XCTAssert(false)
			  }
			  let key2 = try PEMKey(source: pubKey)
			  try jwt.verify(algo: .es256, key: key2)
			  let fndName = jwt.payload["name"] as? String
			  XCTAssert(name == fndName!)
		  } catch {
			  XCTAssert(false, "\(error)")
		  }
		}
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
			("testCipher2", testCipher2),
			("testJWTCreate1", testJWTCreate1),
			("testJWTCreate2", testJWTCreate2),
		]
	}
}
