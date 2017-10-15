import bcrypt

open class BCrypt {

  public enum SaltPrefixType:String {
    case _2A = "2a"
    case _2B = "2b"
  }

  public enum Exception: Error {
    case InvalidRounds
    case RandomAllocationFault
    case UTF8Fault
    case Unsupported
    case InvalidSalt
  }
  public static func GenSalt(_ prefix: SaltPrefixType = ._2B,
                             rounds: Int = 12) throws -> String {
    guard rounds > 3 && rounds < 32 else {
      throw Exception.InvalidRounds
    }
    guard let saltBuf = UnsafeRawBufferPointer.allocateRandom(count: 16),
      let salt = saltBuf.baseAddress?.assumingMemoryBound(to: UInt8.self)
      else {
      throw Exception.RandomAllocationFault
    }
    defer { saltBuf.deallocate() }
    let size = 30
    let outputPointer = UnsafeMutablePointer<Int8>.allocate(capacity: size)
    defer { outputPointer.deallocate(capacity: size) }
    _ = encode_base64(outputPointer, salt, 16)
    guard let output = String(validatingUTF8: outputPointer) else {
      throw Exception.RandomAllocationFault
    }
    let rnd = String(format: "%2.2u", rounds)
    return "$" + prefix.rawValue +  "$" + rnd + "$" + output
  }

  public static func Hash(_ password: String, salt: String) throws -> String {
    let size = 128
    let hashed = UnsafeMutablePointer<Int8>.allocate(capacity: size)
    defer { hashed.deallocate(capacity: size) }
    guard 0 == bcrypt_hashpass(password, salt, hashed, size) else {
      throw Exception.InvalidSalt
    }
    guard let ret = (salt.withCString { pSalt -> String? in
      memcpy(hashed, pSalt, 4)
      return String(validatingUTF8: hashed)
    }) else { throw Exception.UTF8Fault }
    return ret
  }
  #if os(Linux)
  public static func Check(_ password: String, hashed: String) -> Bool {
    do {
      let ret = try Hash(password, salt: hashed)
      guard ret.count == hashed.count else {
        return false
      }
      return 0 == timingsafe_bcmp(ret, hashed, ret.count)
    }catch {
      return false
    }
  }
  #else
  @available(OSX 10.12.1, *)
  public static func Check(_ password: String, hashed: String) -> Bool {
    do {
      let ret = try Hash(password, salt: hashed)
      guard ret.count == hashed.count else {
        return false
      }
      return 0 == timingsafe_bcmp(ret, hashed, ret.count)
    }catch {
      return false
    }
  }
  #endif
}
