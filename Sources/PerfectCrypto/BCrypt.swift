import bcrypt

open class BCrypt {

  public enum SaltPrefixType:String {
    case _2A = "2a"
    case _2B = "2b"
  }

  public enum Exception: Error {
    case InvalidRounds
    case Unsupported
  }
  public static func GenSalt(_ prefix: SaltPrefixType = ._2B,
                             rounds: Int = 12) throws -> String {
    guard rounds > 3 && rounds < 32 else {
      throw Exception.InvalidRounds
    }
    throw Exception.Unsupported
  }
}
