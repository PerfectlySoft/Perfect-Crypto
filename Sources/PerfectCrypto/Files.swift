//
//  Files.swift
//  PerfectCrypto
//
//  Created by Rockford Wei on 2018-01-22.
//  Copyright (C) 2018 PerfectlySoft, Inc.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2018 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//
//

import COpenSSL
import PerfectLib
import Foundation

class Digestor<T> {
  var _bufferSize: Int = 0
  var _szSignature: Int = 0
  let _context: UnsafeMutablePointer<T>
  var _constructor: (UnsafeMutablePointer<T>) -> Int32 = { _ in return 0}
  var _updator: (UnsafeMutablePointer<T>, UnsafeRawPointer, Int) -> Int32 = { _, _, _ in return 0}
  var _reducer: (UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<T>) -> Int32 = { _, _ in return 0}
  public init(_ context: UnsafeMutablePointer<T>!) {
    _context = context
  }

  public func sum(_ file: File) throws -> String {
    try file.open(.read)
    guard _bufferSize > 0,
      _szSignature > 0 else {
      throw CryptoError(code: -1, msg: "invalid parameters")
    }
    defer {
      file.close()
    }
    guard 1 == _constructor(_context) else {
      throw CryptoError(code: -2, msg: "context initialization failed")
    }
    var rd = 0
    repeat {
      let buf = try file.readSomeBytes(count: _bufferSize)
      rd = buf.count
      if rd > 0 {
        guard 1 == _updator(_context, buf, rd) else {
          throw CryptoError(code: -3, msg: "context cannot update")
        }
      }
    } while rd > 0
    var signature = UnsafeMutablePointer<UInt8>.allocate(capacity: _szSignature)
    defer {
      signature.deallocate(capacity: _szSignature)
    }
    guard 1 == _reducer(signature, _context) else {
      throw CryptoError(code: -4, msg: "context finalization fault")
    }
    let buf = UnsafeBufferPointer<UInt8>(start: signature, count: _szSignature)
    let array = Array(buf)
    guard let hex = array.encode(.hex),
      let str = String(validatingUTF8: hex) else {
        throw CryptoError(code: -5, msg: "hex encoding failed")
    }
    return str
  }
}

public extension File {

  /// Digest a file into a hex based signature
  /// - parameter algorithm: the algorithm of digest, currently implments: sha0/1/224/256/384/512,ripemd160,whirlpool, md4 and md5
  /// - parameter bufferSize: the file digesting buffer, which is subject to the OS. Default is 16k, can be larger or smaller.
  /// - returns: a heximal string represents the digest text
  /// - throws: CryptoError
  public func digest(_ algorithm: Digest, bufferSize: Int = 16384) throws -> String {
    switch algorithm {
    case .sha:
      var ctx = SHA_CTX()
      let dig = Digestor<SHA_CTX>(&ctx)
      dig._bufferSize = bufferSize
      dig._szSignature = Int(SHA_DIGEST_LENGTH)
      dig._constructor = SHA_Init
      dig._updator = SHA_Update
      dig._reducer = SHA_Final
      return try dig.sum(self)
    case .sha1:
      var ctx = SHA_CTX()
      let dig = Digestor<SHA_CTX>(&ctx)
      dig._bufferSize = bufferSize
      dig._szSignature = Int(SHA_DIGEST_LENGTH)
      dig._constructor = SHA1_Init
      dig._updator = SHA1_Update
      dig._reducer = SHA1_Final
      return try dig.sum(self)
    case .sha224:
      var ctx = SHA256_CTX()
      let dig = Digestor<SHA256_CTX>(&ctx)
      dig._bufferSize = bufferSize
      dig._szSignature = Int(SHA224_DIGEST_LENGTH)
      dig._constructor = SHA224_Init
      dig._updator = SHA224_Update
      dig._reducer = SHA224_Final
      return try dig.sum(self)
    case .sha256:
      var ctx = SHA256_CTX()
      let dig = Digestor<SHA256_CTX>(&ctx)
      dig._bufferSize = bufferSize
      dig._szSignature = Int(SHA256_DIGEST_LENGTH)
      dig._constructor = SHA256_Init
      dig._updator = SHA256_Update
      dig._reducer = SHA256_Final
      return try dig.sum(self)
    case .sha384:
      var ctx = SHA512_CTX()
      let dig = Digestor<SHA512_CTX>(&ctx)
      dig._bufferSize = bufferSize
      dig._szSignature = Int(SHA384_DIGEST_LENGTH)
      dig._constructor = SHA384_Init
      dig._updator = SHA384_Update
      dig._reducer = SHA384_Final
      return try dig.sum(self)
    case .sha512:
      var ctx = SHA512_CTX()
      let dig = Digestor<SHA512_CTX>(&ctx)
      dig._bufferSize = bufferSize
      dig._szSignature = Int(SHA512_DIGEST_LENGTH)
      dig._constructor = SHA512_Init
      dig._updator = SHA512_Update
      dig._reducer = SHA512_Final
      return try dig.sum(self)
    case .ripemd160:
      var ctx = RIPEMD160_CTX()
      let dig = Digestor<RIPEMD160_CTX>(&ctx)
      dig._bufferSize = bufferSize
      dig._szSignature = Int(RIPEMD160_DIGEST_LENGTH)
      dig._constructor = RIPEMD160_Init
      dig._updator = RIPEMD160_Update
      dig._reducer = RIPEMD160_Final
      return try dig.sum(self)
    case .whirlpool:
      var ctx = WHIRLPOOL_CTX()
      let dig = Digestor<WHIRLPOOL_CTX>(&ctx)
      dig._bufferSize = bufferSize
      dig._szSignature = Int(WHIRLPOOL_DIGEST_LENGTH)
      dig._constructor = WHIRLPOOL_Init
      dig._updator = WHIRLPOOL_Update
      dig._reducer = WHIRLPOOL_Final
      return try dig.sum(self)
    case .md4:
      var ctx = MD4_CTX()
      let dig = Digestor<MD4_CTX>(&ctx)
      dig._bufferSize = bufferSize
      dig._szSignature = Int(MD4_DIGEST_LENGTH)
      dig._constructor = MD4_Init
      dig._updator = MD4_Update
      dig._reducer = MD4_Final
      return try dig.sum(self)
    case .md5:
      var ctx = MD5_CTX()
      let dig = Digestor<MD5_CTX>(&ctx)
      dig._bufferSize = bufferSize
      dig._szSignature = Int(MD5_DIGEST_LENGTH)
      dig._constructor = MD5_Init
      dig._updator = MD5_Update
      dig._reducer = MD5_Final
      return try dig.sum(self)
    default:
      throw CryptoError(code: 0, msg: "unsupported")
    }
  }
}
