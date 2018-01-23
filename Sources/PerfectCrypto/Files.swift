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

public extension File {
  /// write a random binary file
  /// - parameter totalBytes: the expected size to generate
  /// - parameter bufferSize: the buffer size to apply in file writing
  /// - throws: CryptoError in case of exceptions.
  public func random(totalBytes: Int, bufferSize: Int = 16384) throws {
    let szbuf = bufferSize > 0 ? bufferSize : 16384
    guard totalBytes > 0 else {
      throw CryptoError(code: -1, msg: "invalid parameter")
    }
    self.delete()
    try self.open(.write)
    var size = 0
    var remain = totalBytes
    repeat {
      size = min(remain, szbuf)
      remain -= size
      let buf = Array<UInt8>(randomCount: size)
      try self.write(bytes: buf)
    } while remain > 0
    self.close()
    guard self.size == totalBytes else {
      throw CryptoError(code: -2, msg: "unexpected size \(totalBytes) != \(self.size)")
    }
  }

  /// Digest a file into a hex based signature
  /// - parameter digest: the algorithm of digest
  /// - parameter bufferSize: the file digesting buffer, which is subject to the OS. Default is 16k, can be larger or smaller.
  /// - returns: digest bytes
  /// - throws: CryptoError
  public func digest(_ digest: Digest, bufferSize: Int = 16384) throws -> [UInt8] {
    let filter = DigestFilter(digest)
    let chain = filter.chain(NullIO())
    try self.open()
    while let buf = try? self.readSomeBytes(count: bufferSize) {
      let rd = try buf.withUnsafeBytes { pointer in
        return try chain.write(bytes: pointer)
      }
      if rd < 1 { break }
    }
    self.close()
    try chain.flush()
    let validLength = digest.length
    let ret = UnsafeMutableRawBufferPointer.allocate(count: validLength)
    guard try filter.get(ret) == validLength else {
      ret.deallocate()
      return []
    }
    return ret.map { $0 }
  }

  /// encode a file to another
  /// - parameter encoding: encoding method
  /// - parameter to: file to save
  /// - parameter bufferSize: size of buffer to perform the encoding
  /// - parameter requiresNewLines: (base64) if needs line breaks, default is true
  /// - throws: CryptoError
  public func encode(_ encoding: EncodingS, to: File, bufferSize: Int = 16384, requiresNewLines: Bool = true) throws {
    guard encoding == .base64 else {
      throw CryptoError(code: -1, msg: "unsupported")
    }
    let filter = Base64Filter(requireNewLines: requiresNewLines)
    let chain = filter.chain(FileIO(name: to.path, mode: "wb"))
    try self.open()
    while let buf = try? self.readSomeBytes(count: bufferSize) {
      let rd = try buf.withUnsafeBytes { pointer in
        return try chain.write(bytes: pointer)
      }
      if rd < 1 { break }
    }
    try chain.flush()
    self.close()
  }
}
