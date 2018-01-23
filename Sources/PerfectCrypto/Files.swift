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

  public func encode(_ encoding: EncodingS, to: File, bufferSize: Int = 16384) throws {
    guard encoding == .base64 else {
      throw CryptoError(code: -1, msg: "unsupported")
    }
    guard let b64 = BIO_new(BIO_f_base64()) else {
      throw CryptoError(code: -2, msg: "byte io fault")
    }
    guard let source = fopen(self.path, "rb"),
      let target = fopen(to.path, "wb"),
      let bio = BIO_new_fp(target, BIO_NOCLOSE) else {
      throw CryptoError(code: -3, msg: "invalid parameter")
    }
    _ = BIO_push(b64, bio)
    var rd = 0
    var wd = Int32(0)
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
    defer {
      buffer.deallocate(capacity: bufferSize)
    }
    repeat {
      buffer.initialize(to: 0)
      rd = fread(buffer, 1, bufferSize, source)
      if rd > 0 {
        wd = BIO_write(b64, buffer, Int32(rd))
      }
    } while rd > 0 && wd > 0
    _ = BIO_ctrl(b64,BIO_CTRL_FLUSH, 0, nil)
    BIO_free_all(b64)
    fclose(source)
    fclose(target)
  }

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
  /// - parameter digest: the algorithm of digest, currently implments: sha0/1/224/256/384/512,ripemd160,whirlpool, md4 and md5
  /// - parameter bufferSize: the file digesting buffer, which is subject to the OS. Default is 16k, can be larger or smaller.
  /// - returns: digest bytes
  /// - throws: CryptoError
  public func digest(_ digest: Digest, bufferSize: Int = 16384) throws -> [UInt8] {
    let filter = DigestFilter(digest)
    let chain = filter.chain(NullIO())
    let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: bufferSize)
    defer {
      buffer.deallocate(capacity: bufferSize)
    }
    guard
      let source = fopen(self.path, "rb")
      else {
        throw CryptoError(code: -1, msg: "invalid parameter")
    }
    var rd = 0
    var wd = 0
    repeat {
      buffer.initialize(to: 0)
      rd = fread(buffer, 1, bufferSize, source)
      if rd > 0 {
        let raw = UnsafeRawBufferPointer(start: buffer, count: rd)
        wd = try chain.write(bytes: raw)
      }
    } while rd > 0 && wd > 0
    try chain.flush()
    let validLength = digest.length
    let ret = UnsafeMutableRawBufferPointer.allocate(count: validLength)
    guard try filter.get(ret) == validLength else {
      ret.deallocate()
      return []
    }
    return ret.map { $0 }
  }
}
