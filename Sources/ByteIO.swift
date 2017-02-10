//
//  ByteIO.swift
//  PerfectCrypto
//
//  Created by Kyle Jessup on 2017-02-07.
//	Copyright (C) 2017 PerfectlySoft, Inc.
//
//===----------------------------------------------------------------------===//
//
// This source file is part of the Perfect.org open source project
//
// Copyright (c) 2015 - 2017 PerfectlySoft Inc. and the Perfect project authors
// Licensed under Apache License v2.0
//
// See http://perfect.org/licensing.html for license information
//
//===----------------------------------------------------------------------===//
//
//

import COpenSSL
#if os(Linux)
	import SwiftGlibc
#else
	import Darwin
#endif

// TODO: SSLFilter
// it needs many options to configure it

public protocol ByteIO {
	
}

public protocol ByteSink: ByteIO {
	func put(string: UnsafePointer<Int8>) throws
	func write(bytes: UnsafeRawBufferPointer) throws -> Int
}

public protocol ByteSource: ByteIO {
	func read(_ bytes: UnsafeMutableRawBufferPointer) throws -> Int
	func get(_ bytes: UnsafeMutableRawBufferPointer) throws -> Int
}

public protocol ByteFilter: ByteIO {
	
}

typealias BIOPointer = UnsafeMutablePointer<BIO>?

public class ByteIOBase: CustomStringConvertible {
	var bio: BIOPointer
	var head: BIOPointer
	var prev: ByteIOBase?
	
	fileprivate init(bio: BIOPointer) {
		self.bio = bio
		self.head = bio
		self.prev = nil
	}
	
	fileprivate init(method: UnsafeMutablePointer<BIO_METHOD>?) {
		let bio = BIO_new(method)
		self.bio = bio
		self.head = bio
		self.prev = nil
	}
	
	deinit {
		if let bio = bio {
			BIO_free(bio)
			self.bio = nil
			self.head = nil
			self.prev = nil
		}
	}
	
	public var description: String {
		var ret = ""
		var ptr = head
		while let p = ptr {
			if !ret.isEmpty {
				ret.append("<->")
			}
			if p == bio {
				ret.append("(\(String(validatingUTF8: BIO_method_name(p)) ?? "?"))")
			} else {
				ret.append("\(String(validatingUTF8: BIO_method_name(p)) ?? "?")")
			}
			ptr = BIO_next(p)
		}
		return ret
	}
	
	fileprivate var streamName: String? {
		return String(validatingUTF8: BIO_method_name(bio))
	}
	
	private func clear() {
		self.bio = nil
		self.prev?.clear()
		self.prev = nil
	}
	
	public func close() {
		BIO_free_all(head)
		clear()
	}
	
	@discardableResult
	public func reset() -> Self {
		BIO_ctrl(head, BIO_CTRL_RESET, 0, nil)
		return self
	}
	
	@discardableResult
	public func flush() throws -> Self {
		try checkedResult(BIO_ctrl(head, BIO_CTRL_FLUSH, 0, nil))
		return self
	}
	
	public var eof: Bool {
		return 1 == BIO_ctrl(head, BIO_CTRL_EOF, 0, nil)
	}
	
	public var readPending: Int {
		return BIO_ctrl_pending(head)
	}
	
	public var writePending: Int {
		return BIO_ctrl_wpending(head)
	}
	
	public func setNonBlocking() {
		BIO_ctrl(bio, BIO_C_SET_NBIO, 1, nil)
	}
	
	@discardableResult
	public func chain<T: ByteIOBase>(_ next: T) -> T {
		next.prev = self
		next.head = self.head
		BIO_push(self.bio, next.bio)
		return next
	}
	
	public func pair(with: ByteIOBase, thisWriteBuffer: Int = 0, thatWriteBuffer: Int = 0) throws {
		try checkedResult(BIO_ctrl(bio, BIO_C_SET_WRITE_BUF_SIZE, thisWriteBuffer, nil))
		try checkedResult(BIO_ctrl(with.bio, BIO_C_SET_WRITE_BUF_SIZE, thatWriteBuffer, nil))
		try checkedResult(BIO_ctrl(bio, BIO_C_MAKE_BIO_PAIR, 0, with.bio))
	}
	
	@discardableResult
	public func detach() -> Self {
		BIO_pop(bio)
		head = bio
		prev = nil
		return self
	}
	
	@discardableResult
	func checkedResult(_ result: Int) throws -> Int {
		guard result > -1 else {
			try CryptoError.throwOpenSSLError()
		}
		return result
	}
	
	@discardableResult
	func checkedResult(_ result: Int32) throws -> Int {
		return try checkedResult(Int(result))
	}
}

extension ByteSink where Self: ByteIOBase {
	public func put(string: UnsafePointer<Int8>) throws {
		try checkedResult(Int(BIO_puts(head, string)))
	}
	
	public func write(bytes: UnsafeRawBufferPointer) throws -> Int {
		return try checkedResult(Int(BIO_write(head, bytes.baseAddress, Int32(bytes.count))))
	}
}

extension ByteSource where Self: ByteIOBase {
	public func read(_ bytes: UnsafeMutableRawBufferPointer) throws -> Int {
		let result = try checkedResult(BIO_read(head, bytes.baseAddress, Int32(bytes.count)))
		return result
	}
	
	public func get(_ bytes: UnsafeMutableRawBufferPointer) throws -> Int {
		let result = try checkedResult(BIO_gets(head, bytes.baseAddress?.assumingMemoryBound(to: Int8.self), Int32(bytes.count-1)))
		bytes[result] = 0
		return result
	}
}

public class GenericIO: ByteIOBase, ByteSink, ByteSource {
	public init() {
		super.init(method: BIO_s_bio())
	}
	override init(bio: BIOPointer) {
		super.init(bio: bio)
	}
}

public class IOPair {
	public let first: GenericIO
	public let second: GenericIO
	
	public init(firstWriteBuffer: Int = 0, secondWriteBuffer: Int = 0) {
		var fPtr: BIOPointer = nil
		var sPtr: BIOPointer = nil
		BIO_new_bio_pair(&fPtr, firstWriteBuffer, &sPtr, secondWriteBuffer)
		self.first = GenericIO(bio: fPtr)
		self.second = GenericIO(bio: sPtr)
	}
}

public class MemoryIO: ByteIOBase, ByteSink, ByteSource {
	var memory: UnsafeRawBufferPointer? {
		var m: UnsafePointer<Int8>? = nil
		let count = BIO_ctrl(bio, BIO_CTRL_INFO, 0, &m)
		guard let mm = m else {
			return nil
		}
		return UnsafeRawBufferPointer(start: mm, count: count)
	}
	public init() {
		super.init(method: BIO_s_mem())
	}
	public convenience init(allocate count: Int) {
		self.init()
		let mem = BUF_MEM_new()
		BUF_MEM_grow(mem, count)
		BIO_ctrl(bio, BIO_C_SET_BUF_MEM, Int(BIO_CLOSE), UnsafeMutableRawPointer(mutating: mem))
	}
	public init(_ pointer: UnsafeRawBufferPointer) {
		super.init(bio: BIO_new_mem_buf(pointer.baseAddress, Int32(pointer.count)))
	}
	public convenience init(copying: UnsafeRawBufferPointer) {
		self.init()
		let mem = BUF_MEM_new()
		BUF_MEM_grow(mem, copying.count)
		if let data = mem?.pointee.data, let baseAddress = copying.baseAddress {
			memcpy(data, baseAddress, copying.count)
		}
		BIO_ctrl(bio, BIO_C_SET_BUF_MEM, Int(BIO_CLOSE), UnsafeMutableRawPointer(mutating: mem))
	}
	public convenience init(_ string: String) {
		let chars = [UInt8](string.utf8)
		let count = chars.count
		self.init(copying: UnsafeRawBufferPointer(start: UnsafePointer(chars), count: count))
	}
}

public class FileIO: ByteIOBase, ByteSink, ByteSource {
	public init(name: String, mode: String) {
		super.init(bio: BIO_new_file(name, mode))
	}
	public init(file: Int, close: Bool) {
		super.init(bio: BIO_new_fd(Int32(file), close ? BIO_CLOSE : BIO_NOCLOSE))
	}
	public init(socket: Int, close: Bool) {
		super.init(bio: BIO_new_socket(Int32(socket), close ? BIO_CLOSE : BIO_NOCLOSE))
	}
}

public class FileIOStdin: ByteIOBase, ByteSource {
	public init() {
		super.init(bio: BIO_new_fp(stdin, BIO_NOCLOSE))
	}
}

public class FileIOStdout: ByteIOBase, ByteSink {
	public init() {
		super.init(bio: BIO_new_fp(stdout, BIO_NOCLOSE))
	}
}

public class FileIOStderr: ByteIOBase, ByteSink {
	public init() {
		super.init(bio: BIO_new_fp(stderr, BIO_NOCLOSE))
	}
}

public class NullIO: ByteIOBase, ByteSink, ByteSource {
	public init() {
		super.init(method: BIO_s_null())
	}
}

public class AcceptIO: ByteIOBase, ByteSource, ByteSink {
	/// name is "host:port"
	public init(name: String) {
		super.init(bio: BIO_new_accept(name))
		BIO_ctrl(bio, BIO_C_SET_BIND_MODE, Int(BIO_BIND_REUSEADDR), nil)
	}
	
	public func listen() throws {
		let result = BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, nil)
		guard result == 1 else {
			try checkedResult(result)
			return
		}
	}
	
	public func accept() throws {
		let result = BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, nil)
		guard result == 1 else {
			try checkedResult(result)
			return
		}
	}
	
	public func setNonBlockingAccept() {
		var p: UnsafePointer<Int8>? = nil
		// does not matter what p is, just needs to be non-nil
		BIO_ctrl(bio, BIO_C_SET_ACCEPT, 1, &p)
	}
}

public class ConnectIO: ByteIOBase, ByteSource, ByteSink {
	public init(name: String) {
		super.init(bio: BIO_new_connect(name))
	}
	
	public func connect() throws {
		let result = BIO_ctrl(bio, BIO_C_DO_STATE_MACHINE, 0, nil)
		guard result == 1 else {
			try checkedResult(result)
			return
		}
	}
}

public class Base64Filter: ByteIOBase {
	public init(requireNewLines: Bool = false) {
		super.init(bio: BIO_new(BIO_f_base64()))
		if !requireNewLines {
			BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL)
		}
	}
}

public class BufferFilter: ByteIOBase {
	public static let minimumBufferSize = 4096
	public init(bufferSize: Int = 0) {
		super.init(bio: BIO_new(BIO_f_buffer()))
		if bufferSize > BufferFilter.minimumBufferSize {
			BIO_ctrl(bio, BIO_C_SET_BUFF_SIZE, bufferSize, nil)
		}
	}
}

public class DigestFilter: ByteIOBase, ByteSource {
	public init(_ digest: Digest) {
		super.init(method: BIO_f_md())
		let p = digest.evp
		BIO_ctrl(bio, BIO_C_SET_MD, 1, UnsafeMutableRawPointer(mutating: p))
	}
}

public class CipherFilter: ByteIOBase {
	public init(_ cipher: Cipher, key: UnsafePointer<UInt8>, iv: UnsafePointer<UInt8>, encrypting: Bool) {
		super.init(bio: BIO_new(BIO_f_cipher()))
		BIO_set_cipher(bio, cipher.evp, key, iv, encrypting ? 1 : 0)
	}
	
	public func ensureDecryptSuccess() throws {
		try checkedResult(BIO_ctrl(bio, BIO_C_GET_CIPHER_STATUS, 0, nil))
	}
}

/*
BIO_s_accept(3)
BIO_s_bio(3)
BIO_s_connect(3)
BIO_s_fd(3)
BIO_s_file(3)
BIO_s_mem(3)
BIO_s_null(3)
BIO_s_socket(3)
*/

