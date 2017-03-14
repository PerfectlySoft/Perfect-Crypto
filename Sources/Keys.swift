//
//  Keys.swift
//  PerfectCrypto
//
//  Created by Kyle Jessup on 2017-02-13.
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

import COpenSSL
import PerfectLib

public struct KeyError: Error {
	public let msg: String
	init(_ msg: String) {
		self.msg = msg
	}
}

public class Key {
	let pkey: UnsafeMutablePointer<EVP_PKEY>?
	deinit {
		EVP_PKEY_free(pkey)
	}
	init(_ key: UnsafeMutablePointer<EVP_PKEY>?) {
		self.pkey = key
	}
}

public class HMACKey: Key {
	public init(_ key: String) {
		super.init(key.withBufferPointer {
			b in
			return EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nil,
			                            b.baseAddress?.assumingMemoryBound(to: UInt8.self),
			                            Int32(b.count))
		})
	}
	
	public init(_ key: [UInt8]) {
		super.init(EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nil,
			                            UnsafePointer(key),
			                            Int32(key.count)))
	}
}

public class PEMKey: Key {
	public convenience init(pemPath: String) throws {
		try self.init(source: try File(pemPath).readString())
	}
	
	public init(source original: String) throws {
		let source = PEMKey.cleanSource(original)
		var f = MemoryIO(source)
		var kp: UnsafeMutablePointer<EVP_PKEY>? = nil
		if nil == PEM_read_bio_PrivateKey(f.bio, &kp, nil, nil) {
			f = MemoryIO(source)
			guard nil != PEM_read_bio_PUBKEY(f.bio, &kp, nil, nil) else {
				throw KeyError("No public or private key could be read.")
			}
		}
		super.init(kp)
	}
	
	static func cleanSource(_ source: String) -> String {
		var inHeader = true
		let charMax = 64
		var charCount = 0
		var accum = ""
		source.characters.forEach {
			c in
			switch c {
			case "\r", "\n", "\r\n":
				if inHeader {
					inHeader = false
					accum += "\n"
					charCount = 0
				}
			case "-":
				if !inHeader {
					accum += "\n"
					charCount = 0
				}
				inHeader = true
				accum += "-"
				charCount += 1
			default:
				if charCount == charMax {
					accum += "\n"
					charCount = 0
				} else {
					charCount += 1
				}
				accum += String(c)
			}
		}
		if inHeader {
			accum += "\n"
		}
		return accum
	}
}
