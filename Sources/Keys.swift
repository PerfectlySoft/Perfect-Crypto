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
// WIP
//public enum KeyType {
//	case rsa, dsa, dh
//}
//

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
	public init(pemPath: String) {
		var f = FileIO(name: pemPath, mode: "r")
		var kp: UnsafeMutablePointer<EVP_PKEY>? = nil
		if nil == PEM_read_bio_PrivateKey(f.bio, &kp, nil, nil) {
			f = FileIO(name: pemPath, mode: "r")
			PEM_read_bio_PUBKEY(f.bio, &kp, nil, nil)
		}
		super.init(kp)
	}
	
	public init(source: String) {
		var f = MemoryIO(source)
		var kp: UnsafeMutablePointer<EVP_PKEY>? = nil
		if nil == PEM_read_bio_PrivateKey(f.bio, &kp, nil, nil) {
			f = MemoryIO(source)
			PEM_read_bio_PUBKEY(f.bio, &kp, nil, nil)
		}
		super.init(kp)
	}
}
