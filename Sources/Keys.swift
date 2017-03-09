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
public struct KeyPair {
	let pkey: UnsafePointer<EVP_PKEY>?
	
//	public init(type: KeyType) {
//		
//	}
	
	public init(pemPath: String) throws {
		let f = FileIO(name: pemPath, mode: "r")
		var kp: UnsafeMutablePointer<EVP_PKEY>? = nil
		PEM_read_bio_PrivateKey(f.bio, &kp, nil, nil)
		pkey = UnsafePointer<EVP_PKEY>(kp)
	}
}

