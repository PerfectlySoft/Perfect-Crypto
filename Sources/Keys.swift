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

// EC_KEY
// EVP_KEY

// WIP

public struct KeyPair {
	public struct PublicKey {
		let bytes: [UInt8]
	}
	public struct PrivateKey {
		let bytes: [UInt8]
	}
	
	var publicKey: PublicKey?
	var privateKey: PrivateKey?
	
	public init(filePath: String) throws {
		
	}
}

