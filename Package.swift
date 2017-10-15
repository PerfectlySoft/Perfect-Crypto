// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.
//
//  Package.swift
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

import PackageDescription

#if os(Linux)

let package = Package(
    name: "PerfectCrypto",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "PerfectCrypto",
            targets: ["PerfectCrypto"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
				.package(url: "https://github.com/PerfectlySoft/PerfectLib.git", from: "3.0.0"),
				.package(url: "https://github.com/PerfectlySoft/Perfect-Thread.git", from: "3.0.0"),
				.package(url: "https://github.com/PerfectlySoft/Perfect-COpenSSL-Linux.git", from: "3.0.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "PerfectCrypto",
            dependencies: ["PerfectLib", "PerfectThread", "COpenSSL"]),
        .testTarget(
            name: "PerfectCryptoTests",
            dependencies: ["PerfectCrypto"]),
    ]
)
#else

let package = Package(
    name: "PerfectCrypto",
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "PerfectCrypto",
            targets: ["PerfectCrypto"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
				.package(url: "https://github.com/PerfectlySoft/PerfectLib.git", from: "3.0.0"),
				.package(url: "https://github.com/PerfectlySoft/Perfect-Thread.git", from: "3.0.0"),
				.package(url: "https://github.com/PerfectlySoft/Perfect-COpenSSL.git", from: "3.0.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .target(
            name: "PerfectCrypto",
            dependencies: ["PerfectLib", "PerfectThread", "COpenSSL"]),
        .testTarget(
            name: "PerfectCryptoTests",
            dependencies: ["PerfectCrypto"]),
    ]
)
#endif
