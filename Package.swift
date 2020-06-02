// swift-tools-version:5.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "JOSESwift",
	platforms: [
        .macOS(.v10_13), .iOS(.v10)
    ],
    products: [
        .library(
            name: "JOSESwift",
            targets: ["JOSESwift"]),
    ],
    targets: [
        .target(
            name: "JOSESwift",
            path: "Sources")
    ]
)
