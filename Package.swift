// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription
 
let platforms: [SupportedPlatform] = [.macOS(.v10_12), .iOS(.v10), .tvOS(.v10), .watchOS(.v3)]
let products: [Product] = [.library(name: "BLCrypto", targets: ["BLCrypto"])]
let testResources: [Resource] = [
    .copy("Resources/Keys/multiple-keys-testcase.pem"),
    .copy("Resources/Keys/multiple-keys-testcase.sh"),
    .copy("Resources/Keys/swiftyrsa-private-header-octetstring.pem"),
    .copy("Resources/Keys/swiftyrsa-private-headerless.pem"),
    .copy("Resources/Keys/swiftyrsa-private.der"),
    .copy("Resources/Keys/swiftyrsa-private.pem"),
    .copy("Resources/Keys/swiftyrsa-public-base64-newlines.txt"),
    .copy("Resources/Keys/swiftyrsa-public-base64-X509-format.txt"),
    .copy("Resources/Keys/swiftyrsa-public-base64.txt"),
    .copy("Resources/Keys/swiftyrsa-public-headerless.pem"),
    .copy("Resources/Keys/swiftyrsa-public.der"),
    .copy("Resources/Keys/swiftyrsa-public.pem"),
    .copy("Resources/Keys/ehr-gcm-contract-cipher-key-base64"),
    .copy("Resources/Keys/ehr-gcm-contract-message-base64"),
    .copy("Resources/Keys/openssl-private-key-pkcs1-pem"),
    .copy("Resources/Keys/openssl-public-key-pkcs1-pem"),
    .copy("Resources/Keys/ehr-cbc-contract-message-base64"),
    .copy("Resources/Keys/ehr-cbc-contract-cipher-key-base64")
]
let targets: [Target] = [
    .target(name: "BLCrypto"),
    .testTarget(name: "BLCryptoTests", dependencies: ["BLCrypto"], resources: testResources)
]

let package = Package(
    name: "BLCrypto",
    platforms: platforms,
    products: products,
    targets: targets
)
