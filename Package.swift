// swift-tools-version: 6.4

import PackageDescription

let package = Package(
    name: "swift-w3c-webauthn",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
        .visionOS(.v27),
    ],
    products: [
        .library(name: "W3C WebAuthn", targets: ["W3C WebAuthn"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/swift-ietf/swift-rfc-9053.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-ietf/swift-rfc-8259.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-ietf/swift-rfc-4648.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-iso/swift-iso-8824.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-iso/swift-iso-8825.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-standards/swift-fips-186-5.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-standards/swift-fips-180-4.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-atoms/swift-byte.git",
            branch: "main"
        ),
        .package(
            url: "https://github.com/swift-atoms/swift-ascii.git",
            branch: "main"
        ),
    ],
    targets: [
        .target(
            name: "W3C WebAuthn",
            dependencies: [
                .product(name: "RFC 9053", package: "swift-rfc-9053"),
                .product(name: "RFC 8259", package: "swift-rfc-8259"),
                .product(name: "RFC 4648", package: "swift-rfc-4648"),
                .product(name: "ISO 8824", package: "swift-iso-8824"),
                .product(name: "ISO 8825", package: "swift-iso-8825"),
                .product(name: "FIPS 186-5", package: "swift-fips-186-5"),
                .product(name: "FIPS 180-4", package: "swift-fips-180-4"),
                .product(name: "Byte", package: "swift-byte"),
                .product(name: "ASCII", package: "swift-ascii"),
            ]
        ),
        .testTarget(
            name: "W3C WebAuthn Tests",
            dependencies: [
                .target(name: "W3C WebAuthn"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

for target in package.targets where ![.system, .binary, .plugin, .macro].contains(target.type) {
    target.swiftSettings =
        (target.swiftSettings ?? []) + [
            .strictMemorySafety(),
            .enableUpcomingFeature("ExistentialAny"),
            .enableUpcomingFeature("InternalImportsByDefault"),
            .enableUpcomingFeature("MemberImportVisibility"),
            .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
            .enableUpcomingFeature("InferIsolatedConformances"),
            .enableExperimentalFeature("Lifetimes"),
            .treatAllWarnings(as: .error),
        ]
}
