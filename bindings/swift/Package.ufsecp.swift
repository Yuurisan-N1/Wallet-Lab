// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Ufsecp",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "Ufsecp", targets: ["Ufsecp"]),
    ],
    targets: [
        .systemLibrary(
            name: "CUfsecp",
            path: "Sources/CUfsecp",
            pkgConfig: "ufsecp",
            providers: [.brew(["ufsecp"])]
        ),
        .target(
            name: "Ufsecp",
            dependencies: ["CUfsecp"],
            path: "Sources/Ufsecp"
        ),
        .testTarget(
            name: "UfsecpTests",
            dependencies: ["Ufsecp"],
            path: "Tests/UfsecpTests"
        ),
    ]
)
