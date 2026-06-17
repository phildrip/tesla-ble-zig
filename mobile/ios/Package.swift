// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "TeslaBLECore",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "TeslaBLECore",
            targets: ["TeslaBLECore"]
        ),
    ],
    targets: [
        .target(
            name: "TeslaBLECore",
            dependencies: [],
            path: "Sources/TeslaBLECore",
            publicHeadersPath: "include"
        )
    ]
)
