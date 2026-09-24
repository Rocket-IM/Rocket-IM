// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "RocketIMStage0",
    platforms: [.iOS(.v15)],
    products: [.library(name: "RocketIMStage0", targets: ["RocketIMStage0"])],
    targets: [
        .binaryTarget(name: "RocketIMStage0FFI", path: "Artifacts/RocketIMStage0FFI.xcframework"),
        .target(name: "RocketIMStage0", dependencies: ["RocketIMStage0FFI"],
                path: "Sources/RocketIMStage0")
    ]
)
