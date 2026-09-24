// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "RocketsIMStage0",
    platforms: [.iOS(.v15)],
    products: [.library(name: "RocketsIMStage0", targets: ["RocketsIMStage0"])],
    targets: [
        .binaryTarget(name: "RocketsIMStage0FFI", path: "Artifacts/RocketsIMStage0FFI.xcframework"),
        .target(name: "RocketsIMStage0", dependencies: ["RocketsIMStage0FFI"],
                path: "Sources/RocketsIMStage0")
    ]
)
