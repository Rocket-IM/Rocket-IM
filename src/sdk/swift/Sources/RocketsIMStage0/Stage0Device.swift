import Foundation

public let stage0SDKVersion = "0.1.0-stage0.1"

public enum Stage0PackageError: Error, CustomStringConvertible {
    case versionMismatch(expected: String, actual: String)

    public var description: String {
        switch self {
        case let .versionMismatch(expected, actual):
            return "sdk_version_mismatch: expected \(expected), received \(actual)"
        }
    }
}

/// 阶段0独立内存设备。方法同步调用共享Rust实现；不提供网络、持久化或业务设备批准。
/// close幂等，关闭后其余方法返回生成绑定中的DeviceError。
public class Stage0Device {
    private let inner: NativeDevice

    public init(serviceId: String, accountId: String, deviceId: String) throws {
        let actual = sdkVersion()
        guard actual == stage0SDKVersion else {
            throw Stage0PackageError.versionMismatch(expected: stage0SDKVersion, actual: actual)
        }
        inner = try NativeDevice(serviceId: serviceId, accountId: accountId, deviceId: deviceId)
    }

    public func identityKey() throws -> Data { try inner.identityKey() }

    /// 返回该设备原KeyPackage；重复读取不会重新生成一次性材料。
    public func keyPackage() throws -> Data { try inner.keyPackage() }

    public func createGroup(conversationId: String, peerAccountId: String, peerDeviceId: String,
                            peerIdentityKey: Data, keyPackage: Data) throws -> Data {
        try inner.createGroup(conversationId: conversationId, peerAccountId: peerAccountId, peerDeviceId: peerDeviceId,
                              peerIdentityKey: peerIdentityKey, keyPackage: keyPackage)
    }

    public func joinGroup(conversationId: String, creatorAccountId: String, creatorDeviceId: String,
                          creatorIdentityKey: Data, welcome: Data) throws {
        try inner.joinGroup(conversationId: conversationId, creatorAccountId: creatorAccountId, creatorDeviceId: creatorDeviceId,
                            creatorIdentityKey: creatorIdentityKey, welcome: welcome)
    }

    public func encrypt(plaintext: Data) throws -> Data { try inner.encrypt(plaintext: plaintext) }
    public func decrypt(ciphertext: Data) throws -> Data { try inner.decrypt(ciphertext: ciphertext) }
    public func close() throws { try inner.closeDevice() }
}
