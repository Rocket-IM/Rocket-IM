import Foundation
import RocketIMStage0
import UIKit

private struct VerificationFailure: Error, CustomStringConvertible {
    let description: String
}

private func verifyPublicPackage(expectedVersion: String) -> [String: Any] {
    var checks: [String] = []
    func check(_ condition: Bool, _ name: String) throws {
        guard condition else { throw VerificationFailure(description: name) }
        checks.append(name)
    }
    do {
        try check(sdkVersion() == expectedVersion, "package_version")
        let alice = try Stage0Device(serviceId: "consumer-service", accountId: "alice", deviceId: "swift-a")
        let bob = try Stage0Device(serviceId: "consumer-service", accountId: "bob", deviceId: "swift-b")
        let negative = try Stage0Device(serviceId: "consumer-service", accountId: "mallory", deviceId: "swift-c")
        defer { try? alice.close(); try? bob.close(); try? negative.close() }
        try check(alice.identityKey() != bob.identityKey(), "independent_identity")
        let original = try bob.keyPackage()
        try check(original == bob.keyPackage(), "key_package_exact_retry")
        var copy = try bob.keyPackage(); copy[copy.startIndex] ^= 1
        try check(original == bob.keyPackage(), "public_buffer_ownership")
        var rejectedIdentity = false
        do {
            _ = try negative.createGroup(conversationId: "negative", peerAccountId: "bob", peerDeviceId: "swift-b",
                                         peerIdentityKey: alice.identityKey(), keyPackage: original)
        } catch DeviceError.Failure(let code, let poisoned) {
            rejectedIdentity = code == "identity_mismatch" && !poisoned
        }
        try check(rejectedIdentity, "wrong_identity_rejected")
        let welcome = try alice.createGroup(conversationId: "consumer-conversation", peerAccountId: "bob", peerDeviceId: "swift-b",
                                            peerIdentityKey: bob.identityKey(), keyPackage: original)
        try bob.joinGroup(conversationId: "consumer-conversation", creatorAccountId: "alice", creatorDeviceId: "swift-a",
                          creatorIdentityKey: alice.identityKey(), welcome: welcome)
        let unicode = Data("独立Swift包 👋\nUnicode 与零字节\0".utf8)
        let cipher = try alice.encrypt(plaintext: unicode)
        try check(cipher != unicode, "ciphertext_differs")
        try check(bob.decrypt(ciphertext: cipher) == unicode, "unicode_round_trip")
        let binary = Data([0, 255, 1, 128, 0, 42, 127, 254])
        try check(alice.decrypt(ciphertext: bob.encrypt(plaintext: binary)) == binary, "binary_reverse_round_trip")
        var corrupted = try alice.encrypt(plaintext: Data([3, 4, 5]))
        corrupted[corrupted.index(before: corrupted.endIndex)] ^= 1
        var rejectedCiphertext = false
        do { _ = try bob.decrypt(ciphertext: corrupted) }
        catch DeviceError.Failure(let code, let poisoned) { rejectedCiphertext = code == "crypto_failure" && poisoned }
        try check(rejectedCiphertext, "corrupted_ciphertext_rejected")
        var rejectedPoisoned = false
        do { _ = try bob.encrypt(plaintext: Data([1])) }
        catch DeviceError.Failure(let code, let poisoned) { rejectedPoisoned = code == "poisoned" && poisoned }
        try check(rejectedPoisoned, "poisoned_device_rejected")
        try alice.close(); try alice.close()
        var rejectedClosed = false
        do { _ = try alice.identityKey() }
        catch DeviceError.Failure(let code, let poisoned) { rejectedClosed = code == "closed" && !poisoned }
        try check(rejectedClosed, "closed_device_rejected")
        try check(true, "idempotent_close")
        return ["status": "PASS", "checks": checks, "version": sdkVersion()]
    } catch {
        return ["status": "FAIL", "checks": checks, "error": String(describing: error), "version": sdkVersion()]
    }
}

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        let window = UIWindow(frame: UIScreen.main.bounds)
        let controller = UIViewController()
        controller.view.backgroundColor = .systemBackground
        let label = UILabel(frame: window.bounds.insetBy(dx: 24, dy: 48))
        label.numberOfLines = 0; label.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
        label.textColor = .label
        controller.view.addSubview(label); window.rootViewController = controller
        window.makeKeyAndVisible(); self.window = window
        if Interop.startIfConfigured() {
            label.text = "互通控制端已启动"
            return true
        }
        let expected = Bundle.main.object(forInfoDictionaryKey: "ExpectedSDKVersion") as? String ?? "missing-version"
        let result = verifyPublicPackage(expectedVersion: expected)
        do {
            let data = try JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])
            let directory = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask,
                                                       appropriateFor: nil, create: true)
            try data.write(to: directory.appendingPathComponent("result.json"), options: .atomic)
            label.text = String(data: data, encoding: .utf8)
            print("STAGE0_RESULT:" + String(decoding: data, as: UTF8.self))
        } catch { label.text = "FAIL writing result: \(error)" }
        return true
    }
}
