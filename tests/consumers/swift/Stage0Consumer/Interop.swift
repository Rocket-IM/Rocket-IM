import Foundation
import RocketsIMStage0

/// 仅供独立消费验证的控制通道。密码对象由串行actor持有，不在UI回调执行。
enum Interop {
    static func startIfConfigured() -> Bool {
        let environment = ProcessInfo.processInfo.environment
        let keys = ["ROCKETS_INTEROP_URL", "ROCKETS_INTEROP_RUN_ID", "ROCKETS_INTEROP_ENDPOINT_ID"]
        guard keys.contains(where: { environment[$0] != nil }) else { return false }
        Task {
            do {
                let configuration = try Configuration(environment: environment)
                await Endpoint(configuration: configuration).run()
            } catch {
                record(status: "FAIL", error: "harness configuration invalid")
            }
        }
        return true
    }

    private struct HarnessError: Error {
        let code: String
    }

    private struct Configuration {
        let base: URL
        let runID: String
        let endpointID: String

        init(environment: [String: String]) throws {
            guard let raw = environment["ROCKETS_INTEROP_URL"], let url = URL(string: raw),
                  url.scheme == "http", url.host == "127.0.0.1", url.port != nil,
                  url.user == nil, url.password == nil, url.query == nil, url.fragment == nil,
                  let runID = environment["ROCKETS_INTEROP_RUN_ID"],
                  let endpointID = environment["ROCKETS_INTEROP_ENDPOINT_ID"],
                  validID(runID), validID(endpointID) else {
                throw HarnessError(code: "configuration_invalid")
            }
            self.runID = runID
            self.endpointID = endpointID
            base = url.appendingPathComponent("interop").appendingPathComponent(runID).appendingPathComponent(endpointID)
        }
    }

    private struct Command: Decodable {
        let run_id: String
        let command_id: String
        let op: String
        let handle: String
        let args: [String: String]

        func text(_ name: String) throws -> String {
            guard let value = args[name] else { throw HarnessError(code: "argument_missing") }
            return value
        }

        func bytes(_ name: String) throws -> Data {
            let value = try text(name)
            guard let data = Data(base64Encoded: value), data.base64EncodedString() == value else {
                throw HarnessError(code: "argument_base64")
            }
            return data
        }
    }

    private struct Failure: Encodable {
        let origin: String
        let code: String
        let device_poisoned: Bool
        let message: String
    }

    private struct Result: Encodable {
        let run_id: String
        let endpoint_id: String
        let command_id: String
        let ok: Bool
        let value: String?
        let error: Failure?

        enum CodingKeys: String, CodingKey { case run_id, endpoint_id, command_id, ok, value, error }

        func encode(to encoder: Encoder) throws {
            var values = encoder.container(keyedBy: CodingKeys.self)
            try values.encode(run_id, forKey: .run_id)
            try values.encode(endpoint_id, forKey: .endpoint_id)
            try values.encode(command_id, forKey: .command_id)
            try values.encode(ok, forKey: .ok)
            if ok {
                if let value { try values.encode(value, forKey: .value) }
                else { try values.encodeNil(forKey: .value) }
            } else { try values.encodeIfPresent(error, forKey: .error) }
        }
    }

    private actor Endpoint {
        private let configuration: Configuration
        private var devices: [String: Stage0Device] = [:]
        private var seen: Set<String> = []
        private let encoder = JSONEncoder()
        private let decoder = JSONDecoder()
        private let maximumBytes = 1024 * 1024

        init(configuration: Configuration) { self.configuration = configuration }

        func run() async {
            defer {
                for device in devices.values { try? device.close() }
                devices.removeAll()
            }
            do {
                let ready = ["run_id": configuration.runID, "endpoint_id": configuration.endpointID,
                             "sdk_version": sdkVersion(), "platform": "swift-ios"]
                try await post("ready", body: encoder.encode(ready))
                while true {
                    let (data, status) = try await request("next", method: "GET", body: nil)
                    if status == 204 { continue }
                    let command = try decoder.decode(Command.self, from: data)
                    guard command.run_id == configuration.runID, validID(command.command_id),
                          command.op == "shutdown" || validID(command.handle) else {
                        throw HarnessError(code: "command_binding")
                    }
                    guard seen.count < 4096, seen.insert(command.command_id).inserted else {
                        throw HarnessError(code: "command_duplicate_or_limit")
                    }
                    let result = execute(command)
                    // 只提交一次。结果传输失败不得自动再次执行有状态密码操作。
                    try await post("result", body: encoder.encode(result))
                    if command.op == "shutdown" {
                        guard result.ok else { throw HarnessError(code: "shutdown_failed") }
                        record(status: "STOPPED", error: nil)
                        return
                    }
                }
            } catch {
                let failure = failure(error)
                record(status: "FAIL", error: "\(failure.origin):\(failure.code)")
            }
        }

        private func request(_ path: String, method: String, body: Data?) async throws -> (Data, Int) {
            guard (body?.count ?? 0) <= maximumBytes else { throw HarnessError(code: "request_size") }
            var request = URLRequest(url: configuration.base.appendingPathComponent(path))
            request.httpMethod = method
            request.httpBody = body
            request.timeoutInterval = 20
            if body != nil { request.setValue("application/json", forHTTPHeaderField: "Content-Type") }
            let (data, response) = try await URLSession.shared.data(for: request)
            guard data.count <= maximumBytes, let http = response as? HTTPURLResponse,
                  http.statusCode == 200 || (method == "GET" && http.statusCode == 204) else {
                throw HarnessError(code: "http_response")
            }
            return (data, http.statusCode)
        }

        private func post(_ path: String, body: Data) async throws {
            let (data, _) = try await request(path, method: "POST", body: body)
            struct Ack: Decodable { let ok: Bool }
            guard try decoder.decode(Ack.self, from: data).ok else { throw HarnessError(code: "http_ack") }
        }

        private func execute(_ command: Command) -> Result {
            do {
                return Result(run_id: configuration.runID, endpoint_id: configuration.endpointID,
                              command_id: command.command_id, ok: true, value: try perform(command), error: nil)
            } catch {
                return Result(run_id: configuration.runID, endpoint_id: configuration.endpointID,
                              command_id: command.command_id, ok: false, value: nil, error: failure(error))
            }
        }

        private func perform(_ command: Command) throws -> String? {
            if command.op == "new" {
                guard devices[command.handle] == nil, devices.count < 32 else { throw HarnessError(code: "handle_limit_or_duplicate") }
                devices[command.handle] = try Stage0Device(serviceId: command.text("service_id"),
                    accountId: command.text("account_id"), deviceId: command.text("device_id"))
                return nil
            }
            if command.op == "shutdown" {
                for device in devices.values { try device.close() }
                devices.removeAll()
                return nil
            }
            guard let device = devices[command.handle] else { throw HarnessError(code: "handle_missing") }
            switch command.op {
            case "identity": return try device.identityKey().base64EncodedString()
            case "key_package": return try device.keyPackage().base64EncodedString()
            case "create_group":
                return try device.createGroup(conversationId: command.text("conversation_id"),
                    peerAccountId: command.text("peer_account_id"), peerDeviceId: command.text("peer_device_id"),
                    peerIdentityKey: command.bytes("peer_identity_key"), keyPackage: command.bytes("key_package")).base64EncodedString()
            case "join_group":
                try device.joinGroup(conversationId: command.text("conversation_id"),
                    creatorAccountId: command.text("creator_account_id"), creatorDeviceId: command.text("creator_device_id"),
                    creatorIdentityKey: command.bytes("creator_identity_key"), welcome: command.bytes("welcome"))
                return nil
            case "encrypt": return try device.encrypt(plaintext: command.bytes("plaintext")).base64EncodedString()
            case "decrypt": return try device.decrypt(ciphertext: command.bytes("ciphertext")).base64EncodedString()
            case "close": try device.close(); return nil
            case "drop": try device.close(); devices.removeValue(forKey: command.handle); return nil
            default: throw HarnessError(code: "operation_unknown")
            }
        }

        private func failure(_ error: Error) -> Failure {
            if let sdkError = error as? DeviceError, case let .Failure(code, poisoned) = sdkError {
                return Failure(origin: "sdk", code: code, device_poisoned: poisoned,
                               message: String(String(describing: error).prefix(256)))
            }
            if let error = error as? HarnessError {
                return Failure(origin: "harness", code: error.code, device_poisoned: false, message: error.code)
            }
            return Failure(origin: "harness", code: "unexpected_error", device_poisoned: false,
                           message: String(String(describing: error).prefix(256)))
        }
    }

    private static func validID(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 96 && value.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 95
        }
    }

    private static func record(status: String, error: String?) {
        let value = ["status": status, "error": error ?? ""]
        do {
            let data = try JSONEncoder().encode(value)
            let directory = try FileManager.default.url(for: .documentDirectory, in: .userDomainMask,
                                                        appropriateFor: nil, create: true)
            try data.write(to: directory.appendingPathComponent("interop-result.json"), options: .atomic)
            print("ROCKETS_INTEROP:" + String(decoding: data, as: UTF8.self))
        } catch { print("ROCKETS_INTEROP:FAIL recording terminal result") }
    }
}
