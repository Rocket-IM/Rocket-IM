package io.rocketsim.consumer.kotlin

import android.util.Base64
import io.rocketsim.stage0.DeviceException
import io.rocketsim.stage0.Stage0Device
import io.rocketsim.stage0.sdkVersion
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI

/** 本机互通装置；只串行调用已发布SDK，不实现密码处理或有状态命令重试。 */
class InteropEndpoint(url: String, private val runId: String, private val endpointId: String) {
    private val handles = mutableMapOf<String, Stage0Device>()
    private val seenCommands = mutableSetOf<String>()
    @Volatile private var active = true
    @Volatile private var connection: HttpURLConnection? = null
    private val base: String

    init {
        val uri = URI(url)
        require(uri.scheme == "http" && uri.host in setOf("127.0.0.1", "10.0.2.2") && uri.port in 1..65535)
        require(uri.rawUserInfo == null && uri.query == null && uri.fragment == null && uri.path in setOf("", "/"))
        require(validId(runId) && endpointId == "kotlin-android")
        base = "${url.trimEnd('/')}/interop/$runId/$endpointId"
    }

    fun cancel() {
        active = false
        connection?.disconnect()
    }

    fun run(): String {
        check(sdkVersion() == "0.1.0-stage0.1") { "SDK version mismatch" }
        try {
            post("ready", JSONObject().put("run_id", runId).put("endpoint_id", endpointId)
                .put("sdk_version", sdkVersion()).put("platform", endpointId))
            while (active && !Thread.currentThread().isInterrupted) {
                val command = request("GET", "next", null) ?: continue
                require(command.get("run_id") == runId) { "command run mismatch" }
                val commandId = string(command, "command_id")
                require(validId(commandId) && seenCommands.size < 10_000 && seenCommands.add(commandId)) { "duplicate or excessive commands" }
                val op = string(command, "op")
                val result = JSONObject().put("run_id", runId).put("endpoint_id", endpointId).put("command_id", commandId)
                try {
                    result.put("value", execute(command)).put("ok", true)
                } catch (error: DeviceException.Failure) {
                    result.put("ok", false).put("error", JSONObject().put("origin", "sdk").put("code", error.code)
                        .put("device_poisoned", error.devicePoisoned).put("message", error.message.take(512)))
                } catch (error: Exception) {
                    result.put("ok", false).put("error", JSONObject().put("origin", "harness").put("code", "harness_error")
                        .put("device_poisoned", false).put("message", error.javaClass.simpleName))
                }
                post("result", result)
                if (op == "shutdown") return "finished"
            }
            return "cancelled"
        } finally {
            handles.values.forEach { it.close() }
            handles.clear()
        }
    }

    private fun execute(command: JSONObject): Any {
        val op = string(command, "op")
        val args = command.getJSONObject("args")
        require(args.keys().asSequence().all { args.get(it) is String }) { "args must contain strings" }
        if (op == "shutdown") {
            handles.values.forEach { it.close() }
            handles.clear()
            return JSONObject.NULL
        }
        val handle = string(command, "handle")
        require(validId(handle)) { "invalid handle" }
        if (op == "new") {
            require(handle !in handles && handles.size < 32) { "handle exists or limit exceeded" }
            handles[handle] = Stage0Device(string(args, "service_id"), string(args, "account_id"), string(args, "device_id"))
            return JSONObject.NULL
        }
        val device = requireNotNull(handles[handle]) { "unknown handle" }
        return when (op) {
            "identity" -> encode(device.identityKey())
            "key_package" -> encode(device.keyPackage())
            "create_group" -> encode(device.createGroup(string(args, "conversation_id"), string(args, "peer_account_id"),
                string(args, "peer_device_id"), bytes(args, "peer_identity_key"), bytes(args, "key_package")))
            "join_group" -> {
                device.joinGroup(string(args, "conversation_id"), string(args, "creator_account_id"),
                    string(args, "creator_device_id"), bytes(args, "creator_identity_key"), bytes(args, "welcome"))
                JSONObject.NULL
            }
            "encrypt" -> encode(device.encrypt(bytes(args, "plaintext")))
            "decrypt" -> encode(device.decrypt(bytes(args, "ciphertext")))
            "close" -> { device.close(); JSONObject.NULL }
            "drop" -> { device.close(); handles.remove(handle); JSONObject.NULL }
            else -> error("unknown operation")
        }
    }

    private fun post(path: String, value: JSONObject) {
        require(request("POST", path, value)?.get("ok") == true) { "controller did not acknowledge result" }
    }

    private fun request(method: String, path: String, body: JSONObject?): JSONObject? {
        check(active) { "endpoint cancelled" }
        val http = URI("$base/$path").toURL().openConnection() as HttpURLConnection
        connection = http
        try {
            http.requestMethod = method
            http.instanceFollowRedirects = false
            http.connectTimeout = 5_000
            http.readTimeout = 20_000
            if (body != null) {
                val encoded = body.toString().toByteArray(Charsets.UTF_8)
                require(encoded.size <= LIMIT) { "HTTP request exceeds limit" }
                http.doOutput = true
                http.setRequestProperty("Content-Type", "application/json")
                http.setFixedLengthStreamingMode(encoded.size)
                http.outputStream.use { it.write(encoded) }
            }
            if (method == "GET" && http.responseCode == 204) return null
            check(http.responseCode == 200) { "HTTP control channel failed: ${http.responseCode}" }
            val buffer = java.io.ByteArrayOutputStream()
            http.inputStream.use { input ->
                val block = ByteArray(8192)
                while (true) {
                    val count = input.read(block)
                    if (count < 0) break
                    require(buffer.size() + count <= LIMIT) { "HTTP response exceeds limit" }
                    buffer.write(block, 0, count)
                }
            }
            return JSONObject(buffer.toString("UTF-8"))
        } finally {
            connection = null
            http.disconnect()
        }
    }

    private fun string(value: JSONObject, key: String): String = value.get(key) as? String ?: error("expected string $key")
    private fun bytes(value: JSONObject, key: String): ByteArray {
        val encoded = string(value, key)
        val bytes = Base64.decode(encoded, Base64.DEFAULT)
        require(encode(bytes) == encoded) { "non-canonical Base64" }
        return bytes
    }
    private fun encode(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)
    private fun validId(value: String) = Regex("[A-Za-z0-9_-]{1,128}").matches(value)
    private companion object { const val LIMIT = 1024 * 1024 }
}
