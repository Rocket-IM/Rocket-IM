package io.rocketsim.consumer.kotlin

import android.app.Activity
import android.os.Bundle
import android.util.Log
import android.widget.TextView
import io.rocketsim.stage0.Stage0Device
import io.rocketsim.stage0.DeviceException
import io.rocketsim.stage0.sdkVersion
import org.json.JSONObject
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val worker = Executors.newSingleThreadExecutor()
    @Volatile private var interop: InteropEndpoint? = null
    @Volatile private var cancelled = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val status = TextView(this).apply { text = "正在验证本地 Release 包…"; setPadding(32, 64, 32, 32) }
        setContentView(status)
        val interopUrl = intent.getStringExtra("interop_url")
        if (interopUrl != null) {
            worker.execute {
                try {
                    val endpoint = InteropEndpoint(interopUrl, intent.getStringExtra("interop_run_id") ?: "",
                        intent.getStringExtra("interop_endpoint_id") ?: "")
                    interop = endpoint
                    if (cancelled) { endpoint.cancel(); return@execute }
                    val result = endpoint.run()
                    runOnUiThread { if (!isDestroyed) status.text = "互通控制：$result" }
                } catch (error: Exception) {
                    Log.e("RocketsInterop", "harness_failed: ${error.javaClass.simpleName}")
                    runOnUiThread { if (!isDestroyed) status.text = "互通装置失败：${error.javaClass.simpleName}" }
                }
            }
            return
        }
        val runId = intent.getStringExtra("run_id") ?: "manual"
        val scenario = intent.getStringExtra("scenario") ?: "public-api"
        worker.execute {
            val result = JSONObject().put("run_id", runId).put("platform", "kotlin-android").put("scenario", scenario)
            try {
                if (scenario == "version-rejected") verifyRejectedVersion() else verifyPublicApi()
                result.put("status", "passed").put("checks", if (scenario == "version-rejected") 1 else 8)
            } catch (error: Throwable) {
                result.put("status", "failed").put("error", error.javaClass.name).put("message", error.message ?: "")
            }
            val encoded = result.toString()
            Log.i("RocketsStage0", encoded)
            runOnUiThread { status.text = encoded }
        }
    }

    private fun verifyRejectedVersion() {
        var rejected = false
        try {
            Stage0Device("release-local", "alice", "version-negative")
        } catch (error: IllegalStateException) {
            rejected = error.message == "SDK原生库与Kotlin发布包版本不匹配"
        }
        check(rejected) { "SDK包版本不匹配时仍可创建设备" }
    }

    private fun verifyPublicApi() {
        check(sdkVersion() == "0.1.0-stage0.1") { "SDK二进制版本不匹配" }
        val alice = Stage0Device("release-local", "alice", "alice-android")
        val bob = Stage0Device("release-local", "bob", "bob-android")
        try {
            val keyPackage = bob.keyPackage()
            check(keyPackage.contentEquals(bob.keyPackage())) { "KeyPackage精确重试改变" }
            check(!alice.identityKey().contentEquals(bob.identityKey())) { "设备身份重复" }
            val welcome = alice.createGroup("release-group", "bob", "bob-android", bob.identityKey(), keyPackage)
            bob.joinGroup("release-group", "alice", "alice-android", alice.identityKey(), welcome)
            val first = "Kotlin consumer to peer".toByteArray(Charsets.UTF_8)
            val encrypted = alice.encrypt(first)
            check(!first.contentEquals(encrypted)) { "密文与明文相同" }
            check(first.contentEquals(bob.decrypt(encrypted))) { "首方向解密失败" }
            val reply = "Peer to Kotlin consumer".toByteArray(Charsets.UTF_8)
            check(reply.contentEquals(alice.decrypt(bob.encrypt(reply)))) { "反方向解密失败" }
            bob.close()
            bob.close()
            var rejected = false
            try { bob.encrypt(first) } catch (error: DeviceException.Failure) {
                rejected = error.code == "closed" && !error.devicePoisoned
            }
            check(rejected) { "关闭后操作未拒绝" }
        } finally {
            alice.close()
            bob.close()
        }
    }

    override fun onDestroy() {
        cancelled = true
        interop?.cancel()
        worker.shutdownNow()
        super.onDestroy()
    }
}
