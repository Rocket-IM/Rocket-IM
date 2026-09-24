package io.rocketim.stage0

/**
 * 阶段0内存设备。同步方法由调用方调度到后台线程；状态与错误完全由Rust维护。
 * close幂等关闭密码状态；包装保留原生句柄，使关闭后调用仍返回固定Rust错误。
 */
class Stage0Device(serviceId: String, accountId: String, deviceId: String) : AutoCloseable {
    private val inner = createNativeDevice(serviceId, accountId, deviceId)

    private fun createNativeDevice(serviceId: String, accountId: String, deviceId: String): NativeDevice {
        check(sdkVersion() == SDK_VERSION) { "SDK原生库与Kotlin发布包版本不匹配" }
        return NativeDevice(serviceId, accountId, deviceId)
    }

    fun identityKey(): ByteArray = inner.identityKey()

    fun keyPackage(): ByteArray = inner.keyPackage()

    fun createGroup(
        conversationId: String,
        peerAccountId: String,
        peerDeviceId: String,
        peerIdentityKey: ByteArray,
        keyPackage: ByteArray,
    ): ByteArray = inner.createGroup(conversationId, peerAccountId, peerDeviceId, peerIdentityKey, keyPackage)

    fun joinGroup(
        conversationId: String,
        creatorAccountId: String,
        creatorDeviceId: String,
        creatorIdentityKey: ByteArray,
        welcome: ByteArray,
    ) = inner.joinGroup(conversationId, creatorAccountId, creatorDeviceId, creatorIdentityKey, welcome)

    fun encrypt(plaintext: ByteArray): ByteArray = inner.encrypt(plaintext)

    fun decrypt(ciphertext: ByteArray): ByteArray = inner.decrypt(ciphertext)

    override fun close() = inner.closeDevice()
}

private const val SDK_VERSION = "0.1.0-stage0.1"
