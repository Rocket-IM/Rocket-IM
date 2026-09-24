# Kotlin 阶段0实验包

本地 Maven 坐标：`io.rocketsim:rockets-stage0:0.1.0-stage0.1`。Android 24+，只打包 arm64-v8a 与 x86_64 的预编译 Release 库。消费应用正常使用 Gradle，无需 Rust、Cargo 或绑定生成器；缺少二进制不会改为源码构建。

公开入口为 `io.rocketsim.stage0.Stage0Device`。构造器核对本包与原生库版本；所有同步方法由接入方调度至后台线程。`close()` 幂等关闭密码状态，关闭后操作返回固定 Rust 错误，原生句柄随包装对象回收。生成的 `NativeDevice`、转换器、FFI 类型属于绑定实现细节，不是稳定接入契约。

此包只验证两个独立内存设备的身份、KeyPackage、建群和双向加解密，没有账号认证、网络、消息存储或完整 IM 能力。不能用于生产。

运行依赖：UniFFI 0.31.0 生成绑定；JNA 5.17.0 AAR 提供 JNI/JNA 桥接（Apache-2.0 或 LGPL-2.1-or-later，本次按 Apache-2.0 分发），Kotlin 标准库由 Kotlin 2.2.20 工具链正常解析。JNA 会增加原生运行库，发布者必须随 SDK 验证其 ABI 与页面对齐，接入方无需自行构建它。打包器将 Rust 依赖声明、许可证及项目许可状态放在 AAR 的 `assets/rockets-stage0-licenses/`；项目许可尚未确定，不公开发布。
