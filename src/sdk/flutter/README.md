# Flutter 阶段0实验包

> 2026-09-24：当前包与模块名称已统一；以下为打包约定，改名后的移动目标二进制与设备消费尚未重跑。新旧包不可混用，本轮证据见[工程名称统一](../../../docs/工程名称统一.md)。

包名 `rocket_im_stage0`，版本 `0.1.0-stage0.1`，消费基线 Flutter 3.41.0 / Dart 3.11.0。Android 24+ 支持 arm64-v8a、x86_64；iOS 13+ 包含设备 arm64 与模拟器 arm64、x86_64 的静态 XCFramework。实际通过范围以本次运行报告为准。

接入方解压发布包后用本地 `path` 依赖安装，正常运行 Flutter 构建即可。调用 `await initialize()` 后，通过 `newDevice()` 创建 `Stage0Device`；所有设备方法为 Future，字节输入使用 Uint8List。公开入口只在原生库、Dart 包及调用方可选精确版本要求一致后开放；首次加载失败在当前进程保持失败。`lib/src/rust` 为生成实现细节，不属于公共 API。

Android 明确加载包内 `librocket_stage0_flutter.so`；iOS 明确访问进程中已静态链接的符号。没有 Cargo、Cargokit、绑定生成器或源码构建兜底。缺库与版本不符必须修复安装。

运行桥接使用固定 flutter_rust_bridge 2.11.1（MIT），依赖由 Pub 正常解析。打包器依据实际解析清单收集 Dart 依赖 LICENSE，并附带 Rust 依赖声明和项目许可状态于 `licenses/`。桥接运行时是平台加载与异步边界所需，不复制密码或 IM 业务实现；新增支持平台需要重新构建和验证预编译产物。

这是独立内存双设备加解密实验，没有网络、持久化、业务认证或生产 IM 能力。项目许可尚未确定，仅本地验证，不公开发布。
