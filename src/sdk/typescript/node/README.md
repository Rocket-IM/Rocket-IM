# Rocket-IM Stage 0 Node 包

面向桌面 Node 宿主的最小 SDK 产物：公开 JavaScript 接口、TypeScript 声明和预编译 Rust WASM。安装本地发行 `.tgz` 即可消费，不需要 Rust/Cargo、wasm-bindgen 或浏览器。项目尚未发布 npm 公共版本，项目分发许可证未确定。

```typescript
import { initialize, Stage0Device } from "@rocket-im/stage0-node";

// 此模块由宿主通过 node:worker_threads 在工作线程加载。
await initialize();
const device = new Stage0Device("service", "account", "device");
try {
  const publicIdentity = device.identityKey();
  // 使用公开字节接口交换KeyPackage、Welcome和消息密文。
} finally {
  device.close();
}
```

方法为同步调用，宿主负责工作线程及其关闭；不能在 UI/Node 主事件循环直接执行耗时密码操作。每对象的调用按实际执行顺序处理，不引入 Promise 任务池重排。`initialize()` 可重复等待；加载或版本失败不会寻找另一份核心或编译源码，修复安装后重建工作线程。

错误保持 `错误码; device_poisoned=true/false`。毒化实例只能关闭，禁止重新加密重试或自动重建。字节结果不借用 Rust 内存；关闭幂等，不影响其他设备，不承诺完整内存安全擦除。只有内存双设备 MLS 能力，没有正式 IM 网络、SQLite、账号登录或历史恢复。

生成器使用 wasm-bindgen 0.2.128 的 `nodejs` 目标，在包内 CommonJS 子目录加载预编译 WASM；公开入口为 ESM。必须按目录保留 JS、声明和 WASM；没有安装脚本，也不运行绑定生成器。桌面目标为 macOS/Windows，具体通过的系统、CPU和Node版本以维护者运行报告为准。Windows、Electron/Tauri应用集成和正式桌面持久化不能由macOS Node通过推定。
