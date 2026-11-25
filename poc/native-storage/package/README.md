# TS 桌面 SQLite 阶段 0 实验包

仅在 macOS ARM64 / Node 的合成数据环境使用。该包包含 JS、类型声明和预编译 Rust 子进程，不需要 Cargo、Rust 源码或生成器；不提供安装脚本或源码编译回退。无运行时 npm 依赖。Windows、正式 SDK、最终桌面绑定与生产发布均未验收。

```ts
import { DesktopStorage } from '@rocket-im/stage0-desktop-storage';
const client = await DesktopStorage.open({
  path: '/absolute/existing-directory/device.sqlite', create: true,
  scope: { service: 'test-service', account: 'alice', device: 'alice-desktop' }
});
const unsubscribe = client.subscribe(async event => {
  const committed = await client.state(); // 可以重入查询，不占数据库事务
});
await client.initialize('stable-initialize-request');
await client.state();
unsubscribe();
await client.close();
```

`create: true` 仅新建，已有路径明确拒绝；`false` 只重开，不偷偷创建。数据库父目录由应用准备。服务/账号/设备绑定于该库，错误范围拒绝读取或复用同 ID。请求 ID、发送尝试 ID 与消息 ID 由调用方稳定保存；精确重试返回已提交缓存，冲突拒绝。当前普通持久端只有创建群入口；持久入群不在本包范围内。验收使用独立合成内存对端，不表示双端持久化。

每实例一个原生进程；原 Rust 协调线程计算密码，另一个 Rust 线程唯一持有 SQLite。迁移、读写和恢复查询均通过原显式事务；TS 不操作 SQL。最多 8 个在途请求，每个编码不超过 256 KiB；默认请求超时 10 秒（含排队，允许 100—60000ms）。原实验库仍有 128 条结果/下载等限制，不提供生产清理或容量承诺。

`StorageError.code`/`paused` 明确报告失败。发送前已取消返回 `cancelled`；发出后取消、超时或进程中断会终止该实例并返回未知结果错误，取消不等于回滚。必须重开库，用原请求 ID 精确查询/重试；若原 Rust 预约未决，则持续拒绝重算，不能删除库或强行解除。一个实例关闭/取消不影响其他实例。

事件在对应事务结束后派发，只表示本机提交；缓存重试、失败不发布成功事件。订阅者可以异步重入查询；异常转交 `onListenerError`，未配置则以微任务抛出。`close` 立即停止新请求与回调，等待已经接受的请求和进程退出；迟到提交可在重开后读取。退出进程前必须等待 `close`。

本实验默认数据库包含合成私密状态与正文，未接入系统秘密保护、独立锚或安全擦除；不得用于真实用户数据。故障注入、MemoryPeer、SQL、trace/metrics 不属于包 API。`runtime` 仅给出当前进程/线程归属。包摘要用于检测损坏与版本错配，不构成发行签名/敌对宿主完整性保证。
