# 双持久端独立接入示例

需要 macOS arm64 和 Node >=22。把本目录复制到任意仓库外目录，安装本地实际 TGZ：

```sh
npm install --ignore-scripts /absolute/path/rocket-im-desktop-dev-0.2.0-dev.5.tgz
npm start
```

若使用验收产出的仓库外目录，包已安装，直接 `npm start` 即可。每次运行会建立新的测试数据子目录并打印其路径，不覆盖以前的数据库。

示例由两个依次启动的 Node 进程分别完成 setup/resume；每阶段内 Alice/Bob 是两个真实 Rust + SQLite 进程。它们通过公开 SDK 初始化、固定从各自直接创建的测试实例取得的准确公钥、建群/普通加入、双向消息、读取历史，以及重启后继续通信。没有 Rust/Cargo/生成器、SQL 或仓库源码引用。

`test-pins.json` 只固定本次测试身份；生产业务不能用测试程序自建公钥来源替代独立身份核验。密文由测试程序交换，不代表网络连接、Service接受、设备送达或已读。

`cases.mjs` 是配套边界验收，默认 `边界数据` 只运行一次；重跑可用 `ROCKET_CASE_DATA` 指定一个新目录。`types.ts` 只做公开接口类型校验，不是安装前置。测试数据库保存测试私钥和消息明文，禁止放入真实账号或秘密。完整限制见安装包 README。


`recovery-cases.mjs <jobs.json> <report.json>` 打开独立故障程序已中断的原库，只通过此目录安装的正常 Release 包完成精确恢复/双方签名后继、历史核验、重复和错误材料门禁、回调重入、关闭重开及双向新通信。jobs 由维护者验收入口准备，不是普通接入方必需工具。运行后的数据库仍在 jobs 所列原路径；不要重新执行同一已消耗的验收清单。恢复协议用法、v1显式升级和不能恢复的旧初始化 Pending 见包 README。

签名升级复现入口为 `python3 -B tools/platform_release/persistent_signing.py`（仓库根运行）。装置自行生成新的隔离合成签名身份，旧 dev.3 原件不变，先签副本再封成真实包；第22节验收的新包为 dev.4；重跑时新包按当前源码版本从冻结输入构建。消费脚本 `signing-cases.mjs` 仅通过公开 SDK 比较完整状态和恢复材料，不自行读写 SQL 或密钥；测试故障程序不进入正常 npm 包。


历史分页入口为 `python3 -B tools/platform_release/persistent_history.py`。它从保留的第22节 dev.4 归档复制并用新合成身份签署旧包副本，实际构建和签署 dev.5，在仓库外分别安装；原归档不改。`history-cases.mjs` 验证旧库、11种普通/未决/恢复窗口及旧新包往返；`history-live.mjs` 验证并发收发、重启续页、非法游标、长正文、真实锁定、自然256条上限及退出迟到结果。所有历史查询和恢复仅经公开 API，系统控制与故障程序留在维护者装置中。

```js
const first = await device.history({ direction: 'backward', page_size: 20 });
if (!first.done) {
  const second = await device.history({ direction: first.direction, page_size: first.page_size, cursor: first.next_cursor });
}
```

第一页固定本地提交位置上界；期间新增消息需新查询。短页仍可能有下一页，使用 `done` 判断。完整契约与本机范围见包内 README 和 `docs/端侧存储与附件管理.md` 第23节。
