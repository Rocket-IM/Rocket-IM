# Rocket-IM

面向现有业务接入的自托管即时通讯方案，采用 Go Service 与 Rust 客户端核心。

A self-hosted instant messaging project for integration into existing products, built around a Go Service and a Rust client core.

[中文](#中文) · [English](#english) · [开发路线 / Roadmap](docs/开发路线与检查清单.md) · [Issues](https://github.com/Rocket-IM/Rocket-IM/issues)

> **开发状态：阶段 0 验证中。** 当前提供隔离 POC、最小 SDK 包及固定双设备 Go Service 联网 Alpha，完整 IM Service、四端持久 SDK 与生产发布尚未交付。
>
> **Development status: stage 0 validation.** The repository contains isolated proofs of concept, minimal SDK packages and a fixed two-device Go Service network Alpha. The full IM Service, persistent SDKs for all four languages and production releases are not yet available.

## 中文

### 项目定位

Rocket-IM 的目标是让开发者部署独立 IM Service、安装客户端 SDK，并将即时通讯接入已有账号体系、业务后台与客户端界面。标准接入通过公开 SDK/API 完成，无需 fork、修改方案源码、复制 Demo 或直接访问 IM 数据表。

项目按以下方向设计：

- **自托管服务：** Go Service 独立运行、部署与升级，首期采用中心化、单租户、单实例的模块化单体。
- **共享客户端核心：** Rust 统一管理连接、消息队列、重试、同步、密码状态、本地 SQLite 与附件任务，平台层提供语言接口和系统适配。
- **保留业务与 UI 自主权：** SDK 不含 UI，接入方负责业务身份、界面和系统入口；示例应用用于演示与验收。
- **明确安全边界：** E2EE 与多设备默认开启，并可按既定策略关闭；登录、设备信任与历史密钥恢复分别处理。

### 架构与交付目标

以下为计划交付形态，当前实现范围见[当前进展](#当前进展)。

| 组件 | 交付形态与职责 |
|---|---|
| IM Service | Go + PostgreSQL；独立镜像与可执行文件，负责鉴权、设备/公钥目录、权限、消息持久化、投递及附件访问 |
| Rust SDK 核心 | 无 UI 的 Rust crate；共享消息与密码状态，统一持有 SQLite，管理附件编解码、加解密与传输任务 |
| Flutter SDK | Dart 包与预编译原生库；目标为 iOS / Android |
| Swift SDK | Swift Package + XCFramework；目标为 iOS |
| Kotlin SDK | Maven 包 + AAR/JNI；目标为 Android |
| TypeScript SDK | npm 包、JS 接口、类型声明与匹配的预编译运行产物；主要面向 macOS / Windows 桌面客户端，浏览器次要 |
| 业务服务端 SDK | Go HTTP API 客户端；对接业务用户映射、凭证和管理 API，不依赖 Service 内部包或 IM 数据表 |
| 示例与管理后台 | 各端公开 SDK 接入示例，以及可选 Vue 3 + TypeScript 管理后台 |

“四端 SDK”指 Flutter、Swift、Kotlin、TypeScript 四种语言交付。TypeScript 的最终桌面宿主与绑定按实测确定；原 Node 内存最小包使用预编译 Rust WASM，新增 macOS 持久联网包使用预编译 Rust 原生程序，浏览器包独立验证。

发布流程负责生成绑定和预编译产物。目标是让 Flutter / Swift / Kotlin / TypeScript 接入方正常构建自己的应用，无需 Rust/Cargo 或绑定生成器；Service 使用者无需 Go 工具链。Rust crate 使用者按 Rust 工具链集成。

预期接入流程：

1. 部署 Service 和存储，配置 HTTPS/WSS、持久化与运行参数。
2. 业务后台验证已有账号，通过公开 API 完成 IM 用户映射并取得受限凭证。
3. 客户端安装对应 SDK，提供 Service 地址和凭证，完成设备授权与连接。
4. 自有 UI 通过 SDK 的查询、命令与事件访问消息，并接入推送及业务事件。

正式安装坐标、部署命令与支持矩阵将在发布时提供；当前开发验证入口见[开始开发](#开始开发)。

### 功能规划

以下是已确认的产品范围，完整验收条件见[功能分期与验收](docs/功能分期与验收.md)。

| 分期 | 范围 |
|---|---|
| 第一期 · 21 项 | 登录/注册与业务接入；文字、图片、视频、语音消息；多设备、多账号、可选 E2EE；会话列表、聊天、历史与状态同步；用户、好友和群管理；可靠投递、离线推送、设备授权与历史恢复；账号生命周期、附件完整流程、举报及解决方案接入 |
| 第二期 · 12 项 | 编辑、撤回、转发、引用回复、表情回应、收藏、全文搜索、输入状态、在线状态、跨端草稿、语音转文字、音视频通话 |

第一期 21 项及四端独立交付均属于一期验收范围。工程阶段 0—4 表示实施顺序，完整功能与发布门槛仍以产品分期为准。

### 当前进展

状态核对：**2026-11-25**。阶段0仍未通过；用户已授权先整合有限的双持久端 SDK 开发版本，其验收单独记录。

| 已有工作 | 当前边界与记录 |
|---|---|
| 独立 Rust 内存核心与四端最小包 | 验证双设备建群、加解密、版本检查和独立包消费；包含限定跨端互通。这些原内存包无网络、SQLite、业务登录、完整同步或附件能力。见[最小包验证](docs/四端最小发布验证.md)、[互通验证](docs/四端互通验证.md) |
| 有限双持久端 SDK 开发版本 | Rust 持久化核心和 macOS arm64 TypeScript 包，固定两个测试成员、显式公钥核验、普通加入、双向消息及未决恢复；完整候选精确安装，无候选由双方签名授权后继，同一原库保留身份、历史与请求。本机有限验收通过；开发包已接入 SQLCipher、专用系统钥匙串及显式本地退出，覆盖真实拒绝、重启、隔离和清理。另已通过合成自签身份下 dev.3→dev.4 的原身份/历史/恢复材料连续性与错签名拒绝，见[签名升级验收](docs/端侧存储与附件管理.md#22-sdk-签名升级与原身份连续性2026-10-21)。dev.5 新增本地已提交收发历史和稳定分页，保留旧库/身份及256条限额；并发追加、重启续页、恢复及系统拒绝均通过[本地分页验收](docs/端侧存储与附件管理.md#23-sdk-本地消息历史与稳定分页2026-10-21)。上述 dev.5 本地包无 Service 网络或 Windows 产物，非生产安全验收。见[秘密保护范围与验收](docs/端侧存储与附件管理.md#21-sdk-系统秘密保护与本地退出2026-10-21) |
| Go Service + Rust 联网文本 Alpha | `src/backend/` 的真正 Go/PostgreSQL 服务，TLS 设备鉴权、固定公钥、幂等接受及持久信箱；dev.6 macOS arm64/Node 包由 Rust 自动建群、发送、重连、双游标补拉和送达状态。实际包的双向收发、离线多页、丢 ACK/超时、进程与提交边界恢复、越权及篡改拒绝单独验收。仅固定两个测试设备、单会话文本，不等于一期或阶段0完成。见[本机运行](deploy/README.md)及[联网验收](docs/端侧存储与附件管理.md#24-go-service与rust联网文本-alpha2026-11-24) |
| 业务身份接入与 Go 服务端 SDK | 新增公开用户映射、固定设备公钥绑定、短期凭证及单凭证失效；独立Go模块只用标准库，业务后台保留自己的登录。真实版本化模块与dev.6包的本机接入验收见[业务身份记录](docs/端侧存储与附件管理.md#25-业务身份接入与-go-服务端-sdk2026-11-24)，公开接入见[Go SDK](src/server-sdk/go/README.md)与[业务示例](examples/business-backend/README.md)。目录公钥仍需独立核验；不包含动态成员或完整账号生命周期 |
| 客户端自动凭证续期 | dev.7 由Rust管理真实到期、单次在途认证、有界退避和重连；TypeScript只提供可替换业务认证回调。最终实际包通过直连15组、故障16组、原联网14组、业务5组及退出HTTP专项1组验收，覆盖原密文恢复、跨账号/Service/设备隔离、退出取消及迟到结果。仅本机固定双设备范围，见[续期验收与产物](docs/端侧存储与附件管理.md#26-客户端自动凭证续期2026-11-24) |
| 固定双端联网后继恢复 | dev.8由Rust交换原身份签名的恢复材料，双方明确授权后续接；保留原身份、公钥和历史，旧队列按真实接受/送达事实记录终态，不重加密原请求。实际新包、Go/PostgreSQL、双Node进程和版本化Go SDK的本机验收见[恢复验收与产物](docs/端侧存储与附件管理.md#27-固定双端联网后继恢复2026-11-24)。固定双设备单会话范围；完整阶段0、生产和分发仍未完成/批准 |
| 联网持久包签名升级 | 真实dev.7→dev.8包在同一新合成签名要求下完成本机验收：原身份、公钥、历史分页、原请求/密文/接受事实与双游标连续；普通混合版本可收发，恢复须双方升级并明确授权，旧版拒读新版恢复状态。54组含重复回归，错签名/装配及锁定边界分别验证，256条限额不变。见[升级范围、产物与证据](docs/端侧存储与附件管理.md#28-联网持久包跨版本签名升级2026-11-24)；不代表生产签名或防回滚 |
| 联网持久数据同机备份恢复 | dev.9新增公开加密备份/恢复，Rust拥有完整快照、钥匙串进度与原子安装；仅同机原路径/空间/系统秘密，过旧备份明确拒绝。真实包64组通过，原身份/历史/队列/接受事实/游标连续，执行未知仍须明确授权后继。见[恢复范围、用法与证据](docs/端侧存储与附件管理.md#29-联网持久数据同机备份恢复2026-11-24)。不包含跨设备秘密导出、Service回滚或全盘共同回滚证明 |
| Service停服备份与受控恢复 | Service 0.1.0-alpha.4新增schema4和离线维护CLI，依赖数据库之外幸存的维护记录，仅将最新封存状态恢复到新空数据库。逐项保持接受事实、事件、凭证撤销和后继材料；未正常封存明确阻断。真实产物与独立dev.9消费的52组验收、用法和限制见[服务备份恢复](docs/服务备份恢复.md)。不代表自动崩溃恢复、共同回滚证明或生产灾备 |
| Service异常退出对账 | alpha.5新增显式启用schema5及离线`reconcile`，提交前将完整候选承诺保存在独立维护记录中，提交后持久确认才开放成功结果。仅精确对应的完整状态允许重开，缺证据/分叉继续拒绝；真实产物与独立SDK消费83组、Go/race32项通过。见[异常对账契约](docs/服务备份恢复.md#7-异常退出对账契约与验收)。独立记录幸存、无其他写入者为前提，共同回退仍不可判定 |
| 现有限额容量与时延 | 同机独立两轮各完成256条真实E2EE，另实测Service第257条明确拒绝；9套91组、35项Go/race通过，短凭证续期、取消、近满/满额恢复和原件连续性已验收。该dev.9基线中的未接受队列会阻塞补拉，大正文可能先触及端侧字节预算；该轮限额及运行版本未变。测量口径和限制见[容量与时延验收](docs/服务备份恢复.md#8-现有限额容量与时延验收)，不作生产容量承诺 |
| 永久容量拒绝与补拉 | dev.10将已证明的Service容量拒绝持久化为rejected，原请求、密文和历史留在既有有界账本。真实第257条拒绝后双方游标达到256；原库升级、恢复、故障和续期共12套122组通过。普通256消息/1024请求及字节预算不变，Service仍alpha.5；请求或字节耗尽仍明确失败。见[契约、产物与验收](docs/端侧存储与附件管理.md#30-永久容量拒绝与补拉连续性2026-11-24)，仅限macOS arm64/Node本机范围 |
| 长期预算策略 | 已完成当前源码和策略文档核对：保留已持久原件/幂等、到限停止相应新写，区分恢复有效状态与释放容量。备份不重置额度，任意满额库同步追平未保证；该策略轮的容量诊断、同步/恢复专用余量、扩容和归档尚未实现。见[策略与验收边界](docs/端侧存储与附件管理.md#budget-policy-20261125)，本项无新增运行验收 |
| 容量诊断与有限余量设计 | 完成一致快照/公开诊断契约、按完整候选与原件计额的有限预留设计及内部验证。实际MLS最大控制字符正文接收22条后字节拒绝；1024请求、近Data/Meta、完整候选、16轮及4096认证/撤销边界分列核验。现有预算不能保证所有合法输入追平或全量导出；该设计轮未实现诊断API和预留机制，未重发包。见[设计与证据](docs/端侧存储与附件管理.md#capacity-reserve-design-20261125) |
| 只读容量诊断 | dev.11提供Rust/TS同SQLite快照查询，Service alpha.6提供设备自身范围及显式授权的全局查询，Go SDK alpha.2封装公开接口。精确字节、候选/恢复阶段与多项阻断分列；硬余量不代表预留或成功许可。实际包、旧库/备份兼容及验证范围见[端侧第33节](docs/端侧存储与附件管理.md#capacity-readonly-20261125)与[Service第11节](docs/服务备份恢复.md#service-capacity-readonly-20261125)。未改变原准入、限额或持久格式，受保护预留仍未实现 |
| 密码与消息协议 POC | 隔离验证设备注册与首次信任、签名权限、发送顺序、精确重试、双游标、已读及回收恢复等路径。网络 Relay 是 Python HTTP/SQLite 实验装置，身份与独立信任输入仍有合成边界。见[安全模型](docs/安全与身份模型.md)、[协议草案](docs/消息协议草案.md) |
| 原生与浏览器存储 POC | 验证 Rust 管理的显式事务、密码状态共同提交、崩溃恢复及独立锚；另有 macOS 受保护存储实验。尚未整合到四端内存 SDK。见[端侧存储](docs/端侧存储与附件管理.md)、[浏览器存储](docs/浏览器存储验证.md) |

已有有限 Go Service Alpha 与 Go 业务身份 SDK；完整 Service、完整管理 SDK、产品 Demo 与管理后台尚未实现。Windows Node 运行、移动真机、完整安全/容量及生产发布验收仍未完成；模拟器、本机或浏览器结果仅适用于各自记录的环境。剩余条件集中维护在[开发路线与检查清单](docs/开发路线与检查清单.md)。

### 开始开发

当前可从源码了解架构、运行核心测试或复现实验。先获取仓库：

```sh
git clone https://github.com/Rocket-IM/Rocket-IM.git
cd Rocket-IM
```

**Rust 内存核心验证：** 准备 Rust/Cargo **1.98.1**（以 [rust-toolchain.toml](src/sdk/rust/rust-toolchain.toml) 为准）及系统原生构建工具，在仓库根目录执行：

```sh
cargo +1.98.1 test --manifest-path src/sdk/rust/Cargo.toml \
  --locked --release -p rocket-crypto-core -p rocket-im-sdk
```

这会运行现有内存核心与公共边界的自动化测试。首次执行需要下载锁文件对应的依赖，或事先准备依赖缓存。

**平台包与 POC 验证：** 按[四端最小发布验证](docs/四端最小发布验证.md)、[端侧代码生成](docs/端侧代码生成.md)及各存储文档准备固定工具链、生成器与目标环境。维护者脚本中仍有本机路径和离线缓存配置，全新机器重建尚未完整验收。

`dist/` 中的包、逐轮报告、失败记录及源码快照不纳入 Git。专项文档的 `dist/` 链接用于定位验证机器上的历史材料，纯源码克隆无法直接访问；公开证据归档与正式下载渠道仍待建立。历史产物须按对应名称、版本和摘要核对，不能混用旧实验状态与新代码，详见[工程名称统一](docs/工程名称统一.md)。

### 仓库结构

以下列出已存在的主要源码目录：

```text
Rocket-IM/
├── api/                 # 阶段 0 实验协议源
├── src/backend/         # 固定双设备Go/PostgreSQL Alpha
├── deploy/              # 本机TLS配置与运行说明
├── src/sdk/             # Rust核心、四种最小包及macOS持久联网包
│   ├── rust/
│   ├── flutter/
│   ├── swift/
│   ├── kotlin/
│   └── typescript/      # 浏览器与 node/ 目标分别管理
├── poc/                 # 密码、网络及原生/浏览器存储隔离实验
├── tests/               # 独立发布包消费者与跨组件验证
├── tools/               # 构建、生成、打包与验证入口
├── docs/                # 设计、验收与验证记录
├── AGENTS.md            # 项目协作规则
└── README.md
```

Go 实现归 `src/backend/`，部署配置归 `deploy/`；独立业务 SDK 已在 `src/server-sdk/go/`，认证接入示例在 `examples/business-backend/`，各端完整应用示例 `src/apps/` 尚未建立。文件落位与依赖方向见[项目文件结构](docs/项目文件结构.md)。

### 文档导航

| 主题 | 文档 |
|---|---|
| 产品与接入 | [交付物与技术栈](docs/交付物与技术栈.md) · [功能分期与验收](docs/功能分期与验收.md) |
| 架构与推进 | [项目文件结构](docs/项目文件结构.md) · [开发路线与检查清单](docs/开发路线与检查清单.md) |
| 安全与密码 | [安全与身份模型](docs/安全与身份模型.md) · [密码方案验证](docs/密码方案验证.md) |
| 消息契约 | [消息协议草案](docs/消息协议草案.md) |
| SDK 包与互通 | [四端最小发布验证](docs/四端最小发布验证.md) · [四端互通验证](docs/四端互通验证.md) |
| 绑定与版本 | [端侧代码生成](docs/端侧代码生成.md) · [工程名称统一](docs/工程名称统一.md) |
| 本地存储与附件 | [端侧存储与附件管理](docs/端侧存储与附件管理.md) · [浏览器存储验证](docs/浏览器存储验证.md) |

### 开发路线

| 工程阶段 | 目标 |
|---|---|
| 0 · 当前 | 验证密码与身份、协议、端侧存储、恢复及最小包交付，关闭阶段出口问题 |
| 1 | 建立 Go Service 与 Rust SDK 的可靠消息闭环 |
| 2 | 补齐第一期完整功能 |
| 3 | 完成独立业务接入与发布交付 |
| 4 | 完成安全、容量与实际运行验收 |

每阶段依据源码、产物和运行证据验收，详细任务与未完成条件见[开发路线](docs/开发路线与检查清单.md)。

### 安全设计

以下原则约束正式实现，当前 POC 仅验证其中的限定路径：

- 会话创建时固定加密模式；第一期变更模式需新会话。加密失败或版本不兼容明确报错。
- E2EE 正文、附件、缩略图与封面在端侧保护，用户解密私钥由设备持有；Service 仍可观察路由、时间、大小和 IP 等元数据。非 E2EE 模式需明确标识服务器可读范围。
- 业务登录、设备密码身份和历史恢复分别验证；撤销无法收回已保存的副本，服务器备份也不等于历史密钥恢复。
- 凭证、密钥、数据库、队列、游标和回调按服务实例与账号隔离；消息与相关状态成功提交后，才派发对应的数据成功事件。
- 日志、推送和公开问题报告不得包含凭证、私钥或 E2EE 正文；举报仅披露用户确认的选定证据。

完整信任假设、待验证问题与恢复限制见[安全与身份模型](docs/安全与身份模型.md)。

### 参与贡献

问题、文档修正与功能建议可通过 [Issues](https://github.com/Rocket-IM/Rocket-IM/issues) 提交。修改前阅读 [AGENTS.md](AGENTS.md) 与[项目文件结构](docs/项目文件结构.md)，保持既定模块边界、锁文件及工具链配置。

提交修复时附复现步骤、环境与版本、预期/实际结果和验证范围，区分通过、失败与未执行；使用脱敏样本，保留原失败记录。

### 许可证

**项目许可证尚未确定，仓库当前没有 `LICENSE` 文件。** 正式发布前需完成项目许可证选择与第三方分发成分核对；现有依赖许可采集记录见[密码方案验证](docs/密码方案验证.md)和[最小包验证](docs/四端最小发布验证.md)。

## English

### About

Rocket-IM aims to let developers deploy an independent IM Service, install client SDKs and integrate messaging into existing accounts, business backends and client interfaces. Standard integration uses public SDKs and APIs without requiring a fork, source changes, copied demos or direct access to IM database tables.

The project follows these design goals:

- **Self-hosted service:** an independently deployed and upgraded Go Service, initially a centralized, single-tenant, single-instance modular monolith.
- **Shared client core:** Rust owns connections, queues, retries, synchronization, cryptographic state, local SQLite and attachment tasks. Platform layers provide language APIs and system adapters.
- **Application-owned business logic and UI:** SDKs contain no UI. Integrators retain their identity system, interface and platform entry points; demos support demonstration and acceptance testing.
- **Explicit security boundaries:** E2EE and multiple devices are enabled by default and can be disabled under the defined policies. Sign-in, device trust and historical key recovery are separate concerns.

### Architecture and planned deliverables

These are the intended deliverables. See [Current progress](#current-progress) for the implemented scope.

| Component | Deliverable and responsibility |
|---|---|
| IM Service | Go + PostgreSQL; independent images and executables for authentication, device/public-key directories, authorization, message persistence, delivery and attachment access |
| Rust SDK core | UI-free Rust crate; shared message and cryptographic state, sole ownership of SQLite, and attachment encoding/decoding, encryption/decryption and transfers |
| Flutter SDK | Dart package and precompiled native libraries; targeting iOS / Android |
| Swift SDK | Swift Package + XCFramework; targeting iOS |
| Kotlin SDK | Maven package + AAR/JNI; targeting Android |
| TypeScript SDK | npm package, JS APIs, type declarations and matching precompiled runtime artifacts; primarily targeting macOS / Windows desktop clients, with browsers secondary |
| Business backend SDK | Go HTTP API client for user mapping, credentials and management APIs; no dependency on Service internal packages or IM tables |
| Examples and admin console | Public SDK integration examples and an optional Vue 3 + TypeScript admin console |

The four SDKs refer to four language deliveries: Flutter, Swift, Kotlin and TypeScript. The final TypeScript desktop host and bindings require their own tests. The original in-memory Node package uses precompiled Rust WASM; the new macOS persistent network package uses a precompiled native Rust executable. Browser packages are validated separately.

The release process will generate bindings and precompile runtime artifacts. Flutter / Swift / Kotlin / TypeScript consumers should build their applications without Rust/Cargo or binding generators; Service consumers should not need Go tooling. Rust crate consumers use the Rust toolchain normally.

Intended integration flow:

1. Deploy the Service and storage; configure HTTPS/WSS, persistence and operational settings.
2. Have the business backend verify existing accounts, map IM users and obtain scoped credentials through public APIs.
3. Install a client SDK, provide the Service address and credentials, authorize the device and connect.
4. Use SDK queries, commands and events in the application UI, with push notifications and business event integration.

Official package coordinates, deployment commands and support matrices will accompany releases. Current development entry points are described in [Getting started](#getting-started).

### Feature roadmap

The confirmed product scope is defined in [Feature Phases and Acceptance](docs/功能分期与验收.md).

| Product phase | Scope |
|---|---|
| Phase one · 21 items | Sign-up/sign-in and business integration; text, image, video and voice messages; multiple devices, multiple accounts and optional E2EE; conversations, chat, history and state synchronization; users, friends and groups; reliable delivery, offline push, device authorization and history recovery; account lifecycle, complete attachment workflows, abuse reporting and solution integration |
| Phase two · 12 items | Editing, recall, forwarding, quoted replies, reactions, favorites, full-text search, typing indicators, presence, cross-device drafts, speech-to-text and audio/video calls |

All 21 phase-one items and independent delivery of all four SDKs belong to phase-one acceptance. Engineering stages 0–4 describe implementation order; product phases still define the complete feature and release requirements.

### Current progress

Status reviewed: **2026-11-25**. Stage 0 remains incomplete. The user has authorized an earlier, limited SDK development package with two persistent endpoints; its acceptance is recorded separately.

| Existing work | Scope and records |
|---|---|
| Independent Rust in-memory core and minimal platform packages | Two-device group creation, encryption/decryption, version checks and independent package consumption, with limited cross-platform interoperability. These original in-memory packages have no networking, SQLite, business sign-in, complete synchronization or attachments. See [Package Validation](docs/四端最小发布验证.md) and [Interoperability Validation](docs/四端互通验证.md) |
| Limited SDK development package with two persistent endpoints | Rust persistence and a macOS arm64 TypeScript package for two fixed test members, pinned public keys, ordinary joining, bidirectional messages and pending-operation recovery. Durable candidates install exactly; missing candidates use a successor authorized by both pinned endpoints, preserving identities, history and requests in the original databases. Scoped local acceptance has passed. The development package now integrates SQLCipher, a dedicated system keychain and explicit local logout, with actual refusal, restart, isolation and cleanup checks. Synthetic self-signed dev.3→dev.4 upgrades also preserve identities, history and recovery material, with mismatched signatures refused; see [Signature upgrade acceptance](docs/端侧存储与附件管理.md#22-sdk-签名升级与原身份连续性2026-10-21). dev.5 adds locally committed sent/received history and stable pagination while preserving old databases, identities and the 256-message limit; concurrent appends, restart continuation, recovery and system refusals passed [Local history acceptance](docs/端侧存储与附件管理.md#23-sdk-本地消息历史与稳定分页2026-10-21). The dev.5 local package described above has no Service networking or Windows artifact; this is not production security acceptance. See [Secret protection scope and acceptance](docs/端侧存储与附件管理.md#21-sdk-系统秘密保护与本地退出2026-10-21) |
| Go Service + Rust network text Alpha | A real Go/PostgreSQL service in `src/backend/`, with TLS device authentication, pinned identities, idempotent acceptance and durable mailboxes. The dev.6 macOS arm64/Node package delegates group setup, sending, reconnects, dual-cursor sync and delivery state to Rust. Actual package acceptance covers bidirectional messages, offline pages, lost ACKs/timeouts, process and commit-boundary recovery, scope denial and tampering. Limited to two fixed test devices and one text conversation; not stage-0 or phase-one completion. See [Local operation](deploy/README.md) and [Network acceptance](docs/端侧存储与附件管理.md#24-go-service与rust联网文本-alpha2026-11-24) |
| Business identity integration and Go server SDK | Public user mapping, fixed public-key binding, short-lived device credentials and individual credential invalidation. The independent Go module uses only the standard library; business login remains with the integrating backend. Actual versioned-module and dev.6 consumption is recorded in [Business identity acceptance](docs/端侧存储与附件管理.md#25-业务身份接入与-go-服务端-sdk2026-11-24); see the [Go SDK](src/server-sdk/go/README.md) and [business example](examples/business-backend/README.md). Public keys still require independent verification. Dynamic membership and full account lifecycle are excluded |
| Automatic client credential renewal | dev.7 keeps real expiry, one in-flight authentication request, bounded backoff and reconnects in Rust; TypeScript supplies a replaceable business authentication callback. The final actual package passed 15 direct-connection, 16 fault, 14 networking-regression, 5 business-regression groups and one logout HTTP check, including original-ciphertext recovery, account/Service/device isolation, cancellation and late results. Limited to the local fixed-two-device scope; see [Renewal acceptance and artifacts](docs/端侧存储与附件管理.md#26-客户端自动凭证续期2026-11-24) |
| Fixed two-device network successor recovery | dev.8 lets Rust exchange recovery materials signed by the original identities after explicit consent from both endpoints. Identities, public keys and history are retained; old queues reach truthful acceptance/delivery outcomes without re-encrypting original requests. Actual package, Go/PostgreSQL, two independent Node processes and versioned Go SDK acceptance are recorded in [Recovery acceptance and artifacts](docs/端侧存储与附件管理.md#27-固定双端联网后继恢复2026-11-24). Limited to two fixed devices and one conversation; stage 0, production and distribution remain incomplete or unapproved |
| Signed upgrades of the persistent networking package | Real dev.7→dev.8 packages passed local acceptance under one fresh synthetic signing requirement, preserving identities, public keys, history pagination, original requests/ciphertext/acceptance and dual cursors. Ordinary mixed-version traffic works; recovery requires both endpoints to upgrade and explicitly consent, and old readers reject new recovery state. The 54 groups include repeated regressions; signing, assembly and lock boundaries are checked separately, with the 256-message limit unchanged. See [Upgrade scope, artifacts and evidence](docs/端侧存储与附件管理.md#28-联网持久包跨版本签名升级2026-11-24). This is neither production signing nor anti-rollback validation |
| Same-machine backup and restore of persistent network data | dev.9 adds public encrypted backup/restore APIs, with Rust owning complete snapshots, keychain progress and atomic installation. Limited to the original machine, path, scope and system secrets; stale backups are refused. The actual package passed 64 groups preserving identities, history, queues, acceptance facts and cursors; unknown execution still requires explicit successor consent. See [Scope, usage and evidence](docs/端侧存储与附件管理.md#29-联网持久数据同机备份恢复2026-11-24). Cross-device secret export, Service rollback and joint full-state rollback proofs are excluded |
| Controlled Service backup and restore after shutdown | Service 0.1.0-alpha.4 adds schema4 and an offline maintenance CLI. A surviving record outside the database binds the latest sealed state to a fresh empty target. Acceptance facts, events, credential revocations and successor materials are retained; unsealed runs are blocked. See [Service backup and restore](docs/服务备份恢复.md) for 52 acceptance groups using the actual executable and independent dev.9 consumers, usage and limits. Automatic crash recovery, joint rollback proofs and production disaster recovery are excluded |
| Service reconciliation after abnormal exit | alpha.5 adds explicit schema5 enablement and offline `reconcile`. An independent record commits to the full candidate before the database commit; success is exposed only after durable external completion. Only exact matching states may reopen; missing evidence and forks remain blocked. Scoped acceptance passed 83 actual-artifact/independent-consumer groups and 32 Go/race tests; see [Reconciliation contract](docs/服务备份恢复.md#7-异常退出对账契约与验收). The independent record must survive without rollback and there must be no other writers; joint rollback remains indeterminate |
| Capacity and latency within existing limits | Two independent local runs each completed 256 real E2EE messages; a separate real 257th send was explicitly rejected by the Service. Nine suites/91 groups and 35 Go/race tests passed, covering short credential renewal, cancellation, near/full-capacity recovery and original-fact continuity. In that dev.9 baseline, a retained unaccepted send blocks further synchronization, and larger payloads may hit local byte budgets first. That run kept limits and runtime versions unchanged. See [Capacity and latency acceptance](docs/服务备份恢复.md#8-现有限额容量与时延验收) for measurements and scope; this is not a production capacity claim |
| Permanent capacity rejection and continued synchronization | dev.10 durably marks proven Service capacity refusals as rejected while preserving original requests, ciphertext and history in the existing bounded ledger. After a real 257th rejection, both endpoints reach cursor 256; twelve suites/122 groups cover original-database upgrade, recovery, faults and renewal. The 256 ordinary-message/1024-request and byte budgets remain unchanged, as does Service alpha.5; exhausted request or byte budgets still fail explicitly. See [Contract, artifacts and acceptance](docs/端侧存储与附件管理.md#30-永久容量拒绝与补拉连续性2026-11-24), scoped to local macOS arm64/Node |
| Long-term budget policy | Current source and policy documentation reviewed: preserve persisted originals and idempotency, stop affected new writes at capacity, and distinguish restoring valid state from freeing capacity. Backups do not reset quotas; synchronization cannot be guaranteed for every full database. At that policy-only checkpoint, capacity diagnostics, protected synchronization/recovery reserves, expansion and archival were unimplemented. See [Policy and acceptance boundaries](docs/端侧存储与附件管理.md#budget-policy-20261125); no new runtime acceptance was performed |
| Capacity diagnostics and finite reserve design | Completed the consistent-snapshot/public diagnostic contract, a finite reserve design counting complete candidates and retained originals, and internal verification. Real MLS reception hit the byte preflight after 22 maximum control-character messages; 1024 requests, near Data/Meta limits, complete candidates, 16 rounds and full-ledger authentication/revocation were checked separately. Existing budgets cannot guarantee catch-up or full export for every valid input. At that design checkpoint, diagnostic APIs and reserves were unimplemented; no package was reissued. See [Design and evidence](docs/端侧存储与附件管理.md#capacity-reserve-design-20261125) |
| Read-only capacity diagnostics | dev.11 exposes a Rust/TypeScript query from one SQLite snapshot; Service alpha.6 adds own-device and explicitly authorized global queries, wrapped by Go SDK alpha.2. Exact byte usage, candidate/recovery stages and multiple blockers are reported separately; hard headroom grants neither a reservation nor execution permission. See [Client section 33](docs/端侧存储与附件管理.md#capacity-readonly-20261125) and [Service section 11](docs/服务备份恢复.md#service-capacity-readonly-20261125) for actual-package, old-store/backup compatibility and scoped verification. Existing admission, limits and persistence formats remain unchanged; protected reserves are still unimplemented |
| Cryptographic and message protocol POCs | Isolated paths for device registration and first trust, signed permissions, send ordering, exact retries, dual cursors, read receipts and reclamation recovery. The network Relay is a Python HTTP/SQLite test harness; identity and independent trust inputs retain synthetic boundaries. See [Security Model](docs/安全与身份模型.md) and [Protocol Draft](docs/消息协议草案.md) |
| Native and browser storage POCs | Rust-owned explicit transactions, joint cryptographic-state commits, crash recovery and independent anchors, plus a macOS protected-storage experiment. These are not integrated into the in-memory platform SDKs. See [Client Storage](docs/端侧存储与附件管理.md) and [Browser Storage](docs/浏览器存储验证.md) |

A limited Go Service Alpha and Go business identity SDK are implemented; the full Service, full management SDK, product demos and admin console remain incomplete. Windows Node execution, physical mobile devices, full security/capacity checks and production release acceptance remain incomplete. Simulator, local-machine and browser results apply only to their recorded environments. Remaining criteria are maintained in the [Development Roadmap and Checklist](docs/开发路线与检查清单.md).

### Getting started

The current source supports architecture review, core tests and experiment reproduction. Obtain the repository:

```sh
git clone https://github.com/Rocket-IM/Rocket-IM.git
cd Rocket-IM
```

**Test the Rust in-memory core:** prepare Rust/Cargo **1.98.1**, as pinned in [rust-toolchain.toml](src/sdk/rust/rust-toolchain.toml), and native build tools for your system. Run from the repository root:

```sh
cargo +1.98.1 test --manifest-path src/sdk/rust/Cargo.toml \
  --locked --release -p rocket-crypto-core -p rocket-im-sdk
```

This runs automated tests for the existing in-memory core and its public boundary. The first run requires downloading the locked dependencies or preparing a dependency cache.

**Platform packages and POCs:** follow [Minimal Package Validation](docs/四端最小发布验证.md), [Binding Generation](docs/端侧代码生成.md) and the storage documents to prepare the fixed toolchains, generators and target environments. Maintainer scripts still contain local paths and offline-cache settings. A complete rebuild on a fresh machine has not been validated.

Packages, per-run reports, failures and source snapshots under `dist/` are excluded from Git. Links to `dist/` in detailed documents locate historical materials on the validation machine and are unavailable in a source-only clone. Public evidence archives and official downloads are pending. Match historical artifacts by name, version and hash; old experimental state must not be mixed with new code. See [Project Naming Migration](docs/工程名称统一.md).

### Repository structure

The main source directories currently present are:

```text
Rocket-IM/
├── api/                 # Stage 0 experimental protocol sources
├── src/backend/         # Fixed two-device Go/PostgreSQL Alpha
├── deploy/              # Local TLS configuration and operation
├── src/sdk/             # Rust core, minimal packages and macOS persistent networking
│   ├── rust/
│   ├── flutter/
│   ├── swift/
│   ├── kotlin/
│   └── typescript/      # Separate browser and node/ targets
├── poc/                 # Isolated crypto, network and native/browser storage POCs
├── tests/               # Independent package consumers and integration checks
├── tools/               # Build, generation, packaging and validation entry points
├── docs/                # Design, acceptance and validation records
├── AGENTS.md            # Project collaboration rules
└── README.md
```

Go implementation lives in `src/backend/` and deployment configuration in `deploy/`. The independent business SDK is in `src/server-sdk/go/`, with an authentication example in `examples/business-backend/`. Full application examples in `src/apps/` have not been created. Placement and dependency rules are defined in [Project Structure](docs/项目文件结构.md).

### Documentation

The detailed documents are currently maintained in Chinese.

| Topic | Documents |
|---|---|
| Product and integration | [Deliverables and Technology Stack](docs/交付物与技术栈.md) · [Feature Phases and Acceptance](docs/功能分期与验收.md) |
| Architecture and implementation | [Project Structure](docs/项目文件结构.md) · [Development Roadmap and Checklist](docs/开发路线与检查清单.md) |
| Security and cryptography | [Security and Identity Model](docs/安全与身份模型.md) · [Cryptographic Validation](docs/密码方案验证.md) |
| Message contracts | [Message Protocol Draft](docs/消息协议草案.md) |
| SDK packages and interoperability | [Minimal Package Validation](docs/四端最小发布验证.md) · [Interoperability Validation](docs/四端互通验证.md) |
| Bindings and versions | [Binding Generation](docs/端侧代码生成.md) · [Project Naming Migration](docs/工程名称统一.md) |
| Local storage and attachments | [Client Storage and Attachment Management](docs/端侧存储与附件管理.md) · [Browser Storage Validation](docs/浏览器存储验证.md) |

### Development stages

| Engineering stage | Goal |
|---|---|
| 0 · Current | Validate cryptography, identity, protocols, client storage, recovery and minimal package delivery; resolve the exit criteria |
| 1 | Establish a reliable messaging loop across the Go Service and Rust SDK |
| 2 | Complete all phase-one features |
| 3 | Complete independent business integration and release delivery |
| 4 | Complete security, capacity and operational acceptance |

Each stage requires source, artifacts and runtime evidence. Detailed tasks and open criteria are in the [Development Roadmap](docs/开发路线与检查清单.md).

### Security design

These principles govern the formal implementation. Current POCs validate only limited paths:

- Fix encryption mode at conversation creation; phase-one mode changes require a new conversation. Encryption failures and incompatible versions return explicit errors.
- Protect E2EE bodies, attachments, thumbnails and covers on clients, with user decryption keys held by devices. The Service can still observe routing, timing, size and IP metadata. Non-E2EE mode must identify server-readable content.
- Validate business sign-in, cryptographic device identity and history recovery separately. Revocation cannot retrieve existing copies, and server backups do not restore historical keys.
- Isolate credentials, keys, databases, queues, cursors and callbacks by Service instance and account. Emit corresponding data-success events only after messages and related state commit successfully.
- Keep credentials, private keys and E2EE bodies out of logs, push payloads and public issue reports. Abuse reports disclose only evidence selected and approved by the user.

See [Security and Identity Model](docs/安全与身份模型.md) for complete trust assumptions, open questions and recovery limits.

### Contributing

Use [Issues](https://github.com/Rocket-IM/Rocket-IM/issues) for bugs, documentation corrections and feature proposals. Read [AGENTS.md](AGENTS.md) and [Project Structure](docs/项目文件结构.md) before making changes. Preserve the module boundaries, lockfiles and toolchain configuration.

Include reproduction steps, environment and versions, expected/actual results and validation scope. Distinguish passed, failed and unexecuted checks, use sanitized samples and retain original failure records.

### License

**The project license is undecided; this repository currently has no `LICENSE` file.** Project licensing and third-party distribution contents must be reviewed before a formal release. Existing dependency-license records are described in [Cryptographic Validation](docs/密码方案验证.md) and [Package Validation](docs/四端最小发布验证.md).
