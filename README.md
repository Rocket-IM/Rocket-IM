# Rocket-IM

面向现有业务接入的自托管即时通讯方案，采用 Go Service 与 Rust 客户端核心。

A self-hosted instant messaging project for integration into existing products, built around a Go Service and a Rust client core.

[中文](#中文) · [English](#english) · [开发路线 / Roadmap](docs/开发路线与检查清单.md) · [Issues](https://github.com/Rocket-IM/Rocket-IM/issues)

> **开发状态：阶段 0 验证中。** 当前提供隔离 POC 和最小 SDK 包实验，正式 IM Service、完整 SDK 与生产发布尚未交付。
>
> **Development status: stage 0 validation.** The repository contains isolated proofs of concept and minimal SDK package experiments. The full IM Service, complete SDKs and production releases are not yet available.

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

“四端 SDK”指 Flutter、Swift、Kotlin、TypeScript 四种语言交付。TypeScript 的最终桌面宿主与绑定按实测确定；当前 Node 最小包使用预编译 Rust WASM，浏览器包独立验证。

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

状态核对：**2026-10-10**。项目仍处于阶段 0，完整阶段出口尚未通过。

| 已有工作 | 当前边界与记录 |
|---|---|
| 独立 Rust 内存核心与四端最小包 | 验证双设备建群、加解密、版本检查和独立包消费；包含限定跨端互通。当前实验 SDK 无网络、SQLite、业务登录、完整同步或附件能力。见[最小包验证](docs/四端最小发布验证.md)、[互通验证](docs/四端互通验证.md) |
| 密码与消息协议 POC | 隔离验证设备注册与首次信任、签名权限、发送顺序、精确重试、双游标、已读及回收恢复等路径。网络 Relay 是 Python HTTP/SQLite 实验装置，身份与独立信任输入仍有合成边界。见[安全模型](docs/安全与身份模型.md)、[协议草案](docs/消息协议草案.md) |
| 原生与浏览器存储 POC | 验证 Rust 管理的显式事务、密码状态共同提交、崩溃恢复及独立锚；另有 macOS 受保护存储实验。尚未整合到四端内存 SDK。见[端侧存储](docs/端侧存储与附件管理.md)、[浏览器存储](docs/浏览器存储验证.md) |

正式 Go Service、业务服务端 SDK、产品 Demo 与管理后台尚未实现。Windows Node 运行、移动真机、完整安全/容量及生产发布验收仍未完成；模拟器、本机或浏览器结果仅适用于各自记录的环境。剩余条件集中维护在[开发路线与检查清单](docs/开发路线与检查清单.md)。

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
├── src/sdk/             # Rust 内存核心与四种语言的最小 SDK 包
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

后续 Go 实现归 `src/backend/`，业务服务端 SDK 归 `src/server-sdk/`，应用示例归 `src/apps/`，部署配置归 `deploy/`；这些目录尚未建立。文件落位与依赖方向见[项目文件结构](docs/项目文件结构.md)。

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

The four SDKs refer to four language deliveries: Flutter, Swift, Kotlin and TypeScript. The final TypeScript desktop host and bindings require their own tests. The current minimal Node package uses precompiled Rust WASM; browser packages are validated separately.

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

Status reviewed: **2026-10-10**. The project remains in stage 0 and has not passed the full exit criteria.

| Existing work | Scope and records |
|---|---|
| Independent Rust in-memory core and minimal platform packages | Two-device group creation, encryption/decryption, version checks and independent package consumption, with limited cross-platform interoperability. The experimental SDKs have no networking, SQLite, business sign-in, complete synchronization or attachments. See [Package Validation](docs/四端最小发布验证.md) and [Interoperability Validation](docs/四端互通验证.md) |
| Cryptographic and message protocol POCs | Isolated paths for device registration and first trust, signed permissions, send ordering, exact retries, dual cursors, read receipts and reclamation recovery. The network Relay is a Python HTTP/SQLite test harness; identity and independent trust inputs retain synthetic boundaries. See [Security Model](docs/安全与身份模型.md) and [Protocol Draft](docs/消息协议草案.md) |
| Native and browser storage POCs | Rust-owned explicit transactions, joint cryptographic-state commits, crash recovery and independent anchors, plus a macOS protected-storage experiment. These are not integrated into the in-memory platform SDKs. See [Client Storage](docs/端侧存储与附件管理.md) and [Browser Storage](docs/浏览器存储验证.md) |

The formal Go Service, business backend SDK, product demos and admin console are not implemented. Windows Node execution, physical mobile devices, full security/capacity checks and production release acceptance remain incomplete. Simulator, local-machine and browser results apply only to their recorded environments. Remaining criteria are maintained in the [Development Roadmap and Checklist](docs/开发路线与检查清单.md).

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
├── src/sdk/             # Rust in-memory core and four language SDK packages
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

Future Go implementation belongs in `src/backend/`, business backend SDKs in `src/server-sdk/`, application examples in `src/apps/`, and deployment configuration in `deploy/`. These directories do not exist yet. Placement and dependency rules are defined in [Project Structure](docs/项目文件结构.md).

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
