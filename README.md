# Rocket-IM

可自托管、接入现有业务的 E2EE 即时通讯解决方案。

A self-hosted E2EE instant messaging solution for integration into existing products.

[中文](#中文) · [English](#english)

## 中文

### 仓库内容与复现边界

源码仓库为 [Rocket-IM/rocket-im](https://github.com/Rocket-IM/rocket-im)，纳入 `api/`、`src/`、`poc/`、`tests/`、`tools/`、`docs/` 及根目录说明和协作规则；保留依赖锁文件、工具链版本配置及源码中直接参与编译的生成绑定。`poc/` 保存阶段 0 实验与回归测试，不代表正式产品实现。

`dist/`、依赖安装目录、构建缓存和本机状态不纳入 Git。历史验证文档中的 `dist/` 相对链接定位验证机器上的报告、失败轮、源码快照和发布包，在纯源码克隆中不可访问；这些本地材料继续保留，本次入库尚未建立在线证据归档。维护者复现前需准备固定工具链、生成器和依赖缓存，部分脚本仍有本机路径配置，详见[端侧代码生成](docs/端侧代码生成.md#51-生成入口)。源码入库不代表已完成全新机器重建或正式发布验收。

### 当前状态

**2026-09-24 工程名称统一：** 当前源码、包名、模块名和密码协议域已按 `Rocket-IM` 命名迁移。下文既往运行成绩属于改名前版本，不自动证明新包可用；旧实验状态及包不能与新代码混用。名称映射、两轮实际验证、发现的问题及剩余限制见[工程名称统一](docs/工程名称统一.md)。历史逐轮报告、归档产物及链接目标保留原样；可变 fixture 输出隔离问题另列于该记录。

**2026-09-15 定位纠正：四端 SDK 指 Flutter、Swift、Kotlin、TypeScript 四种语言交付。TypeScript 主要用于 macOS、Windows 桌面客户端，浏览器是次要目标。** 交付可调用的 JS 接口、TypeScript 类型声明及匹配的预编译运行产物，IM 核心仍由 Rust 实现。当前最小桌面交付路线为独立 Node 目标 npm 包，复用 Rust 核心生成 Node.js 绑定；具体产物与验收见[Node 目标最小产物](docs/四端最小发布验证.md#typescript-node-目标最小产物)。最终桌面应用宿主与原生存储绑定尚未确定，旧 Chrome 结果不计作桌面验收。 已打出可独立安装的Node包，macOS ARM64 / Node v26.5.0的104项公开检查及缺库/错版本负例通过；Windows尚未实测。同包的[Windows离线验收材料](docs/四端最小发布验证.md#windows-便携验收材料)已准备。 随后与Swift iOS模拟器的[24项限定互通](docs/四端互通验证.md#macos-node-与-swift-限定互通)通过；随后与Kotlin及Flutter iOS/Android的[72项限定互通](docs/四端互通验证.md#macos-node-与-kotlin-及-flutter-限定互通)也通过，首轮Kotlin控制超时保留为原因未确认的失败记录。

**项目处于阶段 0 验证，尚无正式 IM 业务、公开发布的 SDK 或 Service。** 当前已有隔离密码探针、OpenMLS 合成设备授权与恢复实验，以及`src/sdk/`中的独立内存密码核心和平台预编译包实验。探针证据见[密码方案验证](docs/密码方案验证.md)，实验包的接入方式、实测矩阵和限制见[四端最小发布验证](docs/四端最小发布验证.md)。下文为计划交付能力，不代表完整产品已实现、通过验收或完成安全审计。

Q04 已有[消息协议草案与实验接口源](docs/消息协议草案.md)，并接通独立 Rust CLI 与本机 HTTP/SQLite Relay。119 个网络增量场景通过，覆盖消息、签名权限、恢复、有界历史接收、真实 Add/Welcome 入群、选定历史副本迁移及 Q02 已知回滚/分叉检测。新账号设备由群主邀请，同账号新设备由本群有效旧设备批准；加入本身仅授权未来消息，不继承旧密码状态、其他设备游标或全账号 roster。另经明确授权后，旧设备可将自己已接收，或已核验 Service 接受证明的已发送消息，按选择定向加密给同账号新设备；两类消息都须仍有正文及接受证明；迁移副本与新设备的未来通信状态分开保存。初始身份仍是合成数据，附件迁移、跨群设备协调、持续隔离分叉的生产独立对照渠道、完整协议/安全验收及正式 Go Service 尚未完成。

Q02 本机实验会在检查开始时持久阻断新加密；发现已知回滚或可验证分叉后重启仍暂停。回滚须真实补链并显式恢复，分叉没有原地解除入口；没有独立对照时始终为不可判断。现已固定人工当面逐次核验指纹的最小契约，并通过实际持有端导出、签名公开文件交换、可信前驱核验及取消/撤销/原子退出的本机实验；自动化仅使用合成核验声明，不证明生产渠道独立或全局最新。契约及实际证据见[协议第 17 节](docs/消息协议草案.md#17-q02-已知回滚与同一前驱分叉的检测)和[第 18 节](docs/消息协议草案.md#18-q02-独立对照的最小信任契约与本机交换)。

Q05/Q02 进一步验证了完整快照的独立锚：在加载密码状态前先预约当前完整摘要，只有已完整保存的结果才允许显式完成提交。旧快照、未决预约和锚不可达都会暂停，恢复不清原有权限或分叉状态。实现与证据见[第 19 节](docs/消息协议草案.md#19-q05q02-完整快照回滚的独立锚)。未决预约后的最小安全重建进一步固定旧范围永久封存、独立批准的唯一新身份，并通过真实 Add/Welcome 建立另一个通信范围，见[第 20 节](docs/消息协议草案.md#20-q05-未决预约后的安全重建)。

2026-09-14，重建后继已接通独立授权的新设备流：Service 签名绑定唯一新身份与新群，Rust 在独立锚保护下复用原同步引擎处理签名分页。42 项真实 HTTP/Rust 本机场景通过，覆盖登记前排队、分页、重复及迟到响应、错范围拒绝、崩溃恢复和原安全暂停保留，见[第 21 节](docs/消息协议草案.md#21-重建后继的新设备流授权与恢复同步)。后继不迁移旧历史，不继承旧设备游标；本机合成锚不证明生产独立故障域，两端同时回滚仍不可判断。正式Go Service、正式四端SDK发布及完整阶段0验收仍未完成。

随后完成四端最小预编译实验包（`0.1.0-stage0.1`）：Swift、Kotlin、Flutter与浏览器独立工程均通过双向加解密和版本拒绝，接入工程不编译Rust或生成绑定。iOS/Android运行来自ARM64模拟器，浏览器为Chrome；真机运行未测。包内只含内存双设备核心，无网络、持久化或上述POC恢复能力；下载路径、实际运行层次和完整记录见[四端最小发布验证](docs/四端最小发布验证.md)。

基于同一四份包，随后完成五个运行端的交叉互通与错误一致性验证：Swift、Kotlin、Chrome、Flutter iOS和Flutter Android的20条建群路线及55项错误场景全部通过，共75/75。Android两端使用独立ARM64/16KiB模拟器前台运行，源码与实际安装产物摘要核对通过；失败记录与限制见[四端互通验证](docs/四端互通验证.md)。后台持续运行、真机及完整阶段0出口仍未验收。

2026-09-14已完成[阶段0出口差距评审](docs/开发路线与检查清单.md#阶段-0-出口差距评审2026-09-14)：该次评审仅核对现有文档、源码/产物摘要及已保存报告，没有重跑测试；Q01—Q06仍开放，阶段0未通过，不进入阶段1。

随后按授权推进的[隔离浏览器Rust+SQLite持久化实验](docs/浏览器存储验证.md)，除普通记录的显式事务、单写、关闭/崩溃恢复及独立包消费外，已增加真实OpenMLS状态与待发送密文共同提交、接收消息与去重及处理游标共同提交，并将原始下载记录与下载游标单独一致保存；持久未决预约在失败或中断后阻止继续密码操作。运行结果与限制详见该记录，不代表已整合到四端内存SDK。随后新增独立锚入口，以 `synthetic_local` 本机锚验证完整旧库阻断与完整候选的精确恢复，详见[第 7 节](docs/浏览器存储验证.md#7-浏览器独立锚与恢复契约)。随后增加独立批准的新身份和存储空间重建，封存旧未决范围并以新群实际互通，见[第 8 节](docs/浏览器存储验证.md#8-浏览器未决范围安全重建)。生产独立故障域、首次信任、强制可信入口、秘密保存与安全删除尚未验证，Q05、T09/T10及完整阶段0仍开放。

随后完成[原生Rust+SQLite普通记录实验](docs/端侧存储与附件管理.md#9-原生普通记录事务与重启实验)：macOS ARM64下14项Rust测试与10项进程场景通过，覆盖显式事务、真实提交失败、迁移回滚、提交前后强杀及重启一致性。失败记录保留。随后[原生OpenMLS发送共同提交实验](docs/端侧存储与附件管理.md#10-原生密码状态与待发送密文共同提交)的29项Rust测试及16项进程场景通过：密码状态与密文共同提交，失败/重启保留未决暂停，缓存重试不再加密。随后[原生接收共同提交实验](docs/端侧存储与附件管理.md#11-原生接收状态消息去重与处理游标共同提交)的38项Rust测试及21项进程场景通过，覆盖消息/去重/处理游标落盘、重启查询、重复投递零解密和故障暂停。随后[原生下载双游标实验](docs/端侧存储与附件管理.md#12-原生原始下载记录与双游标共同落盘)的48项Rust测试及25项进程场景通过：原始密文与下载游标共同保存，重启后按已存序号处理；下载进度与解密进度分离，坏密文和未决预约保留。随后[原生完整库回滚与独立锚实验](docs/端侧存储与附件管理.md#13-原生完整数据库回滚与独立锚)的56项原生Rust测试、25项helper锚测试及30项进程场景通过：已知旧库停止收发/处理，未决操作重启后仍暂停，完整日志可原样恢复且不重算密码；数据库、锚与可信配置共同回滚仍不可检测。以上均为隔离实验，未加入TypeScript原生绑定或现有SDK包；完整同步、秘密保护、Windows和完整阶段0尚未验收。

随后完成[原生未决状态安全重建](docs/端侧存储与附件管理.md#14-原生未决状态安全重建)：79项原生Rust测试、25项既有helper锚测试及33项重建进程场景通过，五个旧入口回归共102项通过。故障前固定的健康设备独立批准新身份、新库和新范围，通过真实Add/Welcome建立通信；旧状态与预约继续封存，完整结果恢复不重复密码计算或成功事件。首轮32/33失败及修正过程保留。这仍是macOS ARM64下的 `synthetic_local` 隔离实验，原SDK包不变；生产信任、系统秘密保护与完整阶段0尚未验收。

随后完成[原生秘密保护与可信配置保存](docs/端侧存储与附件管理.md#15-原生秘密保护与可信配置保存)的macOS ARM64局部验收：95项Rust测试、41项独立进程场景及135项旧入口回归通过。SQLCipher覆盖provider、正文和恢复控制，专用系统钥匙串保存密钥与固定配置；重启保持原身份，锁定/缺钥暂停，配置篡改及跨库替换拒绝，已提交结果精确恢复。首轮37/38失败和装置修正保留。这仍是合成数据隔离实验；真实屏幕锁、正式签名升级、生产信任及完整阶段0未验收，既有SDK包不变。

随后完成[签名访问与升级恢复验证](docs/端侧存储与附件管理.md#16-原生签名访问与升级恢复生命周期)：先完成隔离自签实验，随后使用用户指定的Apple Development身份，通过14份Apple签名产物核对、8次新旧程序要求交叉校验、10项升级/晚期锁定恢复及41项新版保护回归。相同签名身份升级保留原数据并真实收发，完整结果精确恢复，未决预约不重算。原95项受保护与79项默认Rust测试证据保留，本轮未改Rust或重跑这两组测试。开发签名本机验收已通过；其他Apple团队、证书轮换、Developer ID发行/公证和正式SDK验收仍未执行。 2026-09-16按用户当前条件将Developer ID发行验证延期，不阻塞其他不依赖发行身份的阶段0工作；延期不计为验收通过。


### 项目定位

Rocket-IM 希望让第三方部署独立 IM Service、安装 SDK，并通过公开接口接入已有账号、后台与客户端 UI，正常集成无需 fork、修改方案源码或直接读写 IM 数据表。

首期采用中心化、单租户、单实例部署。前端 Demo 用于演示和验收；SDK 不包含 UI。Service 独立运行、部署和升级，内部优先采用模块化单体。

### 计划交付与职责

| 交付物 | 技术与职责 |
|---|---|
| IM Service | Go + PostgreSQL；负责鉴权、设备/公钥目录、权限、消息持久化与投递。提供独立镜像、可执行文件和迁移入口 |
| 业务服务端 SDK | Go HTTP API 客户端；对接用户映射、凭证和管理操作。其他语言可调用公开 HTTP API；不依赖 Service 内部包 |
| Rust SDK | 无 UI 核心与版本化 crate；统一持有四端 SQLite，管理消息、连接、同步、重试、密码状态及附件处理/传输任务 |
| Flutter SDK | Dart 包、已生成桥接与预编译库；首期面向 iOS/Android |
| Swift SDK | Swift Package + XCFramework；首期面向 iOS |
| Kotlin SDK | Maven 包 + AAR/JNI 库；首期面向 Android |
| TypeScript SDK | npm 包、JS 接口、TypeScript 类型声明及匹配的预编译运行产物；主要面向 macOS/Windows 桌面客户端，浏览器次要；当前最小路线使用 Node 绑定，正式桌面范围按实测确定 |
| 端侧 Demo | Flutter Demo，以及 Swift、Kotlin、TypeScript 桌面/浏览器最小接入示例；均通过公开 SDK 提供演示登录/注册和必要验收入口 |
| 管理后台 | 可选 Vue 3 + TypeScript 界面；通过公开管理 API 管理用户、设备、群组、举报及运行状态 |

四端 SDK 接入者无需安装 Rust/Cargo、生成绑定或编译 Rust 核心，仍正常构建自己的应用；Rust crate 使用者正常使用 Rust 工具链。Service 使用者无需 Go 工具链。本地最小实验包已有包名和实测记录，正式包名、公共下载地址和正式发布的支持矩阵尚未确定。macOS/Windows 是 TypeScript 的主要目标，最小 Node 路线不替代最终桌面宿主与原生存储验收；Flutter Web 及其他未列目标另行评估。

后续端侧存储已确认由 Rust 统一管理 SQLite，包含 TypeScript 桌面与浏览器；发送/接收及状态变化先提交数据库，再通过回调通知宿主，后续读写通过公开 SDK 进入统一读写线程，浏览器使用等价串行执行上下文。隔离POC已采用Worker与SQLite/OPFS，正式四端SDK整合、原生线程分配及完整平台验收仍待完成。Rust 同时管理附件编解码、加解密、上传下载，宿主可设置最大附件工作数；附件具体 API 和并发计数口径仍待验证与商议。当前四端内存实验包尚未实现这些能力，见[端侧存储与附件管理](docs/端侧存储与附件管理.md)。

Rust 的所有数据库读取和写入均须经过显式事务，包括单次只读查询；读事务正常结束后返回结果，写事务提交后派发对应成功事件。事务边界、维护命令限制及后续验收统一见上述专项文档，当前四端内存实验包尚未整合；隔离浏览器POC的已执行范围另见验证记录。

### 预期接入流程

1. 部署发布版 Service 及存储，配置 HTTPS/WSS、持久化和运维参数。
2. 业务后台验证原有账号，通过公开 API 完成用户映射并取得受限 IM 凭证；管理凭证保留在可信后台。
3. 客户端安装对应 SDK，提供 Service 地址与 IM 凭证，完成设备授权和连接。
4. 自有 UI 使用 SDK 查询与事件收发消息；通过配置和公开接口接入资料、附件存储、推送与业务事件。

演示账号系统可替换。业务登录、设备信任和历史恢复分别处理；具体接口和运行步骤以未来发布文档为准。

### 功能范围

**第一期共 21 项：** 登录/注册与业务身份接入；文字和图片/视频/语音消息；多设备、多账号、可选 E2EE；会话列表、聊天、历史和状态同步；用户/好友、详情与关系流程；群聊及权限；可靠投递、离线推送、设备管理与历史恢复；账号生命周期、附件完整流程、举报处理及解决方案接入。

**第二期共 12 项：** 消息编辑、撤回、转发、引用回复、表情回应、收藏、全文搜索、输入状态、在线状态、跨端草稿、语音转文字、音视频通话。

一期 21 项及四端独立发布均属于一期验收范围。开发路线中的阶段 0—4 是工程顺序，不改变产品分期；逐项标准见[功能分期与验收](docs/功能分期与验收.md)。

### 安全与数据边界

- E2EE 默认开启，可按部署策略选择非 E2EE；会话创建时固定模式，一期变更模式需新建会话。加密失败或版本不兼容必须明确报错，禁止静默降级。
- E2EE 正文及附件在端侧加解密，解密私钥和会话密钥由端侧持有。仅成员设备持有私钥的“公钥加密群”也属于 E2EE；具体密码协议与库待验证，不自研密码学原语。
- 非 E2EE 模式必须标识服务器可能读取内容。两种模式均使用 HTTPS/WSS；服务器仍可观察路由、时间、大小和 IP 等元数据。
- 多设备默认开启、可关闭；多账号可并存登录和接收消息。凭证、密钥、存储、队列、回调与推送按服务实例及账号隔离。
- IM 凭证不等于设备信任，也不能自动恢复历史密钥。撤销设备或移除成员后，旧密钥不能解开新密码状态下产生的密文；既有副本与变更前在途消息须另定边界。
- 管理后台不具备通用 E2EE 解密或冒充用户能力；举报只披露用户主动确认的证据。端侧失陷和浏览器脚本信任需单独评估，不能用“E2EE”替代端侧安全验证。

### 文档与待定项

| 文档 | 内容 |
|---|---|
| [交付物与技术栈](docs/交付物与技术栈.md) | 发布形式、组件职责和接入边界 |
| [功能分期与验收](docs/功能分期与验收.md) | 一期 21 项、二期 12 项和发布门槛 |
| [安全与身份模型](docs/安全与身份模型.md) | 阶段 0 设计草案、信任与恢复边界、POC 用例及待验证问题 |
| [密码方案验证](docs/密码方案验证.md) | 候选筛选、精确依赖、原生与浏览器探针结果及剩余边界 |
| [四端最小发布验证](docs/四端最小发布验证.md) | 预编译实验包、独立接入、运行矩阵、摘要及失败记录 |
| [四端互通验证](docs/四端互通验证.md) | 五运行端的交叉互通、错误一致性、包来源和失败记录 |
| [端侧代码生成](docs/端侧代码生成.md) | Rust 导出接口、现有生成器、手写封装与 TypeScript 桌面交付边界 |
| [浏览器存储验证](docs/浏览器存储验证.md) | 普通记录与真实OpenMLS的 Rust/SQLite/OPFS 实验、共同提交、未决预约及崩溃证据 |
| [端侧存储与附件管理](docs/端侧存储与附件管理.md) | Rust 持有 SQLite、提交后回调、统一读写及附件工作数配置 |
| [消息协议草案](docs/消息协议草案.md) | Q04 字段与认证绑定、重试/替代、回执、补拉及网络验收样例 |
| [开发路线与检查清单](docs/开发路线与检查清单.md) | 工程阶段、验证顺序和完成证据 |
| [项目文件结构](docs/项目文件结构.md) | 现有文件、规划目录、模块归属与新增文件规则 |
| [AGENTS.md](AGENTS.md) | 项目协作规则和各技术层约束 |

实施前需锁定密码方案、依赖许可证、设备授权与历史恢复、平台/架构与版本兼容、发布渠道、推送和附件限制及容量指标。

**许可证：待确定。** 项目计划开源，当前仓库尚未提供 `LICENSE`；最终许可证及第三方依赖声明将在发布前明确。

## English

### Repository contents and reproduction limits

The source repository is [Rocket-IM/rocket-im](https://github.com/Rocket-IM/rocket-im). It includes `api/`, `src/`, `poc/`, `tests/`, `tools/`, `docs/`, and the root documentation and collaboration rules. Dependency lockfiles, pinned toolchain configuration, and generated bindings directly used by the source build are retained. `poc/` contains Stage 0 experiments and regression tests, not a production implementation.

`dist/`, installed dependencies, build caches, and machine-local state are excluded from Git. Historical `dist/` links identify reports, failed runs, source snapshots, and packages on the validation machine and are unavailable in a source-only clone. Those local materials are preserved; this initial import does not establish an online evidence archive. Maintainers must prepare the pinned toolchains, generators, and dependency caches before reproduction; some scripts still require machine-specific path configuration. See the [code-generation prerequisites](docs/端侧代码生成.md#51-生成入口). Importing the source does not establish clean-machine reproducibility or production release acceptance.

### Current status

**2026-09-24 project rename:** The current source, package names, modules, and cryptographic domains have been migrated to `Rocket-IM`. Historical results below apply to the pre-rename revision and do not establish acceptance of the renamed packages. Do not mix old experimental state or packages with the new code. See the [rename record](docs/工程名称统一.md) for mappings, both validation rounds, discovered issues, and remaining limits. Historical per-run reports, archived artifacts, and link destinations are preserved unchanged; the mutable fixture output isolation issue is documented separately in that record.

**Scope correction on 2026-09-15: the four SDK deliveries are Flutter, Swift, Kotlin and TypeScript. TypeScript primarily targets macOS and Windows desktop clients; browsers are secondary.** The deliverable provides callable JavaScript APIs, TypeScript declarations and matching precompiled runtime artifacts, while the IM core remains implemented in Rust. The current minimal desktop delivery path is a separate Node-targeted npm package with Node.js bindings generated from the shared Rust core; artifacts and acceptance are recorded in [Minimal Node-targeted Artifacts](docs/四端最小发布验证.md#typescript-node-目标最小产物). The final desktop application host and native storage bindings remain undecided. Earlier Chrome results do not count as desktop acceptance. The independently installable Node package passed 104 public API checks plus missing-runtime and version-mismatch cases on macOS ARM64 / Node v26.5.0; Windows execution remains untested. An [offline Windows acceptance kit](docs/四端最小发布验证.md#windows-便携验收材料) for the same package is ready. A subsequent [24-case interoperability check with Swift on the iOS simulator](docs/四端互通验证.md#macos-node-与-swift-限定互通) passed; A subsequent [72-case check with Kotlin and Flutter on iOS/Android](docs/四端互通验证.md#macos-node-与-kotlin-及-flutter-限定互通) also passed; the first-run Kotlin control timeout remains recorded with its cause unconfirmed.

**This project is in stage 0 validation. No formal IM business implementation, publicly released SDK or Service is available.** Isolated cryptographic probes, synthetic OpenMLS device authorization and recovery experiments now exist, along with an independent in-memory cryptographic core and experimental precompiled platform packages under `src/sdk/`. Probe evidence is recorded in [Cryptographic Candidate Validation](docs/密码方案验证.md); package integration, tested environments and limits are in [Minimal Four-Platform Package Validation](docs/四端最小发布验证.md). The capabilities below remain planned deliverables, not a completed product, full acceptance or a security audit.

Q04 now has a [Message Protocol Draft and Experimental API Definitions](docs/消息协议草案.md), connecting independent Rust CLIs to a loopback HTTP/SQLite Relay. 119 incremental network scenarios passed, covering messages, signed permissions, recovery, bounded history reception, actual Add/Welcome joins, selected historical-copy migration and Q02 known rollback/fork detection. New-account devices require an owner invitation; new devices for an existing account require approval from a current device of that account in this group. Joining itself authorizes future messages without inheriting old cryptographic state, another device's cursor or the account-wide roster. Separate explicit authorization lets an old device encrypt selected received messages, or outgoing messages with verified Service acceptance proofs, for a new device of the same account. Both require the original content and acceptance proofs to remain available locally. Migrated copies remain separate from the new device's future communication state. Initial identities remain synthetic; attachment migration, device coordination across groups, a production independent comparison channel for persistently isolated forks, full protocol/security acceptance and the formal Go Service are not complete.

The local Q02 experiment durably blocks new encryption when a check starts; known rollback or verifiable fork evidence keeps sending paused across restarts. Rollback requires actual chain recovery and explicit resumption. Confirmed forks have no in-place reset, and freshness remains unknown without independent comparison. A minimum contract now requires an in-person comparison of full key fingerprints for each exchange. Local experiments cover exports from actual holders, signed public files, trusted predecessor checks, cancellation, revocation and atomic exits. Automation uses synthetic verification declarations only; it does not establish production channel independence or global freshness. The contract and executed evidence are in [Section 17](docs/消息协议草案.md#17-q02-已知回滚与同一前驱分叉的检测) and [Section 18](docs/消息协议草案.md#18-q02-独立对照的最小信任契约与本机交换).

Q05/Q02 now also has a local experiment for an independent anchor over complete snapshots. It reserves the current snapshot commitment before loading cryptographic state and permits explicit completion only for fully persisted results. Old snapshots, unresolved reservations and an unavailable anchor keep operations paused; recovery preserves existing permission and fork restrictions. See [Section 19](docs/消息协议草案.md#19-q05q02-完整快照回滚的独立锚). The minimal rebuild path permanently seals the old scope, links one independently approved new identity, and establishes a different communication scope through actual Add/Welcome processing; see [Section 20](docs/消息协议草案.md#20-q05-未决预约后的安全重建).

As of 2026-09-14, the rebuilt successor has an independently authorized new device stream. A Service-signed binding fixes the unique new identity and group; Rust processes signed pages through the existing synchronization engine under the independent anchor. All 42 local HTTP/Rust scenarios passed, covering events queued before registration, pagination, duplicate and late responses, scope rejection, crash recovery and preservation of existing security pauses; see [Section 21](docs/消息协议草案.md#21-重建后继的新设备流授权与恢复同步). The successor neither migrates old history nor inherits another device's cursor. The synthetic local anchor does not establish production fault-domain independence, and rolling back both sides remains undetectable. The formal Go Service, formal four-platform SDK releases and full stage 0 acceptance remain incomplete.

The minimal precompiled experimental packages (`0.1.0-stage0.1`) subsequently passed independent integration in Swift, Kotlin, Flutter and the browser, including bidirectional encryption/decryption and version rejection. Consumer projects neither compile Rust nor generate bindings. iOS/Android runs used ARM64 simulators/emulators and the browser run used Chrome; physical-device execution remains untested. The packages contain only an in-memory two-device core, without networking, persistence or the POC recovery features above. Local artifacts, exact runtime layers and evidence are listed in [Minimal Four-Platform Package Validation](docs/四端最小发布验证.md).

The same four packages subsequently passed interoperability and error-consistency checks across five runtimes: Swift, Kotlin, Chrome, Flutter iOS and Flutter Android. All 20 group-creation routes and 55 error scenarios passed (75/75). The Android consumers ran in the foreground on separate ARM64/16 KiB emulators; source and installed-artifact hashes were verified. Failed attempts and limits are recorded in [Four-Platform Interoperability Validation](docs/四端互通验证.md). Sustained background execution, physical devices and the complete stage 0 exit remain unaccepted.

The [stage 0 exit gap review](docs/开发路线与检查清单.md#阶段-0-出口差距评审2026-09-14) was completed on 2026-09-14. That review checked existing documents, source/artifact hashes and saved reports without rerunning tests. Q01–Q06 remain open; stage 0 has not passed and stage 1 is not started.

The subsequently authorized [isolated browser Rust + SQLite persistence experiment](docs/浏览器存储验证.md) extends ordinary-record transactions, single-writer ownership, close/crash recovery and independent package consumption with joint commits of real OpenMLS state and outgoing ciphertext, and of received messages, deduplication and the processing cursor. Raw downloads and the download cursor are committed together separately. Persistent unresolved reservations block further cryptographic operations after failure or interruption. Measured results and limits are recorded there; these capabilities have not been integrated into the four in-memory SDKs. A subsequent anchored entry uses a `synthetic_local` authority to test blocking of complete old databases and exact recovery of fully saved candidates; see [Section 7](docs/浏览器存储验证.md#7-浏览器独立锚与恢复契约). A subsequent rebuild path uses independent approval for a new identity and storage namespace, seals the unresolved predecessor and exchanges real messages in a new group; see [Section 8](docs/浏览器存储验证.md#8-浏览器未决范围安全重建). Production fault-domain independence, first trust, enforced client policy, secret storage and secure deletion remain unverified; Q05, T09/T10 and full stage 0 acceptance remain open.

The subsequent [native Rust + SQLite ordinary-record experiment](docs/端侧存储与附件管理.md#9-原生普通记录事务与重启实验) passed 14 Rust tests and 10 process scenarios on macOS ARM64, covering explicit transactions, actual commit failures, migration rollback, process termination before and after commit, and consistent reopening. Failed runs remain recorded. The subsequent [native OpenMLS send-commit experiment](docs/端侧存储与附件管理.md#10-原生密码状态与待发送密文共同提交) passed 29 Rust tests and 16 process scenarios: cryptographic state and ciphertext commit together, failures/restarts preserve pending reservations, and cached retries do not encrypt again. The subsequent [native receive-commit experiment](docs/端侧存储与附件管理.md#11-原生接收状态消息去重与处理游标共同提交) passed 38 Rust tests and 21 process scenarios, covering persisted messages/deduplication/processing cursors, queries after restart, duplicate delivery without decryption, and persistent failure gates. The subsequent [native download and dual-cursor experiment](docs/端侧存储与附件管理.md#12-原生原始下载记录与双游标共同落盘) passed 48 Rust tests and 25 process scenarios: raw ciphertext and the download cursor commit together, processing resumes from stored sequences after restart, download progress remains separate from decryption progress, and invalid ciphertext and pending reservations are retained. The subsequent [native full-database rollback and external-anchor experiment](docs/端侧存储与附件管理.md#13-原生完整数据库回滚与独立锚) passed 56 native Rust tests, 25 helper anchor tests and 30 process scenarios: known old databases cannot continue sending/receiving or processing, unresolved operations remain paused after restart, and complete committed journals recover the exact result without recomputing cryptography. Rolling back the database, anchor and trusted configuration together remains undetectable. These remain isolated experiments without native TypeScript bindings or integration into existing SDK packages; complete synchronization, secret protection, Windows and full stage 0 remain unaccepted.

The subsequent [native unresolved-state safe rebuild](docs/端侧存储与附件管理.md#14-原生未决状态安全重建) passed 79 native Rust tests, 25 existing helper anchor tests and 33 rebuild process scenarios, plus 102 regression scenarios across five existing entry points. A healthy device pinned before the failure independently approves a fresh identity, database and scope, with real Add/Welcome establishing communication. The old state and reservation remain sealed; complete-result recovery repeats neither cryptographic computation nor success events. The first 32/33 failed run and its harness correction remain recorded. This is still an isolated macOS ARM64 experiment using `synthetic_local` trust, with existing SDK packages unchanged; production trust, system secret protection and full stage 0 remain unaccepted.

The subsequent [native secret protection and trusted configuration experiment](docs/端侧存储与附件管理.md#15-原生秘密保护与可信配置保存) passed its local macOS ARM64 acceptance: 95 Rust tests, 41 independent-process scenarios and 135 regression scenarios across existing entry points. SQLCipher covers provider state, plaintext and recovery controls; a dedicated system keychain stores keys and pinned configuration. Restart preserves identity, locked or missing keys pause operations, configuration tampering and cross-database substitution are rejected, and committed results recover exactly. The first 37/38 failed run and its harness correction remain recorded. This remains an isolated synthetic-data experiment; actual screen lock, signed release upgrades, production trust and full stage 0 remain unaccepted, with existing SDK packages unchanged.

The subsequent [signing access and upgrade recovery validation](docs/端侧存储与附件管理.md#16-原生签名访问与升级恢复生命周期) first completed the isolated self-signed experiment, then used the user-selected Apple Development identity to pass checks on 14 Apple-signed artifacts, 8 cross-version requirement checks, 10 upgrade/late-lock recovery cases and 41 protected regression cases with the new programs. Upgrades with the same signing identity preserve existing state and exchange real messages; committed results recover exactly and unresolved reservations are not recomputed. Prior evidence for 95 protected and 79 default Rust tests is retained; Rust was unchanged and those two suites were not rerun in this round. Local development-signing acceptance passed; other Apple teams, certificate rotation, Developer ID distribution/notarization and official SDK acceptance remain untested. On 2026-09-16, Developer ID distribution validation was deferred at the user’s request and does not block other stage 0 work that does not depend on a distribution identity; deferral is not acceptance.


### Purpose

Rocket-IM aims to let integrators deploy an independent IM Service, install SDKs and connect their existing accounts, backend and client UI through public interfaces. Normal integration should require no fork, source changes or direct access to IM database tables.

The first phase targets centralized, single-tenant, single-instance deployments. Client demos support demonstration and acceptance testing; SDKs contain no UI. The Service runs, deploys and upgrades independently, initially as a modular monolith.

### Planned deliverables and responsibilities

| Deliverable | Technology and responsibility |
|---|---|
| IM Service | Go + PostgreSQL; authentication, device/public-key directory, authorization, message persistence and delivery. Independent images, executables and migration entry points |
| Business backend SDK | Go HTTP API client for user mapping, credentials and management operations. Other languages can use public HTTP APIs; no dependency on Service internal packages |
| Rust SDK | UI-free core and versioned crate; owns SQLite across all four SDKs and manages messages, connections, synchronization, retries, cryptographic state and attachment processing/transfers |
| Flutter SDK | Dart package, generated bindings and precompiled libraries; initially for iOS/Android |
| Swift SDK | Swift Package + XCFramework; initially for iOS |
| Kotlin SDK | Maven package + AAR/JNI libraries; initially for Android |
| TypeScript SDK | npm package, JavaScript APIs, TypeScript declarations and matching precompiled runtime artifacts; primarily for macOS/Windows desktop clients, with browsers secondary; the minimal route uses Node bindings and formal desktop coverage requires its own tests |
| Client demos | Flutter demo plus minimal Swift, Kotlin and TypeScript desktop/browser integration examples; all use public SDKs for demo sign-up/sign-in and required acceptance flows |
| Admin console | Optional Vue 3 + TypeScript UI; public management APIs for users, devices, groups, reports and operational status |

Consumers of the four platform SDKs will not need Rust/Cargo, binding generation or Rust core compilation; they will build their own applications normally. Native Rust crate consumers use the normal Rust toolchain. Service consumers will not need a Go toolchain. The local minimal experimental packages have names and test records; formal package names, public download locations and support matrices for formal releases remain undecided. macOS and Windows are the primary TypeScript targets; the minimal Node route does not establish acceptance for the final desktop application host or native storage. Flutter Web and other unlisted targets require separate assessment.

The planned client architecture now assigns SQLite ownership to Rust across all four SDKs, including TypeScript desktop and browser targets. Sent/received messages and state changes are committed before notifying the host; subsequent reads and writes use public SDK APIs and the Rust-managed database read/write thread, with an equivalent serial execution context for browsers. The isolated POC uses a Worker and SQLite/OPFS; integration into all four SDKs, native thread allocation and complete platform acceptance remain pending. Rust also manages attachment encoding/decoding, encryption/decryption, uploads and downloads, with a host-configurable maximum number of concurrent attachment jobs; concrete attachment APIs and concurrency counting rules still require validation and discussion. The current four in-memory experimental packages do not implement these capabilities; see [Client Storage and Attachment Management](docs/端侧存储与附件管理.md).

All Rust database reads and writes must use explicit transactions, including individual read-only queries. Read results are returned after the read transaction ends successfully; corresponding success events follow a committed write transaction. Transaction boundaries, maintenance-command restrictions and planned validation are defined in the document above. These capabilities have not been integrated into the four in-memory experimental packages; the isolated browser POC has its own validation record.

### Intended integration flow

1. Deploy released Service and storage artifacts; configure HTTPS/WSS, persistence and operational settings.
2. Have the business backend verify existing accounts, map users and obtain scoped IM credentials through public APIs. Keep management credentials in the trusted backend.
3. Install the appropriate client SDK, supply the Service address and IM credentials, authorize the device and connect.
4. Use SDK queries and events in the existing UI for messaging. Integrate profiles, attachment storage, push notifications and business events through configuration and public interfaces.

The demo account system is replaceable. Business sign-in, device trust and history recovery are separate concerns; future release documentation will define concrete interfaces and runnable steps.

### Feature scope

**Phase one contains 21 items:** sign-up/sign-in and business identity integration; text and image/video/voice messages; multiple devices, multiple accounts and optional E2EE; conversation lists, chat, history and state synchronization; users/friends, details and relationship workflows; groups and permissions; reliable delivery, offline push, device management and history recovery; account lifecycle, complete attachment workflows, report handling and solution integration.

**Phase two contains 12 items:** message editing, recall, forwarding, quoted replies, reactions, favorites, full-text search, typing indicators, presence, cross-device drafts, speech-to-text and audio/video calls.

All 21 phase-one items and independent releases of all four platform SDKs belong to phase-one acceptance. Engineering stages 0–4 describe implementation order and do not change product phases. Item-level criteria are in [Feature Phases and Acceptance](docs/功能分期与验收.md).

### Security and data boundaries

- E2EE is enabled by default; deployment policy may permit non-E2EE. The mode is fixed when a conversation is created; changing it in phase one requires a new conversation. Encryption failures or incompatible versions must fail explicitly, without silent downgrade.
- E2EE message bodies and attachments are encrypted and decrypted on clients; decryption private keys and session keys remain client-held. A “public-key encrypted group” whose private keys are held only by member devices is also E2EE. The cryptographic protocol and libraries require validation; the project will not design its own cryptographic primitives.
- Non-E2EE mode must indicate that the server may read content. Both modes use HTTPS/WSS; the server can still observe metadata such as routing, timing, size and IP addresses.
- Multiple devices are enabled by default and can be disabled; multiple accounts can remain signed in and receive messages concurrently. Credentials, keys, storage, queues, callbacks and push notifications are isolated by Service instance and account.
- IM credentials do not establish device trust or automatically restore historical keys. After device revocation or member removal, old keys must not decrypt ciphertext created under the new cryptographic state. Existing copies and messages already in flight before the change require separate rules.
- The admin console has no general E2EE decryption or user-impersonation capability; reports disclose only evidence explicitly approved by the reporting user. Endpoint compromise and browser-script trust require separate assessment; “E2EE” does not replace endpoint security validation.

### Documentation and open decisions

The planning documents are currently in Chinese.

| Document | Contents |
|---|---|
| [Deliverables and Technology Stack](docs/交付物与技术栈.md) | Release formats, component ownership and integration boundaries |
| [Feature Phases and Acceptance](docs/功能分期与验收.md) | The 21 phase-one items, 12 phase-two items and release gates |
| [Security and Identity Model](docs/安全与身份模型.md) | Stage 0 design draft, trust and recovery boundaries, POC cases and open validation questions |
| [Cryptographic Candidate Validation](docs/密码方案验证.md) | Candidate screening, exact dependencies, native/browser probe results and remaining limits |
| [Minimal Four-Platform Package Validation](docs/四端最小发布验证.md) | Precompiled experimental packages, independent integration, runtime matrix, hashes and failure records |
| [Four-Platform Interoperability Validation](docs/四端互通验证.md) | Cross-runtime communication, error consistency, package provenance and failed attempts |
| [Client Binding Generation](docs/端侧代码生成.md) | Rust exports, current binding generators, handwritten wrappers and TypeScript desktop delivery boundaries |
| [Browser Storage Validation](docs/浏览器存储验证.md) | Ordinary-record and real OpenMLS Rust/SQLite/OPFS experiments, joint commits, unresolved reservations and crash evidence |
| [Client Storage and Attachment Management](docs/端侧存储与附件管理.md) | Rust-owned SQLite, post-commit callbacks, serialized database access and attachment concurrency configuration |
| [Message Protocol Draft](docs/消息协议草案.md) | Q04 fields and authenticated context, retries/replacement, receipts, recovery pulls and network acceptance examples |
| [Development Roadmap and Checklist](docs/开发路线与检查清单.md) | Engineering stages, validation order and completion evidence |
| [Project Structure](docs/项目文件结构.md) | Existing files, planned directories, module ownership and file placement rules |
| [AGENTS.md](AGENTS.md) | Collaboration rules and constraints for each technical layer |

Before implementation, decisions are needed on cryptography, dependency licenses, device authorization and history recovery, platform/architecture and version compatibility, distribution channels, push and attachment limits, and capacity targets.

**License: undecided.** The project is intended to be open source, but the repository currently has no `LICENSE`. The project license and third-party notices will be defined before release.
