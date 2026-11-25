# 固定双设备联网 Alpha 的本机运行

仅本机开发验收：一个 Go Service、PostgreSQL、固定两个测试设备、单会话 E2EE 文本。业务身份接入见下节；不是完整业务登录系统、生产发布或阶段0全部通过。Service 不需要 Rust、Node 或仓库源码；SDK 消费者不需要 Go、Cargo 或生成器。

1. 准备 PostgreSQL、独立数据库及可写 schema；本轮验证 PostgreSQL 18.1。不要使用生产账号/数据。准备可信 TLS CA 签发的服务器证书，SAN 必须包含 SDK 连接使用的字面 IP；本轮 SDK 只接受显式端口的 `wss://IP:PORT/v1/ws`，TLS 1.3。
2. 维护者使用 Go 1.27.4 在 `src/backend/` 执行 `go build -trimpath -o /absolute/output/im-service ./cmd/im-service`。运行方只接收生成的二进制。
3. 两个 SDK 消费者分别创建专用文件钥匙串并解锁，使用公开 `PersistentDevice.open`、`initialize` 和 `joiningMaterial` 取得各自的公开身份；通过独立可信渠道核验双方 Identity。不要把 Service 的公开目录当作独立核验。首次联网的空间须尚未手动建群；旧 dev.5 本地群直接连接会报 `network_fresh_group_required`，本轮没有导入协议，不删除旧库来绕过它。
4. 按 `alpha.config.example.json` 显式填写 service、conversation、两组身份公钥和随机设备凭证的 SHA256。第一设备是群创建者。凭证原文仅交给对应 SDK；配置文件包含数据库连接信息，限制为当前用户可读。占位值不能直接运行。
5. 使用本文新增的`recovery_state`模板时先按下节停服维护步骤执行`enroll`，再执行 `/absolute/output/im-service -config /absolute/path/alpha.json`。未登记模式启动时事务安装版本迁移（001—004）并核对固定配置绑定；已有库配置不匹配明确失败。`GET /healthz` 经 TLS 返回204表示数据库可达。SIGINT/SIGTERM 关闭 WSS、等待 HTTP 和数据库释放；未登记的旧Alpha模式仍可直接重开；已登记模式只有正常封存后可重开，异常退出保留门禁，见下节。
6. 对两个 SDK 调用 `connect({url, token, ca_certificate, conversation, peer, creator})`，其中 `ca_certificate` 是独立核验 CA 的 DER 小写十六进制；`peer` 是独立核验的对端 Identity。SDK 自动发布材料、创建/加入群、发送队列和补拉；应用调用 `send`、`history`、`subscribe`、`networkState` 即可。正常收发不导出/搬运密文。`send` 返回本地保存；只有 `networkState` 的 accepted/delivered 分别表示服务已持久接受/对端已持久处理。

开发限额：全会话最多256条累计接受；SDK每库256条收发消息合计（含未接受发送）、1024条累计请求，数据16MiB、密码快照4MiB、元数据32MiB，操作前至少预留1MiB；内容大小和重复保存可能先触及存储预算。消息正文1—32768字节，材料/密文各96KiB，协议帧600KiB，分页1—4条并受字节预算限制，16个鉴权并发请求/连接，8个数据库连接。不清理幂等记录，不自动回退明文。永久身份/协议/密码失败进入 blocked；网络故障保留队列并退避重连。未知密码执行没有完整候选时必须走既有显式安全恢复，不能删库重试。

当前可执行验证：维护者先运行 `python3 tests/interop/network_alpha/environment.py prepare '/private/tmp/Rocket IM Network Alpha <unique-id>'` 创建专用本机 PostgreSQL 和 TLS；运行 `python3 tools/platform_release/persistent_network.py build <absolute-release-run>` 构建与回归实际 TGZ；再用 `python3 tests/interop/network_alpha/consume.py --release <absolute-release-run> --environment <environment.json> --run <new-absolute-test-run>` 做实际消费。工具链路径由项目现有 `dist/toolchains` 提供，须先按[本轮记录](../docs/端侧存储与附件管理.md#24-go-service与rust联网文本-alpha2026-11-24)准备，不会自动修改系统数据库。结束后使用 environment.py 的 `stop <temporary-directory>` 关闭专用 PostgreSQL；消费者与服务由装置回收，钥匙串锁定，证据保留。

尚未交付：动态成员、完整业务注册/登录、签发密钥轮换、密码设备撤销、附件、已读、Windows及Flutter/Swift/Kotlin持久包、完整客户端UI、恶意服务器回滚证明、容量承诺及生产备份/升级方案。下节的短期凭证签发/单凭证失效与本机001/002→003升级是有限能力。本轮未选择自有代码许可证，第三方材料与对外分发继续 NOT_APPROVED。

## 业务身份模式（business-alpha1）

本轮新增可替换业务身份入口及独立Go服务端SDK；前文固定配置模式仍可用于既有回归。新接入使用`business.config.example.json`，保持`devices: []`，两个设备由经过认证的业务后台通过公开API首次关联。业务系统负责自己的登录，不向IM Service交付业务密码或客户端私钥。

1. 部署方生成随机32字节签发密钥的小写十六进制，将其安全注入`credential_key_env`指定的环境变量。另生成`rimb_`加64位随机小写十六进制的业务凭证，仅在Service配置记录其SHA256、主体ID及UTC有效期，原文交给业务后台安全配置。使用安全秘密注入，不把秘密写到命令历史或日志。示例日期和占位字段必须替换，过期配置不会获得隐蔽兜底。
2. 使用当前模板时先按后文维护步骤执行`enroll`，以事务安装001—004，再启动Service；其运行不需要Go/Cargo或仓库源码。业务后台使用[独立Go SDK](../src/server-sdk/go/README.md)依次MapUser、BindDevice、IssueCredential，也可直接调用[公开HTTP契约](../api/http/business.openapi.json)。业务主体ID持久代表同一业务命名空间，不重新分配给其他组织。
3. Go SDK本机产物用`python3 tools/platform_release/business_go.py <absolute-new-package-directory>`组装。设置`GOPROXY=file://<absolute-proxy-directory>`、`GOSUMDB=off`（仅本机未发布包）与隔离模块缓存，安装`rocket-im.local/server-sdk@v0.1.0-alpha.1`，不用replace。外部消费者只依赖此模块；实际包摘要与验收目录见端侧存储第25节。
4. 业务后台从已认证会话取得external_user和授权设备，不信任客户端指定account。测试示例在`examples/business-backend/`，会话仅合成认证输入。MapUser取得账号scope后，客户端自己初始化密码身份，再只交付公钥用于绑定。独立核验双方Identity后使用设备令牌连接；Rust继续负责连接、队列、重试和SQLite。
5. 设备凭证有效期1—3600秒，不能超过主体截止时间；重试使用持久保存的原request_id和参数。过期/已撤销原请求拒绝，显式新请求才能签发新token。设备到期或单凭证撤销后，新HTTP/WSS操作被拒绝；已通过校验的在途操作可能完成。客户端显式disconnect，再用新token connect。该操作不撤销MLS成员私钥。

升级原Alpha库时保留旧devices配置及全部数据，只增加business设置，并在相应principal下增加`"legacy_users":{"已有业务用户":"原IM账号"}`。Service核对原配置绑定并事务补录原公开身份；业务后台经正常公开API映射/绑定同一公钥才能取得新凭证。成功启用后旧固定token禁用；配置不符或迁移失败拒绝启动并保留原库。不能用只识别schema1/2/3的旧程序回退schema4新库，不能删除business设置或任意更换签发密钥重新启动来绕过授权。完整密钥轮换与生产升级编排待后续；本机停服备份恢复见后文。

本轮业务接口请求体16KiB、8个配置业务主体、所有主体合计4096条持久幂等记录；成功映射、绑定、签发、撤销等均占账本，凭证过期不回收。精确重试先核对原件，新请求满额返回request_limit。其他固定双设备、单会话和消息限额沿用前文。数据库和日志不得存设备/业务令牌原文、用户私钥或E2EE正文。签发密钥仍需部署方安全保管；环境变量不是硬件安全边界。本轮没有新增第三方Go依赖，不改变项目和现有客户端包的许可待决状态。

业务联合验收入口：`python3 tests/interop/network_alpha/business_consume.py --release <frozen-release-directory> --environment <new-environment.json> --run <new-absolute-run>`。它创建仓库外Go模块消费者、独立测试业务后台及两份真实npm消费，正常客户端直连Go Service；故障代理只用于业务API响应丢失/超时注入。旧库迁移入口为同目录`business_migration.py`，要求`--baseline`提供前轮冻结后端源码目录、`--consumer`提供本轮实际版本化模块构建的消费者。所有配置和进程仅本机测试，清理由原environment入口管理。


## 双方授权的联网后继恢复（successor-alpha1）

当前dev.8复用dev.7的Rust自动凭证续期；业务后台和Go SDK不持有端侧签名私钥，也不代替双方批准恢复。设备首次遇到无完整候选的 `successor_required` 后，通过公开 `networkRecovery` 发起和批准，正常材料由Rust自动通过Service转交；用法及取消边界见[桌面SDK](../src/sdk/typescript/desktop/README.md)。首次预约/首次批准15分钟窗口，已授权材料可以在重启后续接；Ready后不得自动封存。最多16轮，无自动清理恢复证据。

新增003迁移保存当前密码上下文、恢复轮和逐事件处理结论。空库及真实schema1/2旧库升级均保留原消息与接受事实；旧库初始化为initial，不凭空创建恢复授权。第一次批准冻结旧上下文的新接受，已接受原件仍精确返回原确认；双方安装证明齐备才接受新上下文。未接受的旧发送为not_accepted；已接受但不再可安全解密的原件为context_retired并保留原始证据，不写成delivered。原明文历史和连续双游标保持。

Service须先升级到支持successor-alpha1的schema3版本，再使用dev.8客户端；旧dev.7正常文本接入在未开始后继恢复的升级库上有回归，不能据此承诺旧客户端理解恢复后的新字段或支持降级。跨签名客户端原钥匙串升级、生产备份恢复和数据库回滚不在本轮验收范围。

专项入口为 `tests/interop/network_alpha/recovery_consume.py`，参数沿用 `--release/--environment/--run`，`--suite core|faults|boundaries|lifecycle`；boundaries和lifecycle另加 `--proxy`，代理只注入故障，材料仍由正常Release的Rust转交。只操作新隔离环境；结束时回收进程、停止PG、锁定专用钥匙串。证据集中在[端侧存储第27节](../docs/端侧存储与附件管理.md#27-固定双端联网后继恢复2026-11-24)。


## Service停服备份恢复（service-backup-alpha1）

本机有限交付版本为`0.1.0-alpha.4`，schema4；HTTP/WSS alpha1、business-alpha1、successor-alpha1和Go SDK版本不变。本节扩展前述历史范围，不将生产备份列为已交付。完整契约和实际验收见[服务备份恢复](../docs/服务备份恢复.md)。

前提：显式停止并隔离旧Service，排除其他数据库写入者；使用本机可信原库或空库、原TLS身份与签发密钥。运行/维护使用的数据库角色须具备该schema的DDL/DML及`pg_control_system()`读取权限；本轮只验证专用本机测试角色。维护记录放在数据库和备份之外、预先创建的0700目录，保管者保证记录不回退。路径必须规范绝对路径，父目录不可经过符号链接。维护记录不可作为数据库备份的一部分回填；丢失记录不能用`enroll`重建信任。已登记库省略`recovery_state`也不能运行。路径含空格的PostgreSQL URI须使用`%20`，本轮pgx不将`+`当作空格。

部署方独立保存原配置、TLS证书/私钥及业务签发秘密，仍按原`credential_key_env`安全注入。业务主体/期限、固定设备及签发秘密、TLS证书、Service/会话和维护路径均受配置摘要约束；本版不提供原地配置/证书/签发密钥轮换。数据库连接和监听地址不进入此配置摘要，实际集群/数据库/schema另行绑定到维护记录。备份不包含数据库角色、密码、系统配置或用户E2EE私钥。

```sh
/absolute/output/im-service -version
/absolute/output/im-service -config /absolute/config.json -operation enroll
/absolute/output/im-service -config /absolute/config.json -operation serve
```

`enroll`只做一次。先将SDK断开或隔离接入，再由进程管理器向当前Service发SIGTERM并等待退出码0及`Service maintenance checkpoint sealed`日志。程序关闭WSS、排空HTTP和升级后的WSS任务，再在一致读事务中计算完整检查点；`kill -9`或退出失败均不算完成停服。确认维护记录仍幸存后导出：

```sh
/absolute/output/im-service -config /absolute/config.json -operation backup -backup /absolute/private-backups/latest.rimservice
```

`.rimservice`是本契约的完整数据包，不是任意`pg_dump`/SQL导入入口。最大64MiB，文件0600、父目录0700；不覆盖现有文件，不含签发秘密或私钥。成功输出`status=complete`及检查点/摘要；文件存在本身不代表成功完成。普通配置文件可能包含数据库凭证，仍限当前用户读取；备份包含敏感映射和消息元数据，必须保护。维护输出只报告状态/摘要，不打印秘密或正文。

为恢复创建**全新的隔离空数据库**，生成仅`database_url`指向新目标的配置副本，保留原维护路径及其他身份/秘密配置。原库不要覆盖或删除。保持停服并执行：

```sh
/absolute/output/im-service -config /absolute/restore.json -operation restore -backup /absolute/private-backups/latest.rimservice
/absolute/output/im-service -config /absolute/restore.json -operation serve
```

恢复用一个PG事务建表、导入全部12张表并核验结构/内容，提交后原子切换独立维护目标。原目标之后拒绝启动；重复同一已完成恢复可核验返回。导入或目标切换中断时，继续用**同一备份、同一目标配置**执行`restore`：空目标重做，完整提交目标完成切换；其他目标、非空无关库和部分不符内容拒绝。不能手工删除/编辑维护记录解除门禁。

恢复后使用原SDK对象/原系统秘密重新连接，验证原身份、历史、接受ID/顺序/密文、双游标及双方继续收发，再恢复正常接入。过期凭证仍按当前时钟过期，已撤销凭证保持撤销；不能借旧请求换发新凭证。未知密码执行仍经公开`networkRecovery`，维护工具不打开或修补客户端SQLite。

主要拒绝：`service_backup_stale`（旧检查点或数据不符）、`service_reconciliation_required`（未封存/导入未决）、`maintenance_target_mismatch`（错/已退役目标）、`maintenance_target_not_empty`（目标非空）、`maintenance_configuration_mismatch`（身份/配置/秘密不符）、`maintenance_file_*`（文件损坏、缺失、权限）、`schema_version_unsupported`、`maintenance_schema_mismatch`。运行中维护请求报`service_maintenance_busy`；缺失签发秘密可能在配置加载阶段报`invalid_business_config`。拒绝保留原库和原记录，不静默降级。

维护者演练入口：`python3 tools/platform_release/service_backup.py build <new-absolute-release>`；`verify <task-evidence-root> <release> <new-label> core|unknown|negatives|interruptions|renewal|lifecycle`。构建冻结真实Service，核验历史dev.9后仅为测试副本建立新合成签名；每轮使用新PG/TLS/钥匙串、独立Go模块及npm安装。仅测试程序制造端侧密码边界故障，正常发行程序无故障入口。异常退出的新增入口见下节；跨主机恢复、共同回滚和生产灾备不在交付范围。

## Service异常退出对账（service-reconcile-alpha1）

Service `0.1.0-alpha.5`新增005迁移（schema5）和显式离线对账，本轮83组联合验收及32项Go/race结果见[服务备份恢复第7节](../docs/服务备份恢复.md#7-异常退出对账契约与验收)。HTTP/WSS和Go/客户端SDK公共接口不变。必须保有原独立维护记录；它是本轮可信状态，不随数据库或备份共同回退，也不能有其他数据库写入者。

第一次使用：先按上一节登记并**正常停服封存**。确认维护记录和原配置幸存后执行：

```sh
/absolute/output/im-service -config /absolute/config.json -operation enable-reconciliation
/absolute/output/im-service -config /absolute/config.json -operation serve
```

启用核验完整schema4封存原件，单事务新增运行/操作标识，同时在库外先预约、提交后确认schema5候选。重复启用仅核验当前已封存原件。旧schema4的`running`不能启用或对账，因为此前没有逐事务证据。启用中断也不回退到旧格式：若库精确等于外部候选，可用`reconcile`完成；候选未提交或无法对应则拒绝并保留现场。旧alpha.4程序不能读取新维护格式/schema5；新程序保留未启用的schema4维护流程，并可在启用前恢复原alpha.4备份。启用后只接受新`service-backup-alpha2`检查点，不能恢复旧schema4备份。

运行时所有业务写入仍在原PG事务中完成。每次有变化的事务在提交前持久预约完整候选摘要与唯一操作ID，提交后持久确认；读写准入保持到两个持久步骤完成。结果未知会阻断后续访问并令健康检查失败，不能借普通退出封存未知状态。外部记录仅保存绑定与摘要，不包含用户私钥、凭证原文，也不备份业务数据。

异常退出后，停止并隔离入口，确认原进程退出及所有数据写入停止，再用**原目标、原配置和原维护路径**执行：

```sh
/absolute/output/im-service -config /absolute/config.json -operation reconcile
/absolute/output/im-service -config /absolute/config.json -operation serve
```

`reconcile`不启动监听，不重放密码操作，不导入数据。文件锁与PG维护锁排除并发启动/恢复。它核对12表全部行、结构、目标、身份绑定、运行ID和操作ID：无未决候选时只接受最后完成原件；有未决候选时仅接受DB精确等于该候选。成功生成新封存检查点，重复对账保持检查点；`serve`随后生成新运行身份，再开放监听。与正常停服一样，重开前的旧备份变为过期；需要备份时重新导出最新封存检查点。

`service_reconciliation_evidence_missing`表示旧记录缺少此前运行证据；`service_reconciliation_incomplete`表示候选无法与DB精确对应（包括DB仍在前态）；`service_reconciliation_mismatch`表示完成记录/运行身份与DB不一致。后两者不能通过删除记录、改摘要、重新登记、重放原请求或自动降级解决。保留数据库和全部幸存证据供独立核对。本版没有从摘要恢复丢失业务数据的能力，不宣称可恢复所有崩溃窗口；Service、SDK和独立证据共同回退仍不可判定。

完成对账和重开后，用原SDK/系统秘密验证接受原件、历史/稳定分页、downloaded/processed/reported及双方继续通信；密码执行未知仍通过公开`networkRecovery`，不能清除SDK门禁。正常SIGTERM封存、`backup`与新空目标`restore`继续可用，目标切换中断仍必须使用原备份/原预约目标续接。

新增验收套件：`reconcile-core|reconcile-unknown|reconcile-negatives|reconcile-interruptions|reconcile-upgrade|reconcile-successor|reconcile-renewal|reconcile-lifecycle`，沿用上述`verify`入口。物理断电、恶意Service和共同回退不由本机进程中断测试证明。


## 现有限额的容量与时延复跑

实际alpha.5/dev.9在两个独立本机环境各完成256条E2EE；另一个环境中的真实第257条被Service拒绝，原密文队列保留。当前未接受队列会阻塞后续补拉；32KiB正文也可能先触及端侧字节预算，不能仅按消息条数规划。近满/满额正常备份、新空目标恢复、SIGKILL后显式对账及短凭证续期的测量见[服务备份恢复第8节](../docs/服务备份恢复.md#8-现有限额容量与时延验收)。这是有限本机基线，不是生产QPS或SLO。

复跑使用`python3 tools/platform_release/service_capacity.py verify <task-root> <frozen-service-release> <new-label> baseline|overflow|large-local|recovery|renewal|lifecycle|successor|unknown`，baseline顺序执行两个独立新label。装置通过公开SDK驱动真实包，创建新隔离PG/TLS及专用钥匙串，结束后清理所属进程/PG并锁定钥匙串；不扩额、清库或淘汰幂等事实。64MiB导出文件预算与256MiB完整状态行JSON读取预算分别验证，维护摘要不是数据备份。


## 只读容量诊断（alpha.6历史）

Service `0.1.0-alpha.6`增加 `GET /v1/capacity`（设备自身固定会话/同步范围）和 `GET /v1/business/capacity`（显式全局计量权限）；无query、正文或请求号。两者都使用原Bearer鉴权、维护门与受控只读事务，返回 `Cache-Control: no-store`。业务Go SDK `v0.1.0-alpha.2`提供 `Capacity(ctx)`，全局接口要求对应principal在新实例初始化前配置 `capacity_read: true`；默认普通业务返回forbidden。未配置保持旧配置摘要，不能向已登记旧实例直接添加权限来绕过配置对账。

该alpha.6诊断轮的用量/硬余量不代表持久预留或执行成功，reserve固定not_implemented、受保护余量与普通可用量为null。SDK/Service无跨库原子快照；64MiB最终导出与256MiB行JSON对账分开，schema5旧导出行预检标not_applied。实际计量、超限含义及兼容验证见[Service第11节](../docs/服务备份恢复.md#service-capacity-readonly-20261125)。迁移001—005及普通准入/限额保持；Windows、生产与分发仍未验收/批准。

## 已知控制报告有限预留（alpha.7）

本地`known-v1`只保护已持久、连续且位于下一个message之前的delivered/unavailable报告。先正常停服并确认原维护记录sealed且已启用外部对账，再用相同配置执行`im-service -config <原配置> -operation enable-capacity-reserve`；成功后按原入口启动。006迁移将schema5显式升级至6，不会自动启用或降级，旧Service将拒载；重复操作幂等。每次原受控事务在外部候选预约前核验全部已用行JSON与剩余增长，超额返回`capacity_reserved`且回滚。

新`service-capacity-alpha2`的`reserve.state`为not_enabled或bounded_ready。Go SDK alpha.3仅封装只读查询，启用仍须离线维护；全局查询仍要求原`capacity_read:true`权限，设备仅见自身范围。配置摘要、原鉴权、未知提交/撤销/恢复门禁和256/4096/16、64MiB导出、256MiB对账限额保持。认证续期/撤销、未来消息、后继材料、完整导出和磁盘未预约，也没有SDK/Service共同工作集完成保证。

客户端dev.12单独调用`reserveCapacity()`启用v6及格式2备份；两端启用不是跨库原子操作。构建和复跑仍使用原`persistent_network.py build-reserve`、`service_backup.py build-new-client`及`service_capacity.py verify ... reserve|reserve-full|reserve-upgrade|reserve-upgrade-full`。完整范围与证据见[Service第12节](../docs/服务备份恢复.md#service-capacity-known-20261125)。
