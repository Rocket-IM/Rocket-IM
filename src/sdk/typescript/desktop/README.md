# Rocket-IM macOS 持久 SDK 开发包

`@rocket-im/desktop-dev@0.2.0-dev.13`：仅 macOS arm64 + Node >=22，固定两个成员设备、测试身份、每端一个 SQLite 数据库。预编译 Rust 程序随包提供；消费方无需 Rust、Cargo 或生成器。

本版联网后继恢复通过 `networkRecovery` 明确授权，Rust 自动交换材料。原请求无完整候选且返回 `successor_required` 时，发起端调用 `{kind:'begin', request_id, action}`；对端从 `networkState().recovery` 取得已核验的 `round_id`，调用 `{kind:'approve', round_id}` 或 `{kind:'reject', round_id}`。不把登录成功、Service 目录或通知当作批准。双方安装证明齐备后 `phase==='complete'` 才能继续新发送，新消息必须用新请求/消息 ID。

`building`/`joining` 表示密码步骤可能已执行但无完整候选；不能重做。用户可明确 `{kind:'seal', round_id}`，由 Rust 自动转交双方封存材料，再用原未知请求发起新轮。Ready 后封存被拒绝，只能续接原轮。关闭/断开取消传输，保留已持久授权；同一空间重新连接会续接，logout 仍销毁该空间。

旧队列 `not_accepted` 表示服务在冻结旧上下文后确认原件未接受；`context_retired` 表示原件已接受但对端无法再安全解密，二者均不表示送达。既有明文历史保持；`unavailable_history` 提供未解密历史摘要，`networkUnavailable(sequence)` 单份读取保留的原密文及接受事实。双游标仍连续推进，每个不可解密事件单独提交明确终态，不伪造正文或 delivered。状态变更通知只发生在相应持久提交后。

联网材料协议为 `successor-alpha1`，与既有离线签名材料及设备访问凭证分离；最多16轮。新预约及对端首次批准的窗口为15分钟；已经持久授权的传输不因窗口结束被撤销，Ready 后没有自动关闭。若Service确认首次预约已过期且从未接受，SDK结束这次未产生密码材料的意图并报告 `recovery_deadline`，原未决请求仍保留，重新发起需要显式Begin。已经预约的同ID重传优先返回原记录，不会被当作未预约超时清除。进入联网恢复管理后，原离线材料变更入口明确拒绝 `network_recovery_managed`，状态/已归档材料只读查询仍可用。实际验收见仓库端侧存储文档第27节，完整阶段0/生产/分发未获批准。

安装本地真实 TGZ：`npm install --ignore-scripts /absolute/path/rocket-im-desktop-dev-0.2.0-dev.13.tgz`。导入 `PersistentDevice`，使用规范绝对路径、`{service, account, device}` 和显式 `keychain` 文件路径打开实例。新库须显式 `create: true`；已存在库使用 `false`，不自动新建/重置/迁移旧 POC 库。

公开方法：`connect`、`disconnect`、`networkState`、`networkRecovery`、`networkUnavailable`、`initialize`、`joiningMaterial`、`createGroup`、`joinGroup`、`send`、`receive`、`message`、`history`、`request`、`state`、`capacity`、`subscribe`、`recoverRequest`、`recovery`、`close`、`logout`。身份和协议材料采用小写十六进制；所有计数为十进制字符串。每端仅支持一个群，公钥必须由接入方核验/固定，不能因登录或收到 KeyPackage 自动信任。完整可执行接入示例随仓库外独立消费工程提供。

`send(requestId, messageId, text)` 共同保存密码状态、原密文和消息；以完全相同参数重试返回原结果。请求 ID 异内容和消息 ID 冲突明确失败。`receive` 共同保存去重、明文消息、密码状态和本地成功接收计数；重复密文不再次解密或发成功事件。消息正文上限 32768 UTF-8 字节，单库最多 256 条收发消息和 1024 个请求；到限明确失败，不隐式淘汰精确重试记录。

`history({direction: 'forward', page_size: 20, cursor: null})` 统一返回本空间已提交的发送和接收消息。`forward` 从旧到新，`backward` 从新到旧；顺序是本地持久化追加顺序，不是服务器顺序、网络游标或发送时间。每项 `local_position` 为从1开始的十进制字符串。第一页固定包含式 `upper_bound`，后续收发仅进入新查询；`next_cursor` 原样保存，可在同一路径/空间重开实例后续页。续页保持方向和页大小；相同游标可重复读取同一页。

`page_size` 为1–64，另有512KiB条目JSON编码预算（长控制字符正文会使一页提前结束）。以 `done` 判断结束；结束时 `next_cursor=null`，空库为 `items=[]/upper_bound="0"/done=true`。没有分页会话或长期读事务，每页独立读取、结束事务后才返回，不发提交事件。返回对象是独立数据，不是宿主历史库。

游标绑定规范数据库路径、服务/账号/设备、原身份、固定历史前缀、方向和页大小；跨空间、改变选项、截短或不匹配历史拒绝 `history_cursor_mismatch`，格式坏/未知版本拒绝 `history_cursor_invalid`，页大小0或超过64拒绝 `history_page_size_invalid`；错误类型、负数、小数、未知字段/方向等拒绝 `invalid_request`。这些参数错误不暂停实例。游标是无秘密的查询定位符，不是授权令牌或防回滚锚；不得依赖它认证调用者。锁定/退出/取消/关闭沿用现有错误和逐作业、交付边界检查，已交付的历史不能追溯撤回。

查询不改数据库格式（加密v3）、身份、消息或请求。未绑定网络的dev.4/dev.5原库直接可查；受系统认可的相同签名要求下，旧版仍可打开没有新增网络账本的库。原始dev.4归档的签名不自动授权任意新签名。未提交候选及退役请求不进入列表；精确恢复提交后在新查询中出现一次；后继恢复保留原历史及已有查询范围，新上下文消息继续追加。消息256条/请求1024条等开发限额保持。

`connect({url,token,ca_certificate,conversation,peer,creator})` 接入固定双设备 Go Service Alpha1。两端先各自initialize，独立核验对端Identity，再在Service中显式配置身份和设备凭证摘要。`url`仅接受带端口的`wss://字面IP:端口/v1/ws`，`ca_certificate`为独立核验CA的DER小写十六进制；TLS1.3验证证书链和IP SAN。SDK不会将登录凭证当作E2EE信任。凭证只用于当前连接内存，重开需再次传入；不会放在命令行或SQLite中。

自动凭证接入使用互斥的 `credentialProvider`，不传 `token`：

```ts
await device.connect({
  url, ca_certificate, conversation, peer: independentlyVerifiedPeer, creator,
  authentication: { timeout_ms: 5000, max_attempts: 3 },
  credentialProvider: async ({ scope, request_id, signal }) => {
    // yourBusinessLogin只访问本业务后台；业务会话决定账号/device，不信任客户端scope代领。
    const result = await yourBusinessLogin.issueImCredential({ request_id, signal });
    return { kind: 'credential', credential: {
      scope: result.identity.scope, token: result.token,
      expires_at_unix_ms: String(Date.parse(result.expires_at)),
    }};
  },
});
```

自动模式先返回 `authenticating`，在 `subscribe`/`networkState` 观察核验后的 `online`。Rust首次及真实到期发起一次在途认证，普通重连复用未到期凭证；UTC绝对时间与单调时钟共同防止时钟回拨延长期限。公开回调含冻结scope、唯一request_id、`initial|expired`原因、attempt、timeout_ms和独立signal。每次尝试独立请求号（重启不复用）；业务SDK单次调用内仍用同请求号精确重试。新凭证不自动撤销旧凭证；Service独立拒绝到期、撤销或错误身份，不以宿主元数据作为权限。

回调返回 `{kind:'failure',code:'unavailable'}` 才允许暂时重试，超时同样重试；默认5秒/次、最多3次，配置100–30000毫秒/次、1–3次，退避250/500毫秒。尚未完成Service身份核验就再次到期的凭证也消耗同一轮预算，不靠连续短凭证无限重试。耗尽保留原队列并进入blocked。`login_required|forbidden|cancelled|invalid_credential|provider_failed`、返回过期/错误范围或用途、到期前Service拒绝均永久阻断本轮；异常内容不记录，抛出异常映射provider_failed。修复登录或配置后显式disconnect/connect重新开启。认证期间可以正常保存发送和读取历史，不占SQLite线程；SDK不会重新加密旧发送。

`disconnect`立即使宿主迟到结果失效并abort，Rust处理命令后丢弃连接/凭证；`close`另回收原生进程；`logout`另销毁当前空间本地解密钥。回调应把signal传给I/O并自行清理，不能同步阻塞JS事件循环；SDK不能强制终止忽略signal的用户Promise，但不等待它结束或接受迟到成功/失败。网络等待仍有原绝对截止时间；已受理普通命令取消仍是下文结果未知语义，不能把取消当回滚。JS字符串及运行库内部暂存不承诺可擦除；凭证不进入日志、命令行、SQLite或E2EE消息。

首次联网需要仅已初始化、尚未手动建群的空间；dev.5旧本地群仍可查历史及恢复，但直接connect返回`network_fresh_group_required`，本轮没有旧本地群向Service的导入协议。Rust自动发布公开材料、创建/加入固定群、按本地提交顺序发送原密文、重连、冻结上界分页补拉及报告处理回执。宿主无需网络轮询或搬运密文。`send`只确认本地保存；`networkState().sending`中的`local_saved`、`accepted`、`delivered`分别表示本地保存、Service持久接受、对端持久处理，均不是已读。

`subscribe`新增`network_state`/`network_error`判别事件，保留`local_commit`和`context_changed`，允许回调重入查询。下载原件和下载位置共同提交，处理消息/密码/去重/处理游标在同一事务提交，之后才发对应状态及设备处理报告。`disconnect`/`close`保留队列，重新connect会精确重试；永久身份/协议/密码错误进入blocked。请求共享1秒绝对I/O截止时间，握手3秒，退避250ms—2s；所有网络等待在Rust协调线程，不占数据库线程。

网络协议默认支持最多256条服务接受及512个设备事件，不超过本地既有限额。完整候选在重连时可自动精确安装；可能已执行但无候选仍暂停并要求上述双方明确授权的后继恢复，绝不自动重加密旧请求。

dev.7→dev.8 升级时先 `close()` 原对象，安装由原系统项认可签名的新包，再以原 `path`、完整 `scope`、`keychain` 和 `create:false` 打开。重新提供原连接参数及业务凭证回调；无需再次 initialize，也不复制数据库、不更改 ACL。合法安装目录可以改变，数据库的规范路径保持原样；历史分页游标可继续使用。

本机真实包已验证普通 Alpha1 收发的 dev.7/dev.8 混合运行；dev.7 没有 `networkRecovery`，恢复材料不会因升级、认证或收件自动得到对端批准。需要后继恢复时双方都必须升级，再通过上文公开接口明确授权。新版持久恢复字段写入后，真实 dev.7 打开原库返回 `store_invalid`，保留原文件/身份/ACL；请继续使用 dev.8，不能通过删字段或重建身份解决。尚未写这些字段的普通联网库仍可由同签名 dev.7 打开，故此边界是格式兼容检查，**不是版本防回滚**。普通装配版本/摘要检查与系统签名授权是两条独立门禁。真实范围及副本来源见仓库端侧存储第28节。

取消/超时会终止当前实例的原生进程，属于结果未知。用相同 scope 重开，先 `request(requestId)` 查询；`recoverRequest(requestId, action)` 使用原完整输入显式恢复。未越过执行栅栏的预约只执行一次；已保存完整候选的请求安装原候选；已提交结果精确返回且不重发事件。初始化使用预约前已持久保存的同一身份种子。`successor_required` 表示可能已执行密码操作但没有完整候选，禁止重做、清 Pending 或回退密码状态。

尚未进入联网恢复管理的离线空间可用 `recovery` 执行固定双端后继协议；联网空间使用上文 `networkRecovery`，不手工转交以下材料：

```js
const offer = await target.recovery({ kind: 'begin', request_id: originalId, action: originalAction });
const approval = await peer.recovery({ kind: 'accept', offer: offer.packet, peer: pinnedTargetIdentity });
const ready = await target.recovery({ kind: 'join', approval: approval.packet });
const receipt = await peer.recovery({ kind: 'confirm', ready: ready.packet });
await target.recovery({ kind: 'finish', receipt: receipt.packet });
```

双方签名身份不变，`accept` 的 Identity 必须是接入方已独立核验的目标公钥。签名绑定双方范围、公钥、原上下文、原请求摘要、前轮与全部材料。原库历史、原请求输入/摘要和旧密码快照保留；未决请求变为 `retired`，不伪造原发送/接收成功；重试该请求返回 `request_retired`（paused=false，不表示新上下文暂停）。新消息需要新 requestId/messageId；`context` 明确标识后继，旧上下文密文以新请求提交会在密码处理前拒绝。每次恢复最多一个合法后继；固定身份不等于允许增加成员。

中断后 `recovery({kind:'status'})` 返回已持久阶段和原公开材料。`offered` 重送原 Offer，`prepared` 重送原 Approval，`ready` 必须继续 Confirm/Finish，`committed` 重送原 Commit。`building` 或 `joining` 表示本轮也存在密码执行缺口：该端调用 `{kind:'close',peer_close:null}`，对端用返回原件调用 Close，再将对端 Close 原件交回首端；双方达到 `closed` 后，目标重新 Begin。Close 由双方签名且永久封存该轮，后续用全新材料，不复用可能消耗的 KeyPackage。`closing` 重送原 Close；不得从 `ready` 开始关闭。重复材料返回原件，错误身份/范围/材料拒绝且没有成功事件。若另一端已开始下一轮，用 `recovery({kind:"inspect",context:上轮context})` 只读取回上轮已归档的 Commit 等原件，先完成落后端再处理新 Offer；Inspect 不重新激活旧状态。

`local_commit` 表示原业务请求完成；后继安装的事件为 `context_changed`，其中 `request_id` 是后继 context。签名材料交换和重复结果不发提交事件。每库最多16次完成的后继转换/16轮历史恢复，并有32MiB恢复证据总限额；到限保留证据并拒绝新恢复。`close` 等待已受理请求并回收进程，阻止新调用及迟到事件。

新库为 SQLCipher 加密 v3，覆盖主库、回滚日志中的 provider、data/crypto/recovery、待决候选及恢复档案。`keychain` 必须是宿主事先创建并解锁的专用 macOS 文件钥匙串；SDK 不接收其密码，不操作默认登录钥匙串，不弹出授权 UI。每个空间使用随机32字节钥，钥匙串项固定服务/账号/设备/数据库规范路径/用途。明文 v1/v2 统一拒绝 `plaintext_migration_required`，本版不提供迁移；前版明文文件、备份及历史证据仍有原风险。密文复制到新路径或错误 scope 无法自动重新绑定。

实际钥匙串锁定、缺项、不可用、ACL拒绝或密钥替换均明确失败；每个数据库作业前后及公开结果交付前重新核验；空间访问锁最多等待100ms，超时返回 `protection_busy`，没有固定密钥或缓存放行。系统状态变化与 SQLite 提交不能原子同步：晚期锁定可能已有提交但没有成功结果，解锁后使用原 requestId 精确查询/恢复。已交付数据、Rust/OpenMLS、SQLCipher、系统服务及内存/swap的既有副本不能因锁定被追溯撤回。

`close()` 释放资源并保留钥及历史。`logout()` 是显式破坏性本地退出：停止新请求与通知，已排队调用不再向当前对象交付成功；用无密钥墓碑原子替换本空间钥匙串项并回收原生进程。加密数据库和空访问锁文件保留，本空间不可再次打开，也不自动新建身份。其他相同空间进程的下一次作业/交付检查拒绝；空闲进程需其拥有者关闭，SDK不能跨进程物理抹除既有内存。一个账号退出不锁整个钥匙串、不影响其他账号，也不代表远端设备撤销。

重复实例 `logout()` 复用同一结果；若进程中断或失败，使用 `await PersistentDevice.logout({path, scope, keychain})`：仍有钥则验证原库再退出，已有墓碑则确认退出；锁定/缺项/篡改不能伪装成功。文件钥匙串与磁盘/备份的历史版本可能仍保留旧密钥，不能声称 SSD 安全擦除或抵抗全库/钥匙串共同回滚。再次建立身份需明确使用新的本地存储空间，并按新设备信任规则接入。

这是受限开发/测试版本，只验证 macOS ARM64、当前 Node 宿主和专用文件钥匙串。访问 ACL 由系统根据创建项目时的预编译程序建立代码身份要求。受认可的相同签名要求可支持换版本和安装路径，必须用真实旧项验证；不同签名者或程序标识明确拒绝，不修改原 ACL、不重建身份。ad hoc 没有跨二进制升级保证，改成证书签名也不自动继承旧 ad hoc 项。包版本、协议号和 SHA256 只检测装配一致性，不构成发行者认证；操作系统认可的是原生程序的签名身份，不认证 Node 宿主或调用者。能执行合法程序并访问同一用户数据的宿主仍在信任边界内，不承诺隔离恶意同用户进程。签名验收入口仅使用新生成的合成证书，不代表 Apple 发行签名、公证、证书轮换或版本防回滚。文件钥匙串使用已弃用 Security API，不等同于 Data Protection Keychain 或 Secure Enclave。仅接受应用信任且持久保存的私有目录，禁止不可信共享目录。本轮网络仅接入固定双设备Go Alpha；仅备份启用后的同机钥匙串进度保护，不具备独立故障域或硬件防回滚；无生产信任、成员变更、附件或 UI；Windows、移动端和浏览器持久适配本轮未验收。阶段0仍 NOT_COMPLETE。旧内存 SDK 接口独立保留。

包内许可材料是本次实际编译依赖的采集记录（含构建输入，不是最终链接精确 SBOM），不表示分发批准；HPKE 既有许可冲突仍开放。本包仅在本机开发验收，不公开发布。

## 同机受控备份恢复（dev.9）

```ts
await device.disconnect();
const receipt = await device.createBackup('/private/app-data/recovery.rimbackup');
await device.close(); // 同空间的其他实例也必须关闭
const restored = await PersistentDevice.restoreBackup(
  {path: originalPath, scope, keychain}, '/private/app-data/recovery.rimbackup');
const reopened = await PersistentDevice.open({path: originalPath, scope, keychain});
// 使用原已核验对端与业务凭证提供方重新connect；接受/送达由networkState核对。
```

首次备份将v3库显式升级到v4，并在原专用钥匙串创建进度项；旧版本随后拒绝该库。加密快照包括原身份、历史、请求、密码候选、网络队列、游标和恢复门禁，采用现有SQLCipher，最大64MiB。系统密钥和访问凭证不进入备份。导出目标须为私有目录内规范绝对`.rimbackup`路径，同路径同状态可重试，其他文件不覆盖。失败也可能已完成启用或文件持久化，须以原路径重试核对；不要清除进度项。

导入仅允许原签名身份、同机原系统秘密、原Service/账号/设备和原规范数据库路径。所有实例关闭后，完整候选持久化并原子替换；`BackupInfo`仅确认端侧恢复，联网同步另行确认。原库缺失时仍需外部最新进度；尚有无法对账的提交预约返回`backup_reconciliation_required`。任何后续持久提交均使旧备份返回`backup_stale`，不能通过另建路径或清理钥匙串绕过。有效当前库不静默丢弃。

`backup_store_in_use`要求关闭同空间全部实例；`backup_disconnect_required`要求先断开网络；`backup_invalid`/`backup_format_unsupported`拒绝坏文件/错版本；锁定、缺钥、错误绑定和logout墓碑保持原系统错误。完整候选仍通过原`recoverRequest`准确安装；执行未知保持`successor_required`，必须显式`networkRecovery`，不得重新执行旧密码操作。

该能力假定原钥匙串未共同回滚、同用户宿主/文件环境可信；摘要和版本不是硬件防回滚。跨设备导出、口令托管、云备份、Service回滚、整机断电和生产灾备不在本机开发验收范围。正常程序没有测试故障入口。

## 永久容量拒绝（dev.10）

仅认证WSS中与当前send关联的`message_limit`响应可持久化为`rejected`。Service在事务锁内先检查精确幂等原件，再检查256条累计接受上限；错误表示该原件未接受，且在同一受控Service历史内不会因时间经过恢复容量。超时、响应丢失、认证失败、`idempotency_conflict`、`successor_required`及其他错误不进入此终态。旧上下文`not_accepted`/`context_retired`规则保持。

```ts
const state = await device.networkState();
for (const sending of state.sending) {
  if (sending.status === 'rejected') {
    // acceptance 为 null；rejection 为 {source:'service_send', code:'message_limit'}。
    const original = await device.request(sending.request_id);
    // complete 仅表示原本地密码提交；原密文及原revision保持，不能显示为已接受。
  }
}
const history = await device.history({direction:'forward', page_size:20});
// 拒绝原件仍在原local_position，并带rejection；message()也可取得原正文。
```

普通消息槽仍为256（收/发合计，包含未接受发送）；永久拒绝后，重复消息投影移除，原输入、原密文、原request/message ID、结果及修订留在原1024条请求账本，通过同一账本重建历史。拒绝标记与投影移除在同一SQLite事务中提交，不新增另一份原件、不淘汰幂等记录。故历史可多于256条，但始终受原请求数上限以及16MiB数据、4MiB密码快照、32MiB元数据和预约预算约束；字节/请求耗尽仍明确失败。满额后新消息仍拒绝，不通过清库恢复发送。

dev.9的有效加密v3/v4库可由dev.10原身份原路径打开；首次拒绝与数据库v5格式门禁原子提交，dev.9随后明确拒载。未知字段/坏状态拒载，失败保留原状态。备份容器仍为v1，内部新账本字段由旧包严格拒绝；新包完整保存和恢复。取消/超时不能撤销已提交事实；未完整提交的拒绝不对外冒充终态。

## 请求和字节预算耗尽后的使用边界

当前策略是保留已持久原件和幂等依据，到限停止相应新写；备份/恢复不会释放请求、消息或字节额度。Data包含原输入/结果、消息、网络事件和接受事实；32MiB元数据还包括完整执行候选、恢复材料及旧快照，不能只按正文大小或历史条数估算余量。没有公开的字节/请求余量诊断接口，`storage_limit`仍不区分Data与Meta预检。

- 对新请求，预约前的 `request_limit/storage_limit/message_limit` 不增加请求或执行该次群密码输入；停止生成新请求号反复尝试。若已经预约/执行或结果未知，先用原request ID查询，不能套用“没有提交”。
- 相同request ID及完整输入优先核对原记录，绕过新请求的数量/预留检查；complete复用原结果，failed/retired/pending保留原语义。相同密文但**新request ID**的Receive仍需额度，并新增一条请求结果。本地complete不等于Service接受。
- `request/state/message/history/networkState`及恢复status/inspect可用于查询已存业务状态，仍需完整库、可用系统秘密及匹配外部进度。SDK没有独立只读打开模式；普通操作的缓存路径仍会经过写事务，不能保证物理磁盘满时成功。
- 已接受消息仍需本地下载/处理/报告的写入空间；满请求或字节预算可能使网络blocked。保留原件和三个游标，不跳过事件或伪报送达；disconnect/connect不改变容量。仅认证Service的关联send返回 `message_limit` 才可记永久拒绝，超时、认证失败及其他错误均不能替代该证明。
- 第一次备份会写入guard和外部进度，须在有余量时启用并验证；不能保证Meta近满时首次启用成功。后继恢复保留旧快照并占原32MiB，仍需双方授权及原未知执行门禁。`logout`破坏本空间访问能力，不是释放容量后的恢复办法。
- Service成功业务请求累计4096，新的凭证续期和撤销也占该预算。到期不回收原件，精确重试不使过期/撤销凭证重新有效；因此有消息槽也未必能继续联网。

“恢复成功”只说明支持的完整状态已恢复；是否可继续新写、是否有余量处理至Service尾部须另行验证。有限固定总空间不能同时支持无限新输入和永久保留全部原件。容量诊断、同步/恢复专用余量、扩大总容量及长期归档目前均未实施；本节仅补充现有版本的边界，不发布新包。完整策略与待验收矩阵见[端侧存储第31节](../../../../docs/端侧存储与附件管理.md#budget-policy-20261125)。

## 容量诊断与有限余量设计进展（2026-11-25）

后续已完成[诊断契约与有限预留设计、内部边界验证](../../../../docs/端侧存储与附件管理.md#capacity-reserve-design-20261125)：拟议 `device.capacity()` 由Rust一次一致快照生成，各用量/上限/游标均用十进制字符串，分别报告硬余量、未建立的预留及受影响操作。**当前dev.10尚无此API，也未启用预留**；本轮仅新增内部测试，未修改TS接口或重发包。

实际MLS内部测试在22条32KiB全NUL接收后因字节预算拒绝第23条，满1024请求和近Data/Meta可阻断已下载事件处理；原件、请求和游标保持。近满Meta的完整候选可精确安装，但首次备份guard可能无法写入。结果不保证任意满额库可追平；Go/WSS独立Release联合验收、首次备份钥匙串交叉窗口和真正预留机制仍未完成。接入方继续使用现有状态/错误查询，不照草案调用不存在的API或根据文件大小自行绕过准入。


## 只读容量观察（dev.11）

`await device.capacity()` 返回 `sdk-capacity-alpha1`。可选参数只接受 `{ signal?: AbortSignal }`；null、未知字段或非宿主AbortSignal返回invalid_options，不会改账号范围。Rust在唯一SQLite线程的一次显式读事务内计量同一个完整状态，读事务结束、原访问与外部进度门禁成功后交付。查询不新增request、不执行密码步骤、不改库格式；既有准确外部进度预约仍可能由原核验路径结清。锁定、注销、关闭或取消沿用原错误；迟到结果不交付，不发提交事件。

`budgets`分别报告requests 1024、ordinary_messages 256、events 512、Data 16MiB、原crypto 4MiB、Meta 32MiB以及history/archives/transitions各16的用量、上限与硬余量。所有计数/字节/修订/游标都是u64规范十进制字符串；需要运算时用`BigInt`，禁止转成`Number`。candidate/session/archives/legacy字节是Meta包含项，不能重复相加；候选中的crypto按JSON字节数组真实编码计算。

`reserve.state`始终为`not_implemented`，`protected_remaining`和`ordinary_available`始终为`null`。`requires_input`表示还需原输入，`not_reserved`表示没有预留；二者都不保证执行成功。`blocked`只列当前能确定的阻断原因，执行仍重新核验。普通新接收与当前下载事件处理分别判断；缓存原件、旧上下文和控制事件不按新解密消息统一扣额。

`retry_request`须提供具体原请求，当前未知请求不能阻断其他历史精确重试；`recover_pending`专指当前未决请求。`recovery.pending`区分reserved、initialization_retry、executing_unknown、legacy_unknown和complete_candidate；`locally_authorized`仅表示本机已有恢复意图/决定或本地恢复会话，绝不表示双方已经授权或安装完成。完整候选安装、恢复、首次备份与导入导出仍受各自原门禁约束。

`observation_id`是临时标识，业务revision不包含所有网络变化，均不是执行许可。`physical`和`remote`为`unavailable`且`reserved=false`；这不是磁盘预留或SDK与Service的跨库原子快照。当前仅macOS arm64 Node路径；未扩展Windows、其他平台或UI。实际本轮验收与限制见仓库《端侧存储与附件管理》第33节。


## 已知原件有限预留（dev.12）

`await device.reserveCapacity({signal})` 显式启用 `known-v1` 并同事务升级库格式v6；容量不够返回 `capacity_reserved`，原库保持。取消结果不证明已受理的升级未提交，重开后用 `capacity()` 核实；重复启用不再写库。旧包不能读取v6；未启用的旧v3/v4/v5仍按原格式打开，不自动迁移。新备份格式2保留预留标记，格式1旧备份仍可在原外部进度门内导入。

`capacity()`现返回`sdk-capacity-alpha2`，未启用时`reserve.state=not_enabled`。成功启用后`bounded_ready`只证明当前列出的本地工作集的逻辑字节可容纳；各`reserve.resources`分开给出`protected_remaining`与`ordinary_available`，满足`U+R≤L`。不同资源不能合并成一个额度，所以顶层两个旧标量保持`null`。各普通写在原SQLite事务里重新计量；调用前查询不能代替准入检查。限额256/1024/512、16/4/32MiB和16轮均不变。

`reserve.work`列出：完整普通候选精确安装、已有发送原ID的ACK/认证永久拒绝、已经下载且位于未知解密之前的连续控制事件及报告，以及target已有Ready候选并已保存同轮commit后的本地Finish。首次backup_guard的实际82字节也计入Meta；这不保证64MiB备份文件或磁盘。候选密码字节数组和archives按真实JSON计入，已占用部分不再次预约。预留算法从原账本恢复，失败回滚不消耗、精确重试不重复扣额、关闭/未知结果不释放；原终态结清后R转入U。

仅资源检查通过且原门禁无阻断时，相应操作可显示`bounded_ready`。这不授予权限、不强制网络完成，也不保证对端或Service一起完成。新密码步骤、未知Executing/legacy、新后继、未下载/未来消息及控制、peer安装、凭证续期和任意磁盘故障均不承诺。授权、撤销、钥匙串锁定、退休上下文、外部进度和提交未知继续原安全规则。实际验证与未决项见[第34节](../../../../docs/端侧存储与附件管理.md#capacity-known-reserve-20261125)。


## 同一有限控制工作集（dev.13）

先启用`reserveCapacity()`，在已有联网绑定且下载了连续控制原件后调用`prepareCapacityWorkset()`。Rust从`reported+1`开始选取已下载的非空`delivered/unavailable`前缀，停止于首个message；宿主不能传工作集、范围或容量标签。首次准备自动启用原系统进度保护，再在原写事务保存固定原件摘要并升级v7；没有合格原件返回`workset_empty`，未知候选/活动恢复返回`workset_source_unavailable`。每个设备仅一个不可替换工作集，重复调用返回原记录，包括结清后；其他新工作集不在本实验范围。

`capacityWorkset()`返回`null`或`{workset,phase}`，所有序号均为十进制字符串。`prepared`是本地承诺；`confirmed`表示本地已持久保存Service准备回复；联网同步继续将本地确认提交给Service，保存其确认回复后变为`active`。只有`active/settled`包含SDK已持久收到的共同确认，`capacity().reserve.bounded_ready`仍只是本地保证。Service有独立的prepared/confirmed/settled状态，不能把两个不同时间的查询当作跨库原子快照。

active后沿原控制处理和received报告。SDK本地reported达到固定终点后请求结清；Service独立验证相同原件、全部received及自身游标，保存settled；SDK保存该回复才变为settled。未知提交、丢回复、关闭、重启、取消、超时均保留已有承诺，不自动解除或按期限回收。恢复只重试原范围，不重做密码输入；撤销、锁定和维护门禁仍可能阻止继续。凭证续期、新消息/后继、密码步骤、磁盘或网络可用性不在共同承诺中。

新记录与阶段增长纳入原Data/Meta和候选峰值，普通写无法侵占。v7及备份格式3由旧dev.12明确拒载；未准备的旧库仍按v3—v6打开。完整备份仍只支持原scope/规范路径/系统秘密/外部最新进度，旧备份不能抹掉承诺。格式3恢复保留所有原件与阶段；没有生产分发、Windows或其他语言持久端验收。


取消或关闭不等于未提交；工作集写入若返回`workset_commit_unknown`，重开后查询同一原记录，不创建替代ID。初次Service准备要求原上下文仍活动；已在Service持久准备的记录可以在双方明确授权的后继后继续核对并结清，但不会复活旧密码上下文。若外部进度有候选而数据库缺少对应完整状态，Service继续维护阻断，不自动回收。本机范围不承诺未来密码操作/认证/网络可用；协议与状态顺序见仓库《端侧存储与附件管理》第35节。
