# Go 业务服务端 SDK（本机 Alpha）

模块 `rocket-im.local/server-sdk`，版本 `v0.1.0-alpha.2`，Go 1.27.4，仅标准库。`.local` 是本机版本化模块代理标识，尚未对外发布，也不表示许可或分发获准。接入方只需 Go 与本模块，不需要 Rust、Service 源码或数据库访问。

```go
import rocketim "rocket-im.local/server-sdk"

client, err := rocketim.New(rocketim.Options{
    Endpoint: "https://127.0.0.1:9443",
    Service: "your-service",
    BusinessToken: businessSecret, // 从业务后台的安全配置注入
    RootCAs: trustedRoots,         // nil 使用系统根；不可跳过证书验证
})
// 检查err；调用结束client.Close()，每次调用传入context。
user, err := client.MapUser(ctx, rocketim.UserRequest{
    RequestID: savedMappingRequest, ExternalUser: authenticatedBusinessUser,
})
binding, err := client.BindDevice(ctx, rocketim.DeviceRequest{
    UserRequest: rocketim.UserRequest{RequestID: savedDeviceRequest, ExternalUser: authenticatedBusinessUser},
    Account: user.Account, Device: authorizedDevice, IdentityKey: devicePublicKey,
})
credential, err := client.IssueCredential(ctx, rocketim.CredentialRequest{
    UserRequest: rocketim.UserRequest{RequestID: savedCredentialRequest, ExternalUser: authenticatedBusinessUser},
    Account: binding.Account, Device: authorizedDevice, TTLSeconds: 300,
})
```

上例省略逐步错误处理以突出调用顺序；实际调用必须先处理上一调用的错误。业务系统负责已有账号登录、设备请求授权及秘密保管；`ExternalUser` 必须取自已认证会话，不能信任客户端提交的账号。`RevokeCredential` 只停止指定访问令牌，不改变 E2EE 成员或回收已经解密的数据。

公开接口为 `POST /v1/business/{users,devices,credentials,revocations}`。Service、业务主体、外部用户、IM账号和设备共同约束权限。业务主体只能操作自己映射的用户。本轮固定两个设备、每个账号一个设备、一个会话；不支持替换已有公钥。登录和目录关联均不构成密码信任；客户端必须独立核验对端公钥。SDK不接收任何用户解密私钥。

业务凭证 `rimb_…` 仅使用业务接口；设备凭证 `rimd_…` 使用 `/v1/rpc`、`/v1/ws` 和自身范围的 `GET /v1/capacity`。设备有效期为1—3600秒，不能超过业务凭证截止时间。不要记录令牌或完整响应；服务数据库仅保存不可直接使用的凭证ID/作用域/期限/撤销状态。客户端令牌只通过认证后的安全业务通道交付给对应设备。

同一业务主体的 `RequestID` 在所有写接口共用，须由业务后台持久保存。相同请求号和规范化内容返回相同结果；异内容/异操作返回 `idempotency_conflict`。新请求号映射同一外部用户仍返回原账号；相同设备绑定仍返回原关联。签发重试返回相同令牌和原截止时间，已过期/已撤销则明确拒绝，绝不自动续期。需要新凭证时使用新请求号；旧凭证不会自动撤销。提交后丢响应可安全重试，超时不表示事务未提交。每服务4096条业务请求账本，达到限额拒绝新请求，不删除去重记录。

Client可并发使用，拥有自己的HTTP连接池；`Close`只清理空闲连接。每次尝试默认5秒，最多2次，可配置为1—3次；仅传输失败、429和503会重试，等待50/100毫秒且响应context取消。通过context设置总截止时间，错误保留`errors.Is(context.Canceled/DeadlineExceeded)`。HTTP错误使用`errors.As`读取`*APIError`的`Code`、`StatusCode`。不跟随重定向，不把凭证发送给其他地址；TLS最低1.3。

`client.Capacity(ctx)` 调用无正文、无请求号的 `GET /v1/business/capacity`。需要为运维使用的业务主体显式配置 `capacity_read: true`；默认普通业务主体返回 `forbidden`。此权限允许读取全实例业务请求、恢复轮及完整12表逻辑预算，不能配置给不应看到全局计数的主体。配置未启用时序列化保持兼容；启用会改变既有配置摘要，当前仅在新实例初始化时设置，不允许为诊断绕过旧库配置对账。

结果为同一受控读事务的观察，所有计数和字节是规范十进制字符串。`reserve.state` 为 `not_implemented`，受保护余量与普通可用量为 `null`；硬余量不表示下一操作必定成功。SDK严格校验未知字段、缺失、可空性、枚举及u64范围，设备自身诊断不通过本业务SDK调用。64MiB完整备份编码、256MiB对账行JSON分别报告；schema5不再采用的旧导出行预检标记 `not_applied`，不用于虚构阻断。接口不创建业务请求，4096账本已满也可在正确权限内读取；锁定或对账未确认仍明确失败。公开契约见仓库 `api/http/capacity.schema.json` 与 Service 备份恢复文档。

业务凭证/签发密钥轮换、完备限流、多租户、动态设备和生产运维并未随本模块交付。Service本轮禁止移除已启用的业务认证配置或更换签发密钥后直接打开旧库，避免静默回退旧固定令牌。本模块没有新增第三方依赖或选择项目许可证，既有许可待决保持。
