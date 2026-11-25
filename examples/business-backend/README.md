# 可替换的业务身份接入示例

这是独立 Go 模块，只依赖实际版本化 `rocket-im.local/server-sdk v0.1.0-alpha.2`。没有源码 `replace`、Service内部包或IM数据库连接。用本机模块代理安装后构建，运行 `business-backend -config <absolute-json>`。

配置包含 `listen`、`tls_cert`、`tls_key`、`service_url`、`service`、`ca_file`、`business_token_env` 和两个合成 `sessions`（`external_user`、`device`、`token_sha256`）。业务凭证仅从指定环境变量读取。示例的 `authenticate` 用已准备的合成会话模拟业务系统登录结果，不提供真实注册/密码管理；接入已有业务时用其认证中间件替换此函数，保留从认证上下文获取用户/设备的规则。

所有接口要求 HTTPS 和 `Authorization: Bearer <business-session-token>`，客户端不持有Service业务凭证。按顺序调用：

1. `POST /im/user`，提交`{"device":"已授权设备","request_id":"请求号"}`，取得IM账号与客户端SDK scope。
2. 客户端使用真实 SDK 初始化自己的本地身份。将公开`identity_key`交给`POST /im/device`，附同一device和稳定request_id；私钥留在客户端。
3. `POST /im/credential`，提交device、稳定request_id和`ttl_seconds`，取得短期设备凭证。
4. 客户端通过独立渠道核验对端公开Identity，再向 SDK 的`connect`传入受限凭证、独立CA、会话和对端身份，调用公开send/history/subscribe即可。
5. `POST /im/revoke`，提交device、稳定request_id和credential_id，停止该凭证。它不是MLS设备撤销。

输入不接受external_user或account；冒用其他设备明确拒绝。用户映射请求号由已认证的外部用户稳定派生。业务操作request_id仍由调用方保存和重试；本示例没有代替真实后台实现持久会话、审计和请求工作流。没有把示例复制作为SDK接入要求。


客户端自动续期使用 dev.7及后续版本的 `credentialProvider`：接入方在回调中带自己的业务登录会话调用 `/im/credential`，用回调 `request_id` 作为本次签发号，并把回调 `signal` 传入HTTPS请求。成功结果的 `identity.scope`、`token`、`expires_at` 分别映射到SDK凭证；期限转为 `String(Date.parse(expires_at))`（UTC Unix毫秒）。不得根据SDK回调scope替换业务认证上下文；本示例始终从已认证session限定external_user及device。

业务响应暂时不可用可返回SDK的unavailable；登录失效/越权明确返回login_required/forbidden。同一个Go SDK调用内的网络重试保持原请求号；Rust下一次有界认证尝试使用新请求号，新凭证不延长或撤销旧凭证。业务凭证rimb_仍只在后台。此示例的合成登录不是完整账号系统；具体客户端契约及取消说明见[桌面SDK](../../src/sdk/typescript/desktop/README.md)。


dev.8的联网后继恢复继续使用这里签发的受限设备凭证。恢复的发起、批准或拒绝必须由对应设备通过公开 `networkRecovery` 操作；业务登录成功、重新签发访问凭证和公钥目录都不等于恢复授权。恢复私钥和材料签名保留在客户端，业务后台不转交恢复密文、不直接访问IM表；当前Go SDK接口无需增加恢复方法。
