# 独立 Go 模块消费者

此模块只用公开Go SDK。验收装置把它复制到仓库外，设置隔离的`GOMODCACHE`和本机只读`GOPROXY=file://…`，安装版本化zip，不使用replace或源码路径依赖。构建后的程序读受保护配置文件和标准输入JSONL；输出仅给测试进程内存，不把凭证响应保存为日志。

`op`为users/devices/credentials/revocations，body为SDK请求类型，deadline_ms可测试取消/超时。此程序只负责公开API调用，不读写IM表，不运行Rust/Cargo，也不接触客户端密码私钥。正常Node联网使用独立示例业务后台；本消费者用于并发、故障、越权与精确重试验收。
