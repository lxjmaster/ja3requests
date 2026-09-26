# ja3requests 当前能力与后续改进

## 已实现

- HTTPS 的 TLS 1.2 和可配置的 TLS 1.3 请求路径；通过 ALPN 协商 HTTP/2。
- TLS 1.2 RSA 密钥交换使用服务器公钥加密预主密钥；测试覆盖了选定密码套件的 Finished 验证和失败路径。
- TLS 1.2 与 TLS 1.3 均可进行证书链及目标主机名验证；默认关闭，需要使用 `verify=True` 或 `TlsConfig.verify_cert=True` 启用。
- 会话内 Cookie、连接池、TLS 1.2 会话缓存，以及本地 TLS/HTTP/2/SOCKS 集成测试。

实现范围和测试证据见 [本地协议测试说明](test/README.md)。这些测试不等于完整的协议安全审计。

## 已知限制与后续事项

1. **默认 TLS 设置**：默认为 TLS 1.2 的 RSA/AES-CBC 套件，并关闭证书验证。面向一般 HTTPS 服务调整默认值时，需要同时处理兼容性及升级说明；当前应显式启用证书验证并选择兼容的 TLS 配置。
2. **TLS 1.2 密码套件**：密钥计划仍固定使用 SHA-256；SHA-384 PRF 套件尚未由集成测试确认可用。
3. **TLS 1.3 扩展流程**：HelloRetryRequest、KeyUpdate、PSK 会话恢复和 0-RTT 尚不在当前集成测试范围内；接收 NewSessionTicket 不代表已实现 PSK 恢复。
4. **会话持久化**：Cookie 和 TLS 会话状态保存在内存中，尚无跨进程重启的持久化接口。

后续协议能力应按实际使用需求排序，并针对协商、认证和失败边界补充本地集成验证。
