# ja3requests 当前能力与后续改进

## 已实现

- HTTPS 的 TLS 1.2 和可配置的 TLS 1.3 请求路径；通过 ALPN 协商 HTTP/2。
- TLS 1.2 RSA 密钥交换使用服务器公钥加密预主密钥；测试覆盖了选定密码套件的 Finished 验证和失败路径。
- TLS 1.2 与 TLS 1.3 均可进行证书链及目标主机名验证；默认关闭，需要使用 `verify=True` 或 `TlsConfig.verify_cert=True` 启用。
- TLS 1.3 浏览器预设现提供 TLS 1.3 密码套件；Chrome 120 预设在本地 OpenSSL 服务上完成了已验证的 TLS 1.3 握手，以及带扩展主密钥的 TLS 1.2 回退握手。
- `TlsConfig.secure()` 显式启用证书验证及 TLS 1.3/TLS 1.2 ECDHE-GCM 配置；本地 RSA/ECDSA 证书的两个协议版本均通过互通测试。`TlsConfig.legacy()` 固定旧兼容参数。
- TLS 1.2 ECDHE-RSA/ECDHE-ECDSA AES-256-GCM/SHA-384 已通过本地 OpenSSL 互通，覆盖有无扩展主密钥、碎片读取和 Finished 篡改拒绝。
- 会话内 Cookie、连接池、TLS 1.2 会话缓存，以及本地 TLS/HTTP/2/SOCKS 集成测试。

实现范围和测试证据见 [本地协议测试说明](test/README.md)。这些测试不等于完整的协议安全审计。

## 已知限制与后续事项

1. **默认 TLS 设置**：`TlsConfig()` 仍默认为 TLS 1.2 的 RSA/AES-CBC 套件，并关闭证书验证；新调用方应显式采用 `TlsConfig.secure()`。旧服务需要的参数可通过 `TlsConfig.legacy()` 固定。
2. **默认值迁移**：先在当前版本提供显式安全配置和旧行为入口；只有经过更广的互通验证并给出自签名证书、旧服务和 JA3 指纹的迁移说明后，才应在破坏性版本中改变 `TlsConfig()` 默认值。
3. **TLS 1.2 密码套件**：SHA-384 PRF 的端到端验证限于 ECDHE-RSA/ECDHE-ECDSA AES-256-GCM；其他 SHA-384 CBC 或静态 RSA 套件尚未确认可用，安全配置不提供这些套件。
4. **TLS 1.3 扩展流程**：安全配置已直接提供 X25519 和 P-256 密钥份额，但其他组所需的 HelloRetryRequest、KeyUpdate、PSK 会话恢复和 0-RTT 尚不在当前集成测试范围内；接收 NewSessionTicket 不代表已实现 PSK 恢复。
5. **会话持久化**：Cookie 和 TLS 会话状态保存在内存中，尚无跨进程重启的持久化接口。
6. **HTTP/2 连接复用**：当前每次 HTTP/2 请求结束后关闭 TLS 连接，避免在缺少持久化 HTTP/2 协议状态时重复发送连接前言；多路复用池尚未接入 HTTPS 请求路径。

后续协议能力应按实际使用需求排序，并针对协商、认证和失败边界补充本地集成验证。
