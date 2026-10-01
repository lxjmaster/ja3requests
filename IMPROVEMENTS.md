# ja3requests 当前能力与后续改进

## 已实现

- HTTPS 的 TLS 1.2 和可配置的 TLS 1.3 请求路径；通过 ALPN 协商 HTTP/2。
- TLS 1.2 RSA 密钥交换使用服务器公钥加密预主密钥；测试覆盖了选定密码套件的 Finished 验证和失败路径。
- TLS 1.2 与 TLS 1.3 均可进行证书链及目标主机名验证；2.0 默认启用；`verify=False` 可按请求覆盖，`TlsConfig.legacy()` 显式保留旧验证策略。
- TLS 1.3 浏览器预设现提供 TLS 1.3 密码套件；Chrome 120 预设在本地 OpenSSL 服务上完成了已验证的 TLS 1.3 握手，以及带扩展主密钥的 TLS 1.2 回退握手。
- `TlsConfig.secure()` 显式启用证书验证及 TLS 1.3/TLS 1.2 ECDHE-GCM 配置；本地 RSA/ECDSA 证书的两个协议版本均通过互通测试。`TlsConfig.legacy()` 固定旧兼容参数。
- TLS 1.2 ECDHE-RSA/ECDHE-ECDSA AES-256-GCM/SHA-384 已通过本地 OpenSSL 互通，覆盖有无扩展主密钥、碎片读取和 Finished 篡改拒绝。
- TLS 1.3 KeyUpdate 支持服务端或客户端发起及双向密钥轮换；本地 OpenSSL 互通覆盖两种发起方向。
- TLS 1.3 会话票据可用于内存中的 PSK-DHE 恢复；本地 OpenSSL 验证了三种套件、HelloRetryRequest 和票据被拒后的完整握手回退。
- TLS 1.3 支持主握手中的 RSA/ECDSA 客户端证书认证；本地 OpenSSL 验证了空证书、碎片读取及错误私钥拒绝。配置客户端证书时不使用 PSK 票据恢复。
- TLS 1.3 握手后客户端认证可通过 `PostHandshakeAuthExtension()` 显式启用；本地 OpenSSL 验证了 RSA/ECDSA、空证书、碎片读取及错误私钥拒绝。未启用时 ClientHello 指纹不变。
- HTTP/2 请求（包括带请求体的请求）可在同一 TLS 连接上并发多路复用，保留 HPACK 状态与递增流 ID；已取消流的响应头仍会解码以更新动态表。请求 DATA 遵守发送侧帧大小及流控窗口，响应 DATA 的填充不进入正文但计入接收流控。客户端默认通过 SETTINGS 禁用未实现的服务端推送，收到 PUSH_PROMISE 时使连接失败。本地 OpenSSL 覆盖 TLS 1.2/1.3、分段读取、流控窗口补充、交错响应、GOAWAY 及流重置后的连接回收。
- TLS 1.2 支持带扩展主密钥的 Session ID 简化握手；本地 OpenSSL 验证了 RSA/AES-CBC、ECDHE/AES-GCM、TLS 1.3 配置回退、拒绝旧 ID 和篡改 Finished 的失败路径。
- TLS 1.2 支持内存票据恢复；本地 OpenSSL 验证了有效票据恢复、拒绝票据后的完整握手回退及篡改 Finished 的失败路径。
- 会话内 Cookie、连接池、TLS 1.2 客户端证书签名，以及本地 TLS/HTTP/2/SOCKS 集成测试。
- 显式启用的 Cookie JSON 文件持久化：支持跨进程保存/加载，保留域名、路径、Secure、有效期和扩展属性；默认不保存或恢复会话 Cookie。接口及限制见 [Cookie 文件持久化指南](docs/cookie_persistence.md)。

实现范围和测试证据见 [本地协议测试说明](test/README.md)。这些测试不等于完整的协议安全审计。

## 已知限制与后续事项

1. **默认 TLS 设置**：2.0 的 `TlsConfig()` 默认等同于 `TlsConfig.secure()`：验证证书，优先 TLS 1.3 并允许 TLS 1.2 ECDHE/GCM 回退。旧 RSA/AES-CBC 服务需要显式使用 `TlsConfig.legacy()`。
2. **默认值迁移**：2.0 是默认值迁移的破坏性候选版本；证书信任、旧服务和 JA3 指纹的兼容性影响见迁移指南和版本说明。包发布是独立操作。
3. **TLS 1.2 密码套件**：SHA-384 PRF 的端到端验证限于 ECDHE-RSA/ECDHE-ECDSA AES-256-GCM；其他 SHA-384 CBC 或静态 RSA 套件尚未确认可用，安全配置不提供这些套件。
4. **TLS 1.3 扩展流程**：X25519 和 P-256 可通过 HelloRetryRequest 协商；其他组和 0-RTT 尚未实现。PSK 会话状态只保存在当前进程内。
5. **TLS 会话持久化**：TLS 会话状态仍只保存在内存中，尚无跨进程重启的持久化接口。Cookie 已提供显式文件保存/加载接口，不会持久化 TLS 密钥、连接池或 Session 对象。
6. **HTTP/2 扩展能力**：当前 HTTPS 请求路径支持并发流，可接收并忽略旧式优先级信号，但不按优先级调度。客户端不消费服务端推送，默认禁用推送，显式开启推送的 SETTINGS 配置会被拒绝。
7. **会话恢复与客户端认证**：无扩展主密钥或带客户端证书的 TLS 1.2 会话不提供 Session ID 恢复；配置客户端证书的 TLS 1.3 会话不使用 PSK 票据恢复。TLS 1.3 握手后客户端认证需显式声明扩展。

后续协议能力应按实际使用需求排序，并针对协商、认证和失败边界补充本地集成验证。

分阶段任务、依赖和验收条件见[后续开发计划](issues/next_development_plan.md)。T01–T04 的交付基线、安全配置互通证据、迁移指南和 Cookie 文件持久化已完成。T05 的 2.0.0 安全默认值迁移及本地验收已完成，远程交付检查记录在迁移 PR 中；下一步需选择 T06 的具体协议组和对端。
