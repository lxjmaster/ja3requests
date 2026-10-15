# ja3requests 当前能力与后续改进

当前版本为 2.5.0：保留自行实现的 TLS 握手、密钥派生和加密记录传输，
提供同步及原生异步客户端、流式上传/下载和可配置的 HTTP/2。
版本见 [PyPI 2.5.0](https://pypi.org/project/ja3requests/2.5.0/)
与 [GitHub v2.5.0](https://github.com/lxjmaster/ja3requests/releases/tag/v2.5.0)。
未发布改动单独记录在 [CHANGELOG](CHANGELOG.md) 的 Unreleased 中。

## 已实现

- HTTPS 的 TLS 1.2 和可配置的 TLS 1.3 请求路径；通过 ALPN 协商 HTTP/2。
- TLS 1.2 RSA 密钥交换使用服务器公钥加密预主密钥；测试覆盖了选定密码套件的 Finished 验证和失败路径。
- TLS 1.2 与 TLS 1.3 均可进行证书链及目标主机名验证；2.0 默认启用；`verify=False` 可按请求覆盖，`TlsConfig.legacy()` 显式保留旧验证策略。
- TLS 1.3 浏览器预设现提供 TLS 1.3 密码套件；Chrome 120 预设在本地 OpenSSL 服务上完成了已验证的 TLS 1.3 握手，以及带扩展主密钥的 TLS 1.2 回退握手。
- TLS 1.3 P-384 可通过配置显式启用，独立 OpenSSL 对端覆盖完整握手、HelloRetryRequest 和碎片读取；安全配置默认组仍为 X25519/P-256，历史预设的初始密钥份额未扩大。
- TLS 线级控制支持显式 Session ID、扩展精确排序、发送前配置校验和实际 ClientHello/JA3 检查。Chrome 154 预设依据保留的真实抓包实现受支持子集，需显式选择；其 JA3 与原浏览器不同，不宣称完整模拟。接口及差异见[线级控制说明](docs/tls_wire_control.md)。
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
- 同步及异步流式上传、文件和 multipart 上传；原生异步 Cookie 文件保存/加载。上传源的所有权、重放和取消规则见[上传指南](docs/streaming.md#streaming-request-bodies)及[异步指南](docs/async.md)。
- 缓冲的异步预备请求：`AsyncSession.prepare_request()`、`AsyncPreparedRequest.with_headers()` 和 `send()` 支持准备、检查、签名及独立重发；流式预备请求仍未实现。
- HTTP/2 可配置有序 SETTINGS、初始连接窗口、伪头顺序、独立 PRIORITY、逐请求 HEADERS 优先级、Huffman 和字面量索引排除策略；策略参与连接池隔离。接口及边界见[指纹指南](docs/fingerprints.md)。
- 同步 307/308 已保留方法与正文，支持可重放来源，并在不可重放时明确失败；CONNECT/SOCKS 的逐目标 SNI、握手超时、`h1=True` 的 ALPN 和直接 `send()` 重定向策略已修复。

实现范围和测试证据见 [本地协议测试说明](test/README.md)。这些测试不等于完整的协议安全审计。

2.5.0 新增：显式 Chrome 155/macOS 支持子集及其 H2 默认值；同步
301/302 只将 POST 转成无正文 GET，303 只将非 HEAD 转成无正文 GET。
其余方法保留正文并遵循既有重放规则，与异步方法策略对齐。完整浏览器身份、
额外 GREASE 向量、Session 默认 headers/params 不在本轮范围内。
对应版本的安装包验收与 CI 才是发布证据；推进计划中的开发候选报告保留为历史记录。

## 已知限制与后续事项

1. **默认 TLS 设置**：2.0 的 `TlsConfig()` 默认等同于 `TlsConfig.secure()`：验证证书，优先 TLS 1.3 并允许 TLS 1.2 ECDHE/GCM 回退。旧 RSA/AES-CBC 服务需要显式使用 `TlsConfig.legacy()`。
2. **默认值迁移**：2.0.0 已发布默认值的破坏性变更，2.0.1 延续该策略；证书信任、旧服务和 JA3 指纹的兼容性影响见迁移指南和版本说明。
3. **TLS 1.2 密码套件**：SHA-384 PRF 的端到端验证限于 ECDHE-RSA/ECDHE-ECDSA AES-256-GCM；其他 SHA-384 CBC 或静态 RSA 套件尚未确认可用，安全配置不提供这些套件。
4. **TLS 1.3 扩展流程**：X25519、P-256 和显式配置的 P-384 支持 HelloRetryRequest；其他组和 0-RTT 尚未实现。PSK 会话状态只保存在当前进程内。Chrome 154 子集不提供加密客户端问候（ECH）、后量子组或完整浏览器指纹，未指定版本的 Chrome 预设仍为 124。
5. **TLS 会话持久化**：TLS 会话状态仍只保存在内存中，尚无跨进程重启的持久化接口。Cookie 已提供显式文件保存/加载接口，不会持久化 TLS 密钥、连接池或 Session 对象。
6. **HTTP/2 扩展能力**：当前 HTTPS 请求路径支持并发流，可接收并忽略旧式优先级信号，但不按优先级调度。客户端不消费服务端推送，默认禁用推送，显式开启推送的 SETTINGS 配置会被拒绝。
7. **会话恢复与客户端认证**：无扩展主密钥或带客户端证书的 TLS 1.2 会话不提供 Session ID 恢复；配置客户端证书的 TLS 1.3 会话不使用 PSK 票据恢复。TLS 1.3 握手后客户端认证需显式声明扩展。
8. **响应流式读取**：2.1.0 实现 HTTP/1.1、TLS1.2/1.3 和 HTTP/2 的增量读取与压缩解码。迭代不缓存整包，提前关闭 HTTP/1 响应会丢弃连接，HTTP/2 则仅取消相应流。内存还包括 TLS 记录、H2 窗口及解码状态，不等于 `chunk_size`；完整契约见[流式指南](docs/streaming.md)。
9. **客户端一致性**：异步文件上传、Cookie 文件接口和缓冲预备请求已实现；2.5.0 对齐了同步/异步的重定向方法与正文策略。异步模块级便捷函数、流式预备请求和显式 Session headers/params 默认值仍未实现。两者的 `timeout=None`、代理解析和空 headers 行为也有差异，详见[请求策略](docs/request_policy.md)、[代理指南](docs/proxies.md)及[默认值设计](issues/session_defaults_design.md)。
10. **文档与性能**：提供公共类型支持、可本地构建的文档站及同步/异步性能套件。历史性能数据描述其指定源码和环境，不代表所有运行环境；公共文档站部署仍是独立事项。

后续协议能力应按实际使用需求排序，并针对协商、认证和失败边界补充本地集成验证。

当前任务、依赖和验收条件统一见[2.4.0 后推进计划](issues/post_2_4_0_plan.md)。
其条件清单保留尚未实现的协议、客户端及交付能力；旧计划和历史测试结果保留为证据，
不据此重复开发或重复发布。

## 历史需求的本地核销建议

以下对照已发布能力，不代表修改了远端 Issue 状态。

| Issue | 已交付证据与剩余边界 |
| --- | --- |
| #36 公共类型 | 公共注解、`py.typed` 和安装后消费者类型检查已交付；内部模块的完整严格类型检查仍是独立候选。 |
| #37 异步 API | 原生异步、连接池、hooks、流式读写、文件/Cookie 文件及缓冲预备请求已交付；模块级便捷函数和流式预备请求仍未实现。 |
| #40 性能 | 基准工具和指定源码/环境的历史报告已交付；性能 CI 和新版基准需单独选择，不能把历史数字当成当前运行结果。 |
| #41 流式读取 | 增量读取、解码、背压和保留的 100 MiB 测试已交付；原始 1 GiB / 内存不超过 `chunk_size` 指标尚未验证，不能直接据此关闭。建议先约定进程基线、协议/解码缓冲和增量内存的测量口径，再对固定数据规模和配置验收。 |
| #42 文档 | 本地 MkDocs、API/用户指南、可运行示例和严格文档 CI 已交付；公开文档托管仍需指定目标后实施。 |
