## Session
1. 提供各类请求方法， get， post， head，put等
2. 统一请求入口，创建Request
3. ...

# Request
1. 校验各类参数，如request method是否支持，url是否合法，协议是否支持等
2. 传入参数不做修改只做校验
3. 根据传入参数判断创建HttpRequest还是HttpsRequest

## HttpRequest/HttpsRequest
1. 进一步解析部分参数
2. 修复上一步传进来的不规范参数
3. 补充缺失的必要参数
4. 收集处理后的参数，并构建Context

## Context(HttpContext/HttpsContext)
1. context处理参数，用于最终的发起请求

## Socket(HttpSocket/HttpsSocket/ProxySocket/...)
后续拓展 websocket等
1. 根据context创建不同的socket
2. ProxySocket主要根据proxy信息，创建socket连接代理服务器，提交context给代理服务器，不用多做处理
3. HttpSocket根据HTTP相关协议，通过context创建socket向目标服务器发起请求
4. HttpsSocket相对复杂，根据context创建socket，构建tls发起tls握手，这过程包含协议交换，密钥交换，证书交换等。然后再发送资源请求
5. WebSocket...

## Response
1. 根据socket请求后的结果，解析相对应的内容
