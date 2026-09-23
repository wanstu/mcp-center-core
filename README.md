# MCP Center Core

从 AI Dev Manager 的 MCP 能力抽出的纯 Go 核心库。

当前提供：

- MCP 定义 CRUD 与持久化
- Streamable HTTP / stdio
- 环境变量引用解析（支持 `${NAME}` / `${NAME:-fallback}`）
- Secret-backed HTTP Header
- 健康探测与 `tools/list`
- `tools/call`
- 与 UI、账号、OAuth 授权服务器解耦

目标是让 MCP Center、ADM 以及其他 Go 应用共享同一套 MCP 控制能力。
