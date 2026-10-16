# MCP Center Core

> License: **BSD 3-Clause** (SPDX: `BSD-3-Clause`). Copyright (c) 2026 wanstu.
> See [LICENSE](LICENSE). Third-party Go dependencies retain their own licenses.

从 AI Dev Manager 的 MCP 能力抽出的纯 Go 核心库。

当前提供：

- MCP 定义 CRUD 与持久化
- Streamable HTTP / 旧版 SSE / stdio
- 独立的 MCP 出站会话（统一隔离协议 Context，支持跨请求长连接和显式关闭）
- 环境变量引用解析（支持 `${NAME}` / `${NAME:-fallback}`）
- Secret-backed HTTP Header
- 健康探测与 `tools/list`
- `tools/call`
- 与 UI、账号、OAuth 授权服务器解耦

目标是让 MCP Center、ADM 以及其他 Go 应用共享同一套 MCP 控制能力。
