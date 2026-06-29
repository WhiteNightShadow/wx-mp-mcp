<div align="center">

<img src="docs/logo.svg" width="84" alt="wx-mp-mcp logo">

# wx-mp-mcp

**微信小程序逆向 MCP**

**在线实时解包 · AI 静态分析还原** —— 把小程序接口的签名 / 加密参数，还原成一个**本地 Node.js 就能直接跑**的脚本

<br>

![Core](https://img.shields.io/badge/实时解包-AI静态还原-07C160?style=flat-square)
![MCP](https://img.shields.io/badge/MCP-Server-000000?style=flat-square)
![Node](https://img.shields.io/badge/Node.js-≥18-339933?style=flat-square&logo=node.js&logoColor=white)
![Platform](https://img.shields.io/badge/macOS_·_Windows-555?style=flat-square)
![NonInvasive](https://img.shields.io/badge/不碰微信进程-2EA043?style=flat-square)

</div>

> 一个 MCP（Model Context Protocol）Server，装进你的 AI 编码工具（Claude Code / Cursor / Codex）。
>
> **🎯 核心能力 = 在线实时解包 + AI 静态分析还原**：对本机微信缓存里的**任意小程序**做**实时解密解包**，再让 **AI 静态读懂**其接口的签名 / 加密逻辑，**还原成本地能独立运行的脚本** —— 全程零侵入、不碰微信进程。（抓包 / 沙箱只是签名被运行时加密、静态读不出时的辅助手段。）

---

<h2><img src="docs/sec-features.svg" height="26" align="middle">&nbsp;三个核心能力</h2>

<table>
<tr>
<td align="center" width="33%" valign="top">

<img src="docs/icon-unpack.svg" width="60" alt="">

**实时解包**

`Mac + Windows`

直接读磁盘上的加密包（`.wxapkg`）离线解密成可读 js 源码，主包 / 分包 / 插件全解。微信开不开都行。

</td>
<td align="center" width="33%" valign="top">

<img src="docs/icon-capture.svg" width="60" alt="">

**数据抓包**

`mitmproxy 拦截`

HTTPS 代理拦下小程序真实请求，自动存成结构化样本——每条带 url、参数、`sign` 签名字段。

</td>
<td align="center" width="33%" valign="top">

<img src="docs/icon-analyze.svg" width="60" alt="">

**AI 离线分析**

`还原本地 Node 黑盒`

AI 读 js 定位签名算法 → 穷举反推 / 沙箱实跑复现 → 导出脱离微信的独立签名脚本。

</td>
</tr>
</table>

> 🛡️ **不碰微信进程**：全程只做「读磁盘加密包 · 走代理被动抓流量 · Node 跑解包出的代码副本」三件事，不 attach 微信、不改内存、不开调试端口——不会让微信环境异常或触发风控。（传统 Frida / WMPFDebugger 要注入微信进程改内存，有封号风险，本工具刻意避开。）

---

<h2><img src="docs/sec-flow.svg" height="26" align="middle">&nbsp;工作流</h2>

<table>
<tr>
<td align="center" width="120"><img src="docs/icon-unpack.svg" width="50"><br><b>解包分析</b><br><sub><code>mp_analyze</code></sub></td>
<td align="center"><b>→</b></td>
<td align="center" width="120"><img src="docs/icon-capture.svg" width="50"><br><b>抓真实样本</b><br><sub><code>mp_capture_*</code></sub></td>
<td align="center"><b>→</b></td>
<td align="center" width="120"><img src="docs/wf-crack.svg" width="50"><br><b>破解 / 沙箱</b><br><sub><code>mp_sign_crack</code></sub></td>
<td align="center"><b>→</b></td>
<td align="center" width="120"><img src="docs/icon-export.svg" width="50"><br><b>导出</b><br><sub><code>mp_sandbox_export</code></sub></td>
<td align="center"><b>→</b></td>
<td align="center" width="120"><img src="docs/wf-result.svg" width="50"><br><b>本地出 sign</b><br><sub><code>node signer.mjs</code></sub></td>
</tr>
</table>

多数无混淆小程序，`mp_analyze` 一步就能定位签名并生成复现代码（**走得出 → 直接导出**）；只有签名被运行时加密 / JSVMP 混淆、静态读不出时，才走 **抓包 → 破解 / 沙箱** 那条支线。

---

<h2><img src="docs/sec-start.svg" height="26" align="middle">&nbsp;快速接入</h2>

### 1. 安装

**方式一（推荐）** —— 直接对你的 AI 编码工具说：

```
帮我安装下这个 mcp 工具：wx-mp-mcp
项目地址：https://github.com/WhiteNightShadow/wx-mp-mcp
```

AI 会自动克隆、装依赖、构建、写好 MCP 配置。

**方式二** —— 手动：

```bash
git clone https://github.com/WhiteNightShadow/wx-mp-mcp.git
cd wx-mp-mcp && npm install && npm run build
```

### 2. 配置到客户端

<details>
<summary><b>Cursor（.cursor/mcp.json）</b></summary>

```json
{
  "mcpServers": {
    "wx-mp-mcp": {
      "command": "node",
      "args": ["/绝对路径/wx-mp-mcp/dist/index.js"]
    }
  }
}
```

</details>

<details>
<summary><b>Claude Code</b></summary>

```bash
claude mcp add wx-mp-mcp -- node /绝对路径/wx-mp-mcp/dist/index.js
```

</details>

> **抓包额外准备**：本机装 `mitmproxy`（`pip install mitmproxy` 或 `brew install mitmproxy`），手机 WiFi 代理指向「本机 IP : 8080」并安装其 CA 证书。其余工具零外部依赖、开箱即用。

### 3. 上手示例

把目标告诉 AI，它会自动走上面的工作流：

> 分析小程序 `wxXXXXXXXXXXXXXXXX` 的接口 `POST https://api.xxx.com/order/create`，定位其 `sign` 签名算法，导出一个本地可独立运行的 Node 签名脚本。

完成后你本地：

```bash
node signer.mjs '{"ts":"1719000000","orderId":"123"}'
# → 输出 sign，脱离微信直接复现接口请求
```

---

<h2><img src="docs/sec-tools.svg" height="26" align="middle">&nbsp;工具清单（12）</h2>

| 工具 | 作用 |
|------|------|
| <img src="docs/icon-unpack.svg" height="18" align="middle"> **解包分析** | |
| `mp_list_apps` | 列出本机微信缓存的所有小程序（appid / 版本 / 包数量） |
| `mp_decrypt` | 解密提取单个 `.wxapkg`（传 appid 自动找最新，或传文件路径） |
| `mp_analyze` | **一键分析**：解密解包(主包+分包+插件) → 签名/加密定位 → API 抽取 → 复现代码生成 → 报告（含 `crackHint`：候选密钥+算法+参数序） |
| `mp_analyze_all` | 批量分析本机全部缓存小程序 |
| <img src="docs/icon-capture.svg" height="18" align="middle"> **抓包** | |
| `mp_capture_start` | 启动 mitmproxy 代理抓包，请求自动存成结构化 JSONL（默认 :8080，可按 URL 过滤） |
| `mp_capture_list` | 查看抓到的请求，自动标出 `sign` / `token` 等签名字段 |
| `mp_capture_stop` | 停止抓包，返回文件路径与请求数 |
| `mp_capture_import` | **导入已有抓包** → 归一成 JSONL（HAR / cURL / JSON 体 / JSONL，自己抓的包直接用，免走代理） |
| <img src="docs/wf-crack.svg" height="18" align="middle"> **签名破解** | |
| `mp_sign_crack` | 签名穷举：抓包样本 → 枚举参数子集 × 算法(HMAC/MD5/SHA/AES/DES/3DES) → 反推精确公式并生成复现代码（传 `report` 直接吃 `mp_analyze` 的候选密钥+算法，免手动搬运） |
| <img src="docs/icon-analyze.svg" height="18" align="middle"> **离线沙箱** | |
| `mp_sandbox_modules` | 列出 bundle 里的所有模块，定位 SDK 签名模块位置 |
| `mp_sandbox_run` | 在离线 Node 沙箱加载 `app-service.js`，执行任意 js（直调签名函数验证） |
| `mp_sandbox_export` | **导出独立签名脚本**：追踪依赖、提取最小模块子集，生成不依赖 sandbox / bundle 的自包含 `.mjs` |

**分析产物**（落在 `static/out/<appid>/`）：可读源码树 `app/`、报告 `report.json` + `REPORT.md`、复现代码 `repro.node.mjs` + `repro.python.py`、独立签名脚本 `signer.mjs`。

---

<h2><img src="docs/sec-feedback.svg" height="26" align="middle">&nbsp;问题反馈 / 联系</h2>

使用中遇到问题、想反馈 bug、或交流逆向思路，欢迎加微信：

> **微信号：`han8888v8888`**（加好友请备注「wx-mp-mcp」）

---

<h2><img src="docs/sec-changelog.svg" height="26" align="middle">&nbsp;迭代记录</h2>

**v0.1.2** — 沙箱通用加固(实战打磨)
- **realm 自洽**：沙箱不再注入外层内建，`[].push === Array.prototype.push`，JSVMP/字节码解释器不再崩。
- **webpack 惰性取模块**：覆盖全局 jsonp 与内嵌 `{id:fn}` 两种形态，只实例化目标模块子树、不引导 app。
- **多 bundle 协同**：分包签名 SDK 依赖主包 runtime 时，`bundle_paths` 拼接单次载入。
- **JSVMP 友好**：`runInContext(code, ms)` 带超时执行(同步死循环可中断)、调用后清退心跳定时器；补齐 `wx.getRandomValues`/`getLogManager`、`performance`/`atob`/`btoa`、可配 UA。
- **网关签名检测**：识别 `hmac-auth` / `x-hmac-digest` / `mtgsig` / `wsgsig` / `__NS_sig` 等签名协议，消除「重度签名却报无签名」假阴性。
- **解包↔沙箱路径统一** + 报错清噪(不再回吐整包源码/命令行)。

**v0.1.1**
- 新增 `mp_capture_import`：已有抓包（HAR / cURL / JSON 体 / JSONL）一键归一，自己抓的包直接喂破解，免走代理。
- **analyze→crack 自动桥**：`mp_analyze` 报告多吐 `crackHint`（候选密钥 + 算法 + 参数序），`mp_sign_crack` 传 `report` 直接消费，少一次人工搬运。

**v0.1.0**
- 11 个工具打通完整链路：**实时解包 → mitmproxy 抓包 → AI 离线分析 → 导出本地 Node 黑盒脚本**，经 MCP 暴露给任意 AI Agent。
- **Mac + Windows** 缓存目录自动探测（`WXAPKG_ROOT` 可手动指定）。
- **不碰微信进程**：磁盘加密包离线解密（V1MMWX）+ 被动抓包 + Node vm 沙箱，无内存改写、无进程注入。
- **签名多信号判定**：拦截器 / 安全 SDK / 签名头 / 响应解密联合判定，避免「误报无签名」。

---

> ⚠️ 仅用于对**自有 / 已授权**小程序的安全分析与接口对接。不得用于未授权访问、绕过他人系统安全机制或违反服务条款的行为。
