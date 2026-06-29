#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerStaticTools } from "./staticTools.js";
import { log } from "./logging.js";

const INSTRUCTIONS = `wx-mp-mcp —— 微信小程序逆向分析(零侵入：只读磁盘加密包 + 走代理抓包 + Node 沙箱跑副本，绝不接触微信进程内存)。
目标：把小程序接口的 sign/加密参数还原成本地 Node.js 能独立跑的脚本。

典型流程与决策树（按此自主推进）：
1. mp_list_apps → 选定目标 appid。
2. mp_analyze <appid> → 解包 + 定位签名 + 抽 API + 生成复现代码。读返回的 verdict 决定下一步：
   • 「无签名」→ 已生成 repro.node.mjs，可直接用，结束。
   • 「有签名」且 crackHint.candidateKeys 非空 → 走【穷举破解】(第 3 步)。
   • 「有签名」但 candidateKeys 为空（SDK级签名，如美团 mtgsig/滴滴 wsgsig）→ 走【沙箱复现】(第 4 步)。
3. 穷举破解：拿一条真实请求样本 → mp_sign_crack(capture_file=样本, report=该 appid 的 report.json)。
   样本来源二选一：① 已有抓包(HAR/cURL/JSON)→ mp_capture_import；② 没有 → mp_capture_start→(操作小程序)→mp_capture_list→mp_capture_stop。
4. 沙箱复现：mp_sandbox_modules 找签名模块 → mp_sandbox_run 调用验证 → mp_sandbox_export 导出独立 signer.mjs。
5. 产物都在 static/out/<appid>/：report.json(结构化，含 crackHint) / REPORT.md / repro.node.mjs / repro.python.py / signer.mjs。

要点：mp_analyze 返回里带 reportPath 与 nextStep 建议，按它走即可；sandbox/sign_crack 需先 mp_analyze 解包。`;

async function main(): Promise<void> {
  const server = new McpServer(
    { name: "wx-mp-mcp", version: "0.1.2" },
    { instructions: INSTRUCTIONS },
  );

  // 12 static tools: capture (mitmproxy + import) + unpack + static analysis + offline sandbox.
  // Zero dependencies beyond Node.js; never touches the WeChat process.
  registerStaticTools(server);

  process.on("SIGINT", () => process.exit(0));
  process.on("SIGTERM", () => process.exit(0));

  const transport = new StdioServerTransport();
  await server.connect(transport);

  log("wx-mp-mcp ready — 12 tools (capture · unpack · static analysis · offline sandbox), listening on stdio");
}

main().catch((e) => {
  log("fatal:", e);
  process.exit(1);
});
