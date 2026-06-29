import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { execFile, ChildProcess, spawn } from "node:child_process";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { readFileSync, readdirSync, existsSync } from "node:fs";

const execFileAsync = promisify(execFile);
const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..");

let mitmProcess: ChildProcess | null = null;
let mitmCaptureFile: string | null = null;

const ok = (data: unknown) => ({
  content: [{ type: "text" as const, text: typeof data === "string" ? data : JSON.stringify(data, null, 2) }],
});
const err = (e: unknown) => ({
  content: [{ type: "text" as const, text: JSON.stringify({ error: String((e as Error)?.message ?? e) }) }],
  isError: true as const,
});

async function runScript(script: string, args: string[], timeoutMs = 120_000): Promise<string> {
  const { stdout, stderr } = await execFileAsync("node", [join(PROJECT_ROOT, script), ...args], {
    cwd: PROJECT_ROOT,
    timeout: timeoutMs,
    maxBuffer: 10 * 1024 * 1024,
  });
  return (stdout + (stderr ? `\n[stderr]\n${stderr}` : "")).trim();
}

export function registerStaticTools(server: McpServer): void {
  server.registerTool(
    "mp_list_apps",
    {
      title: "List cached mini programs",
      description:
        "列出本机微信缓存的所有小程序 appid、版本号、包数量。无副作用，用来决定分析哪个 appid。",
      inputSchema: {},
    },
    async () => {
      try {
        return ok(await runScript("static/mp-analyze.mjs", ["--list"]));
      } catch (e) {
        return err(e);
      }
    },
  );

  server.registerTool(
    "mp_analyze",
    {
      title: "One-click static analysis",
      description:
        "一键静态分析：解密解包(主包+分包+插件) → 签名/加密定位 → API 抽取 → 复现代码生成 → 结构化报告。" +
        "输入 appid 或 '--active' 自动检测运行中的小程序。产出 report.json + REPORT.md + repro.node.mjs + repro.python.py。",
      inputSchema: {
        appid: z.string().describe("小程序 appid (wx开头16位hex)，或 '--active' 自动检测"),
      },
    },
    async ({ appid }: { appid: string }) => {
      try {
        const args = appid === "--active" ? ["--active"] : [appid];
        const output = await runScript("static/mp-analyze.mjs", args, 300_000);
        // 解析出实际 appid（--active 时从日志取），读 report.json 拼一个 AI 可直接据此决策的结构化摘要
        const resolved = appid === "--active"
          ? (output.match(/wx[a-f0-9]{16}/)?.[0] ?? appid)
          : appid;
        const reportPath = join(PROJECT_ROOT, "static", "out", resolved, "report.json");
        if (!existsSync(reportPath)) return ok(output);
        const r = JSON.parse(readFileSync(reportPath, "utf8"));
        const ch = r.crackHint;
        let nextStep: string;
        if (!r.crypto?.hasSigning && !r.crypto?.hasEncryption) {
          nextStep = "无签名：repro.node.mjs 已可直接用，填 token/参数即可，无需破解。";
        } else if (ch && ch.candidateKeys?.length) {
          nextStep = `有签名且抽到 ${ch.candidateKeys.length} 个候选密钥：拿一条真实请求样本(mp_capture_import 导入已有抓包 / mp_capture_* 现抓)，再 mp_sign_crack(capture_file=样本, report="${reportPath}")。`;
        } else if (r.crypto?.hasSigning) {
          nextStep = `有签名但未抽到明文密钥(疑 SDK 级签名，算法 ${(ch?.algorithms || []).join("/") || "?"})：走沙箱——mp_sandbox_modules → mp_sandbox_run 调用签名函数 → mp_sandbox_export 导出 signer.mjs。`;
        } else {
          nextStep = "检出加解密但疑无业务签名：人工核对 report.json 的 signingSignals，多为第三方 SDK 自用。";
        }
        const summary = {
          appid: r.appid,
          version: r.version,
          verdict: r.crypto?.verdict,
          hasSigning: r.crypto?.hasSigning,
          algorithms: (r.crypto?.algorithms || []).map((a: { algo: string }) => a.algo),
          signFunctions: (r.crypto?.signFunctions || []).slice(0, 5).map((f: { name: string; file: string; algo: string[]; score: number }) => ({ name: f.name, file: f.file, algo: f.algo, score: f.score })),
          apiCount: r.apiCount,
          crackHint: ch ? { candidateKeys: ch.candidateKeys.length, algorithms: ch.algorithms, signFieldGuesses: ch.signFieldGuesses, patterns: ch.patterns?.length ?? 0 } : null,
          outputDir: join(PROJECT_ROOT, "static", "out", resolved),
          reportPath,
          repro: { node: "repro.node.mjs", python: "repro.python.py" },
          nextStep,
          log: output.split("\n").slice(-12).join("\n"),
        };
        return ok(summary);
      } catch (e) {
        return err(e);
      }
    },
  );

  server.registerTool(
    "mp_analyze_all",
    {
      title: "Batch analyze all cached mini programs",
      description: "批量分析本机缓存的所有小程序。耗时较长，适合全面扫描。",
      inputSchema: {},
    },
    async () => {
      try {
        return ok(await runScript("static/mp-analyze.mjs", ["--all"], 600_000));
      } catch (e) {
        return err(e);
      }
    },
  );

  server.registerTool(
    "mp_decrypt",
    {
      title: "Decrypt and extract wxapkg",
      description:
        "解密并提取 wxapkg 包。可传 appid（自动找最新缓存）或 wxapkg 文件路径。输出解包后的文件列表。",
      inputSchema: {
        target: z.string().describe("appid 或 wxapkg 文件路径"),
      },
    },
    async ({ target }: { target: string }) => {
      try {
        return ok(await runScript("scripts/wxapkg-decrypt.mjs", [target]));
      } catch (e) {
        return err(e);
      }
    },
  );

  server.registerTool(
    "mp_sign_crack",
    {
      title: "Brute-force sign parameters",
      description:
        "签名参数穷举破解：给定抓包样本(JSONL) + 密钥，自动枚举参数子集 × 算法(HMAC/MD5/SHA/AES/DES)，找到产生该 sign 的精确公式并生成复现代码。" +
        "传 report 可直接吃 mp_analyze 的 report.json(自动载入候选密钥+算法+参数序，免手动 key/source)；也可传 source_dir 从源码提取密钥。",
      inputSchema: {
        capture_file: z.string().optional().describe("抓包 JSONL 文件路径"),
        report: z.string().optional().describe("mp_analyze 的 report.json 路径，自动载入候选密钥+算法+参数序(analyze→crack 桥)"),
        key: z.string().optional().describe("HMAC/AES 密钥 (逗号分隔多个)"),
        source_dir: z.string().optional().describe("解包源码目录，自动提取候选密钥"),
        url_filter: z.string().optional().describe("只破解 URL 包含此字符串的请求"),
        sign_field: z.string().optional().describe("签名字段名 (默认 sign)"),
        inline: z.string().optional().describe("直接传 URL-encoded 参数代替 capture_file"),
      },
    },
    async (params: Record<string, string | undefined>) => {
      try {
        const args: string[] = [];
        if (params.inline) {
          args.push("--inline", params.inline);
        } else if (params.capture_file) {
          args.push(params.capture_file);
        }
        if (params.report) args.push("--hint", params.report);
        if (params.key) args.push("--key", params.key);
        if (params.source_dir) args.push("--source", params.source_dir);
        if (params.url_filter) args.push("--url", params.url_filter);
        if (params.sign_field) args.push("--sign-field", params.sign_field);
        args.push("--patterns");
        return ok(await runScript("scripts/sign-crack.mjs", args));
      } catch (e) {
        return err(e);
      }
    },
  );

  // ─── mitmproxy capture tools ─────────────────────────────────────

  server.registerTool(
    "mp_capture_start",
    {
      title: "Start traffic capture",
      description:
        "启动 mitmdump 代理抓包。手机配置代理后，小程序请求自动记录为 sign-crack 兼容的 JSONL。" +
        "默认监听 8080 端口。可选 url_filter 只抓包含指定关键词的 URL。",
      inputSchema: {
        port: z.number().optional().describe("代理端口 (默认 8080)"),
        url_filter: z.string().optional().describe("只捕获 URL 包含此关键词的请求"),
      },
    },
    async ({ port, url_filter }: { port?: number; url_filter?: string }) => {
      if (mitmProcess && !mitmProcess.killed) {
        return err(new Error(`mitmdump already running (pid ${mitmProcess.pid}), call mp_capture_stop first`));
      }
      const addonScript = join(PROJECT_ROOT, "scripts", "mitm-capture.py");
      const captureDir = join(PROJECT_ROOT, "captures");
      const args = [
        "-s", addonScript,
        "--set", `capture_dir=${captureDir}`,
        "-p", String(port || 8080),
        "--ssl-insecure",
      ];
      if (url_filter) args.push("--set", `url_filter=${url_filter}`);

      try {
        mitmProcess = spawn("mitmdump", args, { stdio: ["ignore", "pipe", "pipe"] });
        let startupLog = "";
        const startupPromise = new Promise<string>((resolve) => {
          const timer = setTimeout(() => resolve(startupLog), 3000);
          mitmProcess!.stderr!.on("data", (d: Buffer) => {
            startupLog += d.toString();
            if (startupLog.includes("Proxy server listening") || startupLog.includes("mp-capture")) {
              clearTimeout(timer);
              resolve(startupLog);
            }
          });
          mitmProcess!.on("error", (e: Error) => { clearTimeout(timer); resolve(`error: ${e.message}`); });
          mitmProcess!.on("exit", (code: number | null) => {
            clearTimeout(timer);
            resolve(startupLog || `exited with code ${code}`);
            mitmProcess = null;
          });
        });

        const log = await startupPromise;
        const captureFiles = existsSync(captureDir) ? readdirSync(captureDir).filter(f => f.endsWith(".jsonl")).sort() : [];
        mitmCaptureFile = captureFiles.length ? join(captureDir, captureFiles[captureFiles.length - 1]!) : null;

        return ok({
          status: mitmProcess && !mitmProcess.killed ? "running" : "failed",
          pid: mitmProcess?.pid,
          port: port || 8080,
          captureFile: mitmCaptureFile,
          log: log.trim().split("\n").slice(-5),
          hint: `手机 WiFi 代理设为 <本机IP>:${port || 8080}，确保已安装 mitmproxy CA 证书`,
        });
      } catch (e) {
        return err(e);
      }
    },
  );

  server.registerTool(
    "mp_capture_stop",
    {
      title: "Stop traffic capture",
      description: "停止 mitmdump 抓包进程，返回捕获的文件路径和请求数。",
      inputSchema: {},
    },
    async () => {
      if (!mitmProcess || mitmProcess.killed) {
        mitmProcess = null;
        return ok({ status: "not_running", captureFile: mitmCaptureFile });
      }
      const pid = mitmProcess.pid;
      mitmProcess.kill("SIGTERM");
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => { mitmProcess?.kill("SIGKILL"); resolve(); }, 5000);
        mitmProcess!.on("exit", () => { clearTimeout(timer); resolve(); });
      });
      mitmProcess = null;

      let lineCount = 0;
      if (mitmCaptureFile && existsSync(mitmCaptureFile)) {
        lineCount = readFileSync(mitmCaptureFile, "utf8").trim().split("\n").filter(Boolean).length;
      }
      return ok({ status: "stopped", pid, captureFile: mitmCaptureFile, requestsCaptured: lineCount });
    },
  );

  server.registerTool(
    "mp_capture_list",
    {
      title: "List captured requests",
      description:
        "查看当前抓包文件内容。返回最近的请求概览(URL/method/sign字段)。" +
        "可指定 capture_file 路径，默认读取最新的抓包文件。",
      inputSchema: {
        capture_file: z.string().optional().describe("JSONL 文件路径 (默认最新)"),
        limit: z.number().optional().describe("最多返回条数 (默认 50)"),
        url_filter: z.string().optional().describe("只显示 URL 包含此关键词的请求"),
      },
    },
    async ({ capture_file, limit, url_filter }: { capture_file?: string; limit?: number; url_filter?: string }) => {
      let file = capture_file;
      if (!file) {
        const captureDir = join(PROJECT_ROOT, "captures");
        if (!existsSync(captureDir)) return ok({ requests: [], hint: "无抓包数据，先调用 mp_capture_start" });
        const files = readdirSync(captureDir).filter(f => f.endsWith(".jsonl")).sort();
        if (!files.length) return ok({ requests: [], hint: "无抓包数据" });
        file = join(captureDir, files[files.length - 1]!);
      }
      if (!existsSync(file)) return err(new Error(`file not found: ${file}`));

      const lines = readFileSync(file, "utf8").trim().split("\n").filter(Boolean);
      const max = limit || 50;
      const requests: Array<Record<string, unknown>> = [];
      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          if (url_filter && !entry.url?.includes(url_filter)) continue;
          const params: Record<string, string> = {};
          if (entry.req_body) {
            for (const pair of entry.req_body.split("&")) {
              const [k, ...v] = pair.split("=");
              if (k) params[k] = v.join("=");
            }
          }
          const signFields = Object.keys(params).filter(k =>
            /^(sign|signature|token|hmac|hash|digest|sig|x.s|a_bogus|msToken|_signature)/i.test(k),
          );
          requests.push({
            url: entry.url,
            method: entry.method,
            status: entry.status,
            paramCount: Object.keys(params).length,
            signFields: signFields.length ? signFields.map(k => `${k}=${params[k]?.slice(0, 32)}...`) : [],
            ts: entry.ts,
          });
          if (requests.length >= max) break;
        } catch { /* skip malformed lines */ }
      }
      return ok({ file, total: lines.length, shown: requests.length, requests });
    },
  );

  server.registerTool(
    "mp_capture_import",
    {
      title: "Import existing capture",
      description:
        "把已有抓包归一成 sign-crack 兼容的 JSONL —— 用户自己用任意工具抓的包可直接导入，无需再走 mp_capture_* 代理。" +
        "支持 HAR(Charles/Fiddler/DevTools)、cURL(DevTools 复制)、JSON 请求体、JSONL。" +
        "自动扁平化 JSON 体、折入 GET query 参数，并标出带 sign 字段的请求。",
      inputSchema: {
        input: z.string().optional().describe("抓包文件路径 (HAR/cURL文本/JSON/JSONL)"),
        content: z.string().optional().describe("直接传抓包内容文本 (代替 input 文件)"),
        format: z.string().optional().describe("auto|har|curl|json|jsonl (默认 auto 自动识别)"),
        api_url: z.string().optional().describe("当输入是纯 JSON 请求体时，指定接口 URL"),
        url_filter: z.string().optional().describe("只导入 URL 含此子串的请求"),
        out: z.string().optional().describe("输出 JSONL 路径 (默认 captures/imported-*.jsonl)"),
      },
    },
    async (params: { input?: string; content?: string; format?: string; api_url?: string; url_filter?: string; out?: string }) => {
      try {
        const args: string[] = [];
        if (params.input) args.push(params.input);
        if (params.format) args.push("--format", params.format);
        if (params.api_url) args.push("--api-url", params.api_url);
        if (params.url_filter) args.push("--url", params.url_filter);
        if (params.out) args.push("--out", params.out);
        // 直接传内容 → 经 stdin 喂给脚本；否则走文件路径
        if (params.content && !params.input) {
          const script = join(PROJECT_ROOT, "scripts/capture-import.mjs");
          const out = await new Promise<string>((resolve, reject) => {
            const p = spawn("node", [script, ...args], { cwd: PROJECT_ROOT });
            let so = "", se = "";
            p.stdout.on("data", (d: Buffer) => (so += d));
            p.stderr.on("data", (d: Buffer) => (se += d));
            p.on("close", () => resolve((so + (se ? `\n[stderr]\n${se}` : "")).trim()));
            p.on("error", reject);
            p.stdin.write(params.content!); p.stdin.end();
          });
          return ok(out);
        }
        return ok(await runScript("scripts/capture-import.mjs", args, 60_000));
      } catch (e) {
        return err(e);
      }
    },
  );

  // ─── sandbox tools ───────────────────────────────────────────────

  server.registerTool(
    "mp_sandbox_run",
    {
      title: "Run code in mini-program sandbox",
      description:
        "在离线沙箱中加载小程序 bundle (app-service.js)，执行任意 JS 代码。" +
        "用于调用 SDK 签名函数、分析加密逻辑、提取运行时数据。" +
        "代码中可用: ctx (沙箱上下文), requireMod(path), wpRequire(moduleId), sandbox (全局对象)。" +
        "需要先 mp_analyze 解包。",
      inputSchema: {
        appid: z.string().describe("小程序 appid"),
        code: z.string().describe("要执行的 JS 代码，可用 ctx/requireMod/wpRequire/sandbox"),
        bundle_path: z.string().optional().describe("自定义 app-service.js 路径 (默认自动查找)"),
        storage: z.string().optional().describe("预设 wx storage JSON (如 '{\"key\":\"value\"}')"),
      },
    },
    async ({ appid, code, bundle_path, storage }: { appid: string; code: string; bundle_path?: string; storage?: string }) => {
      try {
        const args = [appid, "--eval", code];
        if (bundle_path) args.push("--bundle", bundle_path);
        if (storage) args.push("--storage", storage);
        const output = await runScript("scripts/sandbox-run.mjs", args, 60_000);
        return ok(output);
      } catch (e) {
        return err(e);
      }
    },
  );

  server.registerTool(
    "mp_sandbox_modules",
    {
      title: "List sandbox modules",
      description:
        "列出小程序 bundle 中注册的所有模块路径。用于发现 SDK 签名模块位置。需要先 mp_analyze 解包。",
      inputSchema: {
        appid: z.string().describe("小程序 appid"),
      },
    },
    async ({ appid }: { appid: string }) => {
      try {
        return ok(await runScript("scripts/sandbox-run.mjs", [appid, "--list-modules"], 60_000));
      } catch (e) {
        return err(e);
      }
    },
  );

  server.registerTool(
    "mp_sandbox_export",
    {
      title: "Export standalone signer",
      description:
        "从沙箱导出独立 Node.js 签名脚本。追踪签名函数的依赖模块，提取最小子集，" +
        "生成不依赖 wx-sandbox / app-service.js 的自包含 .mjs 文件。" +
        "流程：加载 bundle → 运行 verify 验证签名能跑通 → 追踪依赖 → 生成独立脚本。" +
        "需要先 mp_analyze 解包 + mp_sandbox_run 确认签名函数路径。",
      inputSchema: {
        appid: z.string().describe("小程序 appid"),
        entry: z.string().describe("签名模块路径 (如 'npm/some-sdk/index.js')"),
        fn: z.string().optional().describe("要导出的函数名 (如 'sign')，不填则 export default 整个模块"),
        verify: z.string().optional().describe("验证代码 (如 \"requireMod('npm/sdk').sign({ts:1})\")，确保签名能跑通"),
        output: z.string().optional().describe("输出文件路径 (默认 static/out/<appid>/signer.mjs)"),
        storage: z.string().optional().describe("预设 wx storage JSON"),
      },
    },
    async (params: { appid: string; entry: string; fn?: string; verify?: string; output?: string; storage?: string }) => {
      try {
        const args = [params.appid, "--entry", params.entry];
        if (params.fn) args.push("--fn", params.fn);
        if (params.verify) args.push("--verify", params.verify);
        if (params.output) args.push("--output", params.output);
        if (params.storage) args.push("--storage", params.storage);
        return ok(await runScript("scripts/sandbox-export.mjs", args, 120_000));
      } catch (e) {
        return err(e);
      }
    },
  );
}
