#!/usr/bin/env node
/**
 * sandbox-run — load a mini-program bundle into wx-sandbox and run code.
 *
 * Usage:
 *   node scripts/sandbox-run.mjs <appid> --eval "ctx.requireMod('path/to/sdk').sign({ts:1})"
 *   node scripts/sandbox-run.mjs <appid> --list-modules
 *   node scripts/sandbox-run.mjs <appid> --bundle /path/to/app-service.js --eval "..."
 *
 * The sandbox loads the unpacked app-service.js (from static/unpacked/<appid>/),
 * exposes `ctx` (the sandbox context) to --eval code, and prints the result.
 */
import { loadBundle } from "./lib/wx-sandbox.mjs";
import { existsSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..");

// 兜底：单个无关模块(telemetry/Vue 引导/被 stub 的网络 API)抛【异步未捕获异常】不应 abort 整个沙箱，
// 也避免崩溃堆栈把整包源码刷出来。
process.on("uncaughtException", (e) => { console.error("[sandbox uncaught] " + String(e?.message || e).slice(0, 300)); });
process.on("unhandledRejection", (e) => { console.error("[sandbox unhandledRejection] " + String(e?.message || e).slice(0, 300)); });

function findBundle(appid) {
  const names = ["app-service.js", "appservice.app.js"];
  // mp_analyze 解包产物：static/out/<appid>/app/（与解包端路径约定一致，免手动建软链）
  const outApp = join(PROJECT_ROOT, "static", "out", appid, "app");
  for (const n of names) { const c = join(outApp, n); if (existsSync(c)) return c; }
  // 回退：static/unpacked/<appid>/[<ver>/]
  const unpackDir = join(PROJECT_ROOT, "static", "unpacked", appid);
  if (existsSync(unpackDir)) {
    const versions = readdirSync(unpackDir).filter(d => /^\d+$/.test(d)).sort((a, b) => +b - +a);
    for (const ver of versions) for (const n of names) { const c = join(unpackDir, ver, n); if (existsSync(c)) return c; }
    for (const n of names) { const c = join(unpackDir, n); if (existsSync(c)) return c; }
  }
  return null;
}

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { appid: null, bundlePaths: [], evalCode: null, listModules: false, storage: {}, ua: null, device: null };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--eval" && args[i + 1]) { opts.evalCode = args[++i]; }
    else if (args[i] === "--bundle" && args[i + 1]) { opts.bundlePaths.push(args[++i]); }   // 可重复:多 bundle 协同
    else if (args[i] === "--bundles" && args[i + 1]) { opts.bundlePaths.push(...args[++i].split(",").map((s) => s.trim()).filter(Boolean)); }
    else if (args[i] === "--ua" && args[i + 1]) { opts.ua = args[++i]; }
    else if (args[i] === "--device" && args[i + 1]) { opts.device = JSON.parse(args[++i]); }  // 真机种子:覆盖 system/device 字段
    else if (args[i] === "--list-modules") { opts.listModules = true; }
    else if (args[i] === "--storage" && args[i + 1]) { opts.storage = JSON.parse(args[++i]); }
    else if (!args[i].startsWith("-")) { opts.appid = args[i]; }
  }
  return opts;
}

async function main() {
  const opts = parseArgs();
  if (!opts.appid) {
    console.error("Usage: node scripts/sandbox-run.mjs <appid> [--eval code] [--list-modules] [--bundle path]");
    process.exit(1);
  }

  // 多 --bundle → 协同加载;否则按 appid 自动定位主包
  let bundlePaths = opts.bundlePaths.length ? opts.bundlePaths : [findBundle(opts.appid)];
  if (bundlePaths.some((p) => !p || !existsSync(p))) {
    console.error(`❌ app-service.js not found for ${opts.appid}`);
    console.error(`   先跑 'mp_analyze ${opts.appid}' 解包(产物在 static/out/${opts.appid}/app/);分包签名模块可用 --bundle 主包 --bundle 分包 协同加载。`);
    process.exit(1);
  }

  console.error(`Loading bundle: ${bundlePaths.join(" + ")}`);
  const ctx = loadBundle({ appid: opts.appid, bundlePaths, storage: opts.storage, timeout: 30000, ua: opts.ua, device: opts.device });
  console.error(`Loaded ${Object.keys(ctx.modules).length} modules, ${ctx.logs.length} log lines`);

  if (opts.listModules) {
    const mods = Object.keys(ctx.modules).sort();
    console.log(JSON.stringify({ count: mods.length, modules: mods }, null, 2));
    return;
  }

  if (!opts.evalCode) {
    console.log(JSON.stringify({
      appid: opts.appid,
      moduleCount: Object.keys(ctx.modules).length,
      sampleModules: Object.keys(ctx.modules).slice(0, 30),
      logs: ctx.logs.slice(0, 20),
      missing: [...ctx.state.missing].slice(0, 20),
    }, null, 2));
    return;
  }

  try {
    // runInContext(code, ms): 在沙箱 realm 内带【超时】执行(同步死循环会抛 "Script execution timed out"
    // 而非拖死进程被外层 kill)。JSVMP/VMP 签名调用建议走它;setup 仍可用 ctx/requireMod/wpRequire/Buffer。
    const runInContext = (code, ms = 8000) => vm.runInContext(code, ctx.sandbox, { timeout: ms });
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    const fn = new AsyncFunction("ctx", "requireMod", "wpRequire", "sandbox", "runInContext", opts.evalCode);
    const result = await fn(ctx, ctx.requireMod, ctx.wpRequire, ctx.sandbox, runInContext);
    if (result !== undefined) {
      console.log(typeof result === "string" ? result : JSON.stringify(result, null, 2));
    }
  } catch (e) {
    // 限长 + 只保留真正的 "at" 栈帧(丢掉含整包源码的 message 行)，绝不回吐 bundle 源码
    console.error("❌ eval error: " + String(e?.message || e).slice(0, 600));
    const frames = String(e?.stack || "").split("\n")
      .filter((l) => /^\s*at /.test(l))                                  // 只要调用帧，丢 "Error: <长 message>" 首行
      .filter((l) => !/app-service\.js|wpmod-\d+\.js/.test(l))           // 剥掉 bundle/收割模块帧
      .map((l) => l.length > 200 ? l.slice(0, 200) + "…" : l)           // 每帧限长
      .slice(0, 5);
    if (frames.length) console.error(frames.join("\n"));
    process.exit(1);
  }
}

// 结果已打印后强制退出：bundle 的 telemetry/Vue 定时器会占着事件循环不让进程自然退出。
// catch 同样限长，避免 loadBundle/解析异常把整包源码刷进 stderr。
main().then(() => process.exit(0)).catch((e) => { console.error("❌ " + String(e?.message || e).slice(0, 600)); process.exit(1); });
