#!/usr/bin/env node
/**
 * mp-analyze — 微信小程序静态分析成品 (统一 CLI)
 *
 * 一条龙: 解密+解包(主包/分包/插件) → 签名/加密定位 → API 抽取 → 接口复现代码生成 → 报告。
 * 对【任意】已缓存的小程序通用。输出到项目内 static/out/<appid>/,绝不污染微信缓存目录。
 *
 * 用法:
 *   node static/mp-analyze.mjs --active            # 分析当前运行中的小程序
 *   node static/mp-analyze.mjs <appid>             # 分析指定 appid (取最新版本)
 *   node static/mp-analyze.mjs --all               # 批量分析全部缓存小程序
 *   node static/mp-analyze.mjs --list              # 仅列出缓存小程序
 *   node static/mp-analyze.mjs <appid> --version N # 指定版本
 *
 * 产出 (static/out/<appid>/):
 *   app/ , plugins/        解包后的源码树
 *   report.json           结构化分析结果
 *   REPORT.md             人类可读报告
 *   repro.node.mjs        Node 接口复现代码
 *   repro.python.py       Python 接口复现代码
 */
import { execSync } from "node:child_process";
import { writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  WXAPKG_ROOT, listAllApps, findAppPackages, batchUnpack,
} from "./lib/batch-unpack.mjs";
import { locateCrypto } from "./lib/crypto-locate.mjs";
import { extractApis, generateReproCode } from "./lib/codegen.mjs";
import { toSignInfo } from "./lib/sign-adapter.mjs";
import { buildCrackHint } from "./lib/sign-hints.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT_ROOT = join(__dirname, "out");

// ── 运行中小程序检测 ──────────────────────────────────────────────
function findActiveAppIds() {
  try {
    const ps = execSync("ps aux", { encoding: "utf8" });
    const ids = [...ps.matchAll(/--wmpf-appid[=\s](wx[a-f0-9]{16})/g)].map((m) => m[1]);
    return [...new Set(ids)];
  } catch {
    return [];
  }
}

// ── 单个小程序的完整分析 ───────────────────────────────────────────
async function analyzeApp(appid, opts = {}) {
  const outDir = join(OUT_ROOT, appid);
  if (existsSync(outDir) && !opts.keep) rmSync(outDir, { recursive: true, force: true });
  mkdirSync(outDir, { recursive: true });

  const log = opts.quiet ? () => {} : (m) => console.log("    " + m);

  // 1) 批量解包
  const unpacked = await batchUnpack(appid, outDir, { version: opts.version, onLog: log });

  // 2) 签名/加密定位 (吃主包源码树 + 插件树)
  const crypto = await locateCrypto(unpacked.mainDir);

  // 3) API 抽取 (全部 JS)
  const apis = extractApis(unpacked.allJsFiles);

  // 4) module2 → module3 适配
  const signInfo = toSignInfo(crypto);

  // 5) 代码生成
  let reproNode = "", reproPython = "";
  if (apis.length) {
    reproNode = generateReproCode(apis, signInfo, { lang: "node" });
    reproPython = generateReproCode(apis, signInfo, { lang: "python" });
    writeFileSync(join(outDir, "repro.node.mjs"), reproNode);
    writeFileSync(join(outDir, "repro.python.py"), reproPython);
  }

  // 6) 结构化报告
  const report = {
    appid,
    version: unpacked.version,
    analyzedAt: opts.now || null,
    unpack: {
      mainDir: unpacked.mainDir,
      packages: unpacked.stats.packages,
      totalFiles: unpacked.stats.totalFiles,
      jsFiles: unpacked.stats.jsFiles,
      subPackages: unpacked.subPackages.map((s) => ({ filename: s.filename, root: s.root, fileCount: s.fileCount })),
      plugins: unpacked.plugins.map((p) => ({ filename: p.filename, key: p.key, fileCount: p.fileCount })),
      errors: unpacked.errors,
    },
    crypto: {
      hasSigning: crypto.hasSigning,
      hasEncryption: crypto.hasEncryption,
      verdict: crypto.verdict,
      algorithms: crypto.algorithms,
      cryptoLibs: crypto.cryptoLibs,
      signingSignals: crypto.signingSignals || [],
      signFunctions: crypto.signFunctions.map((f) => ({
        name: f.name, file: f.file, algo: f.algo, inputs: f.inputs,
        score: f.score, sourceLen: f.sourceLen,
        signTemplate: f.signTemplate,
      })),
      requestSignLinkage: crypto.requestSignLinkage,
      stats: crypto.stats,
    },
    // analyze → crack 自动桥：候选密钥 + 算法 + 参数序 + 签名字段猜测，
    // 供 sign-crack --hint 直接消费，免人工搬运。
    crackHint: crypto.hasSigning ? buildCrackHint(unpacked.mainDir, crypto) : null,
    apis: apis.map((a) => ({
      file: a.file, method: a.method, urlTemplate: a.urlTemplate,
      baseUrl: a.baseUrl, dynamicSegs: a.dynamicSegs,
      headers: a.headers, data: a.data, signRefs: a.signRefs,
      enableChunked: a.enableChunked,
    })),
    apiCount: apis.length,
  };
  writeFileSync(join(outDir, "report.json"), JSON.stringify(report, null, 2));

  // 7) Markdown 报告
  writeFileSync(join(outDir, "REPORT.md"), renderMarkdown(report, signInfo));

  return { outDir, report, crypto, apis, signInfo, unpacked };
}

// ── Markdown 渲染 ─────────────────────────────────────────────────
function renderMarkdown(r, signInfo) {
  const L = [];
  L.push(`# 小程序静态分析报告: ${r.appid}`);
  L.push("");
  L.push(`- 版本: \`${r.version}\``);
  L.push(`- 解包: ${r.unpack.packages} 个包 / ${r.unpack.totalFiles} 文件 / ${r.unpack.jsFiles} JS`);
  if (r.unpack.subPackages.length) {
    L.push(`- 分包(${r.unpack.subPackages.length}): ${r.unpack.subPackages.map((s) => s.root || s.filename).join(", ")}`);
  }
  if (r.unpack.plugins.length) {
    L.push(`- 插件(${r.unpack.plugins.length}): ${r.unpack.plugins.map((p) => p.key).join(", ")}`);
  }
  if (r.unpack.errors.length) {
    L.push(`- ⚠️ 解包错误(${r.unpack.errors.length}): ${r.unpack.errors.map((e) => `${e.filename}: ${e.error}`).join("; ")}`);
  }
  L.push("");

  L.push(`## 签名 / 加密`);
  L.push("");
  const cryptoTag = r.crypto.hasSigning ? "🔐 有签名" : (r.crypto.hasEncryption ? "🔒 有加解密(疑无业务签名)" : "✅ 无签名");
  L.push(`**${cryptoTag}** — ${r.crypto.verdict}`);
  L.push("");
  if (r.crypto.algorithms.length) {
    L.push(`- 算法: ${r.crypto.algorithms.map((a) => a.algo).join(", ")}`);
  }
  if (r.crypto.signingSignals?.length) {
    const byKind = {};
    for (const s of r.crypto.signingSignals) (byKind[s.kind] ||= []).push(s.signal);
    L.push(`- 签名/加密信号:`);
    for (const [kind, sigs] of Object.entries(byKind)) {
      const uniq = [...new Set(sigs)].slice(0, 6);
      L.push(`  - **${kind}** (${sigs.length}): ${uniq.join(", ")}`);
    }
  }
  if (r.crypto.cryptoLibs.length) {
    L.push(`- 加密库: ${r.crypto.cryptoLibs.map((c) => c.lib).join(", ")}`);
  }
  if (r.crypto.signFunctions.length) {
    L.push("");
    L.push(`### 签名函数 (${r.crypto.signFunctions.length})`);
    for (const f of r.crypto.signFunctions.slice(0, 8)) {
      L.push(`- \`${f.name}\` @ ${f.file} — 算法[${f.algo.join(",") || "?"}] 入参[${f.inputs.join(",") || "?"}] score=${f.score}`);
      if (f.signTemplate?.skeleton) L.push(`  - 签名串骨架: \`${String(f.signTemplate.skeleton).slice(0, 120)}\``);
    }
  }
  if (r.crypto.requestSignLinkage.length) {
    L.push("");
    L.push(`### 签名→请求挂载点 (${r.crypto.requestSignLinkage.length})`);
    for (const l of r.crypto.requestSignLinkage.slice(0, 8)) {
      L.push(`- [${l.type}] ${l.file || ""} ${l.handler ? `handler=${l.handler}` : ""}`);
    }
  }
  L.push("");

  L.push(`## API 接口 (${r.apiCount})`);
  L.push("");
  if (!r.apiCount) {
    L.push("_未从源码静态抽取到 wx.request 调用 (可能经封装层/动态构造)。_");
  } else {
    for (const a of r.apis) {
      L.push(`### [${a.method}] ${a.urlTemplate}`);
      L.push(`- 来源: \`${a.file}\``);
      if (a.baseUrl) L.push(`- base: ${a.baseUrl}`);
      const hdrs = Object.entries(a.headers || {});
      if (hdrs.length) L.push(`- headers: ${hdrs.map(([k, v]) => `${k}(${v.source})`).join(", ")}`);
      if (a.data && !a.data._raw) {
        const fields = Object.entries(a.data);
        if (fields.length) L.push(`- data: ${fields.map(([k, v]) => `${k}(${v.source})`).join(", ")}`);
      } else if (a.data?._raw) {
        L.push(`- data: 动态表达式 \`${a.data._raw}\``);
      }
      if (a.signRefs.length) L.push(`- 🔐 需签名字段: ${a.signRefs.map((s) => `${s.in}.${s.name}`).join(", ")}`);
      if (a.enableChunked) L.push(`- ⚡ SSE 流式接口`);
      L.push("");
    }
  }

  L.push(`## 复现代码`);
  L.push("");
  if (r.apiCount) {
    L.push(`- Node: \`repro.node.mjs\` (node >=18, 内置 fetch)`);
    L.push(`- Python: \`repro.python.py\` (requests)`);
    if (signInfo?.transplantable) {
      L.push(`- 🔐 已移植签名函数 \`${signInfo.fnName}\` 进 Node 代码; ${signInfo.note}`);
    } else if (signInfo) {
      L.push(`- ⚠️ ${signInfo.note}`);
    } else {
      L.push(`- ✅ 无签名,生成的代码可直接填参运行`);
    }
  } else {
    L.push("_无 API 可生成。_");
  }
  L.push("");
  return L.join("\n");
}

// ── 控制台摘要 ─────────────────────────────────────────────────────
function printSummary(res) {
  const { report: r, signInfo } = res;
  console.log(`\n  ✓ ${r.appid} v${r.version}`);
  console.log(`    解包: ${r.unpack.packages}包/${r.unpack.totalFiles}文件/${r.unpack.jsFiles}JS` +
    (r.unpack.subPackages.length ? ` +${r.unpack.subPackages.length}分包` : "") +
    (r.unpack.plugins.length ? ` +${r.unpack.plugins.length}插件` : "") +
    (r.unpack.errors.length ? ` ⚠️${r.unpack.errors.length}错误` : ""));
  const tag = r.crypto.hasSigning ? "🔐 有签名" : (r.crypto.hasEncryption ? "🔒 有加解密" : "✅ 无");
  console.log(`    签名: ${tag} ${r.crypto.algorithms.length ? `[${r.crypto.algorithms.map((a) => a.algo).join(",")}]` : ""}` +
    (r.crypto.signFunctions.length ? ` ${r.crypto.signFunctions.length}函数` : "") +
    (r.crypto.signingSignals?.length ? ` ${r.crypto.signingSignals.length}信号` : ""));
  console.log(`    API: ${r.apiCount} 个` + (signInfo?.transplantable ? ` (签名函数已移植)` : ""));
  console.log(`    → ${res.outDir}`);
}

// ── 入口 ───────────────────────────────────────────────────────────
async function main() {
  const args = process.argv.slice(2);
  const flags = new Set(args.filter((a) => a.startsWith("--")));
  const positionals = args.filter((a) => !a.startsWith("--"));
  const versionIdx = args.indexOf("--version");
  const version = versionIdx >= 0 ? args[versionIdx + 1] : undefined;

  console.log("╔══════════════════════════════════════╗");
  console.log("║  微信小程序静态分析成品 mp-analyze   ║");
  console.log("╚══════════════════════════════════════╝");

  if (flags.has("--list")) {
    const apps = listAllApps();
    console.log(`\n缓存目录: ${WXAPKG_ROOT}`);
    console.log(`找到 ${apps.length} 个小程序:\n`);
    for (const a of apps) {
      const p = a.packages;
      console.log(`  ${a.appid}  v${a.latest?.version || "?"}  ` +
        `[${p.main ? "主包" : "无主包"}${p.subCount ? ` +${p.subCount}分包` : ""}${p.pluginCount ? ` +${p.pluginCount}插件` : ""}]`);
    }
    return;
  }

  let targets = [];
  if (flags.has("--all")) {
    targets = listAllApps().map((a) => a.appid);
    console.log(`\n批量模式: ${targets.length} 个小程序\n`);
  } else if (flags.has("--active")) {
    targets = findActiveAppIds();
    if (!targets.length) {
      console.error("\n❌ 未检测到运行中的小程序 (ps 无 --wmpf-appid)");
      console.error("   请先在微信打开小程序, 或直接指定 appid / 用 --all");
      process.exit(1);
    }
    console.log(`\n检测到运行中: ${targets.join(", ")}`);
  } else if (positionals.length) {
    targets = positionals;
  } else {
    console.log("\n用法:");
    console.log("  node static/mp-analyze.mjs --active        分析运行中的小程序");
    console.log("  node static/mp-analyze.mjs <appid>         分析指定小程序");
    console.log("  node static/mp-analyze.mjs --all           批量分析全部");
    console.log("  node static/mp-analyze.mjs --list          列出缓存");
    return;
  }

  const summary = { ok: 0, failed: 0, signed: 0, totalApis: 0, errors: [] };
  for (const appid of targets) {
    try {
      console.log(`\n──── ${appid} ────`);
      const res = await analyzeApp(appid, { version, quiet: flags.has("--all") });
      printSummary(res);
      summary.ok++;
      if (res.report.crypto.hasSigning) summary.signed++;
      summary.totalApis += res.report.apiCount;
    } catch (e) {
      summary.failed++;
      summary.errors.push({ appid, error: e.message });
      console.error(`  ❌ ${appid}: ${e.message}`);
    }
  }

  if (targets.length > 1) {
    console.log(`\n═══ 汇总 ═══`);
    console.log(`  成功 ${summary.ok} / 失败 ${summary.failed}`);
    console.log(`  有签名 ${summary.signed} / 无签名 ${summary.ok - summary.signed}`);
    console.log(`  共抽取 API ${summary.totalApis} 个`);
    if (summary.errors.length) {
      console.log(`  失败列表:`);
      for (const e of summary.errors) console.log(`    ${e.appid}: ${e.error}`);
    }
  }
  console.log(`\n✅ 完成,输出在 ${OUT_ROOT}/`);
}

main().catch((e) => {
  console.error("致命错误:", e);
  process.exit(1);
});
