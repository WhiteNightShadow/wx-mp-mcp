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

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..");

function findBundle(appid) {
  const unpackDir = join(PROJECT_ROOT, "static", "unpacked", appid);
  if (!existsSync(unpackDir)) return null;
  const versions = readdirSync(unpackDir).filter(d => /^\d+$/.test(d)).sort((a, b) => +b - +a);
  for (const ver of versions) {
    const candidate = join(unpackDir, ver, "app-service.js");
    if (existsSync(candidate)) return candidate;
  }
  const direct = join(unpackDir, "app-service.js");
  if (existsSync(direct)) return direct;
  return null;
}

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { appid: null, bundlePath: null, evalCode: null, listModules: false, storage: {} };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--eval" && args[i + 1]) { opts.evalCode = args[++i]; }
    else if (args[i] === "--bundle" && args[i + 1]) { opts.bundlePath = args[++i]; }
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

  const bundlePath = opts.bundlePath || findBundle(opts.appid);
  if (!bundlePath || !existsSync(bundlePath)) {
    console.error(`❌ app-service.js not found for ${opts.appid}`);
    console.error(`   Run 'mp_analyze ${opts.appid}' first to unpack.`);
    process.exit(1);
  }

  console.error(`Loading bundle: ${bundlePath}`);
  const ctx = loadBundle({ appid: opts.appid, bundlePath, storage: opts.storage, timeout: 30000 });
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
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    const fn = new AsyncFunction("ctx", "requireMod", "wpRequire", "sandbox", opts.evalCode);
    const result = await fn(ctx, ctx.requireMod, ctx.wpRequire, ctx.sandbox);
    if (result !== undefined) {
      console.log(typeof result === "string" ? result : JSON.stringify(result, null, 2));
    }
  } catch (e) {
    console.error(`❌ eval error: ${e.message}`);
    if (e.stack) console.error(e.stack.split("\n").slice(0, 5).join("\n"));
    process.exit(1);
  }
}

main();
