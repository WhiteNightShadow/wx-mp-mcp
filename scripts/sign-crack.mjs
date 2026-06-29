#!/usr/bin/env node
/**
 * sign-crack — 通用小程序签名参数穷举破解
 *
 * 给定一个抓包样本（含已知 sign 值）和候选密钥，
 * 自动枚举参数子集 × 哈希算法，找到产生该 sign 的精确公式。
 *
 * 用法:
 *   # 最小用法：抓包文件 + 密钥
 *   node scripts/sign-crack.mjs <capture.jsonl> --key <hmac_key>
 *
 *   # 从解包源码自动提取候选密钥
 *   node scripts/sign-crack.mjs <capture.jsonl> --source <unpacked_dir>
 *
 *   # 指定 URL 过滤 + sign 字段名
 *   node scripts/sign-crack.mjs <capture.jsonl> --key <key> --url /api/order --sign-field sign
 *
 *   # 单条请求（直接传 key=value 对）
 *   node scripts/sign-crack.mjs --inline "a=1&b=2&sign=abc123&ts=999" --key mykey
 *
 * 支持的算法:
 *   哈希: HMAC-SHA256, HMAC-MD5, HMAC-SHA1, MD5, SHA256, SHA1
 *         MD5(params + "&token=" + key)
 *   对称: AES-128/256-ECB, AES-128/256-CBC (零IV / key[:16]做IV)
 *         DES-ECB, DES-CBC, 3DES-ECB, 3DES-CBC (零IV)
 *         密钥派生: 原文截取 / MD5(key) / hex解码
 *         输出: hex 和 base64 均自动尝试
 */
import { createHmac, createHash, createCipheriv } from "node:crypto";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { extractKeysFromSource, extractSignPatterns } from "../static/lib/sign-hints.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── Hash Methods ────────────────────────────────────────────────

function makeHashers(key) {
  const hashers = [
    { name: "HMAC-SHA256", fn: (s) => createHmac("sha256", key).update(s).digest("hex") },
    { name: "HMAC-MD5",    fn: (s) => createHmac("md5", key).update(s).digest("hex") },
    { name: "HMAC-SHA1",   fn: (s) => createHmac("sha1", key).update(s).digest("hex") },
    { name: "MD5",         fn: (s) => createHash("md5").update(s).digest("hex") },
    { name: "SHA256",      fn: (s) => createHash("sha256").update(s).digest("hex") },
    { name: "SHA1",        fn: (s) => createHash("sha1").update(s).digest("hex") },
    { name: "MD5+token",   fn: (s) => createHash("md5").update(s + "&token=" + key).digest("hex") },
    { name: "MD5+key",     fn: (s) => createHash("md5").update(s + key).digest("hex") },
    { name: "SHA256+key",  fn: (s) => createHash("sha256").update(s + key).digest("hex") },
  ];

  // ─── AES / DES block ciphers ─────────────────────────────────
  const rawKey = Buffer.from(key, "utf8");
  const Z16 = Buffer.alloc(16, 0);
  const Z8 = Buffer.alloc(8, 0);

  const aesKeys = [];
  if (rawKey.length >= 16) {
    aesKeys.push({ k: rawKey.subarray(0, 16), algo: "aes-128", tag: "128" });
  } else {
    const p = Buffer.alloc(16, 0); rawKey.copy(p);
    aesKeys.push({ k: p, algo: "aes-128", tag: "128p" });
  }
  if (rawKey.length >= 32) {
    aesKeys.push({ k: rawKey.subarray(0, 32), algo: "aes-256", tag: "256" });
  }
  aesKeys.push({ k: createHash("md5").update(key).digest(), algo: "aes-128", tag: "128m" });
  if (/^[0-9a-f]+$/i.test(key) && key.length % 2 === 0) {
    const hk = Buffer.from(key, "hex");
    if (hk.length === 16) aesKeys.push({ k: hk, algo: "aes-128", tag: "128h" });
    else if (hk.length === 32) aesKeys.push({ k: hk, algo: "aes-256", tag: "256h" });
  }

  for (const ak of aesKeys) {
    const kiv = ak.k.subarray(0, 16);
    for (const fmt of ["hex", "base64"]) {
      const sfx = fmt === "base64" ? "-b64" : "";
      const enc = (cAlgo, iv) => (s) => {
        try {
          const c = createCipheriv(cAlgo, ak.k, iv);
          return Buffer.concat([c.update(s, "utf8"), c.final()]).toString(fmt);
        } catch { return ""; }
      };
      hashers.push({ name: `AES-${ak.tag}-ECB${sfx}`,    fn: enc(`${ak.algo}-ecb`, null) });
      hashers.push({ name: `AES-${ak.tag}-CBC-0iv${sfx}`, fn: enc(`${ak.algo}-cbc`, Z16) });
      hashers.push({ name: `AES-${ak.tag}-CBC-kiv${sfx}`, fn: enc(`${ak.algo}-cbc`, kiv) });
    }
  }

  // DES (8-byte key)
  const dk = rawKey.length >= 8
    ? rawKey.subarray(0, 8)
    : (() => { const p = Buffer.alloc(8, 0); rawKey.copy(p); return p; })();
  for (const fmt of ["hex", "base64"]) {
    const sfx = fmt === "base64" ? "-b64" : "";
    const enc = (cAlgo, iv) => (s) => {
      try {
        const c = createCipheriv(cAlgo, dk, iv);
        return Buffer.concat([c.update(s, "utf8"), c.final()]).toString(fmt);
      } catch { return ""; }
    };
    hashers.push({ name: `DES-ECB${sfx}`,    fn: enc("des-ecb", null) });
    hashers.push({ name: `DES-CBC-0iv${sfx}`, fn: enc("des-cbc", Z8) });
  }

  // 3DES (24-byte key, works on Node v24+ where DES is disabled)
  const tdk = Buffer.alloc(24, 0);
  rawKey.copy(tdk, 0, 0, Math.min(24, rawKey.length));
  for (const fmt of ["hex", "base64"]) {
    const sfx = fmt === "base64" ? "-b64" : "";
    const enc = (cAlgo, iv) => (s) => {
      try {
        const c = createCipheriv(cAlgo, tdk, iv);
        return Buffer.concat([c.update(s, "utf8"), c.final()]).toString(fmt);
      } catch { return ""; }
    };
    hashers.push({ name: `3DES-ECB${sfx}`,    fn: enc("des-ede3-ecb", null) });
    hashers.push({ name: `3DES-CBC-0iv${sfx}`, fn: enc("des-ede3-cbc", Z8) });
  }

  return hashers;
}


// ─── Request Parsing ─────────────────────────────────────────────

function parseFormBody(body) {
  const params = {};
  for (const pair of body.split("&")) {
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    const k = pair.substring(0, eq);
    const v = decodeURIComponent(pair.substring(eq + 1).replace(/\+/g, " "));
    params[k] = v;
  }
  return params;
}

function loadCapture(file, urlFilter, signField) {
  const requests = [];
  const lines = readFileSync(file, "utf8").trim().split("\n");
  for (const line of lines) {
    const entry = JSON.parse(line);
    if (urlFilter && !entry.url?.includes(urlFilter)) continue;
    const body = entry.req_body || entry.request_body || "";
    if (!body) continue;
    const params = parseFormBody(body);
    if (!params[signField]) continue;
    requests.push({
      url: entry.url,
      params,
      sign: params[signField],
      method: entry.method || "POST",
    });
  }
  return requests;
}

// ─── Core: Brute-force Sign Params ──────────────────────────────

function* subsets(arr, minSize, maxSize) {
  const n = arr.length;
  for (let size = minSize; size <= Math.min(maxSize, n); size++) {
    yield* subsetsOfSize(arr, size);
  }
}

function* subsetsOfSize(arr, size) {
  const n = arr.length;
  const indices = Array.from({ length: size }, (_, i) => i);

  while (true) {
    yield indices.map((i) => arr[i]);

    let i = size - 1;
    while (i >= 0 && indices[i] === n - size + i) i--;
    if (i < 0) break;
    indices[i]++;
    for (let j = i + 1; j < size; j++) indices[j] = indices[j - 1] + 1;
  }
}

function crackSign(params, signValue, keys, signField, maxParams) {
  const paramKeys = Object.keys(params)
    .filter((k) => k !== signField)
    .sort();

  const results = [];
  let tried = 0;

  for (const key of keys) {
    const hashers = makeHashers(key);

    for (const subset of subsets(paramKeys, 2, maxParams)) {
      const sorted = [...subset].sort();
      const plain = sorted.map((k) => `${k}=${params[k]}`).join("&");
      tried++;

      for (const h of hashers) {
        if (h.fn(plain) === signValue) {
          results.push({
            algorithm: h.name,
            key,
            params: sorted,
            plain: plain.length > 200 ? plain.substring(0, 200) + "..." : plain,
            tried,
          });
          return results; // first match is enough
        }
      }
    }

    // Also try with single params (size=1)
    for (const k of paramKeys) {
      const plain = `${k}=${params[k]}`;
      tried++;
      for (const h of hashers) {
        if (h.fn(plain) === signValue) {
          results.push({ algorithm: h.name, key, params: [k], plain, tried });
          return results;
        }
      }
    }

    // Try ALL params sorted (no subset)
    const allPlain = paramKeys.map((k) => `${k}=${params[k]}`).join("&");
    tried++;
    for (const h of hashers) {
      if (h.fn(allPlain) === signValue) {
        results.push({ algorithm: h.name, key, params: paramKeys, plain: allPlain.substring(0, 200), tried });
        return results;
      }
    }

    // Try non-empty params only
    const nonEmpty = paramKeys.filter((k) => params[k] !== "");
    if (nonEmpty.length !== paramKeys.length) {
      const nePlain = nonEmpty.map((k) => `${k}=${params[k]}`).join("&");
      tried++;
      for (const h of hashers) {
        if (h.fn(nePlain) === signValue) {
          results.push({ algorithm: h.name, key, params: nonEmpty, plain: nePlain.substring(0, 200), tried });
          return results;
        }
      }
    }
  }

  return results.length ? results : [{ error: "no match", tried }];
}

// ─── Progress Display ───────────────────────────────────────────

function estimateCombinations(n, maxSize) {
  let total = n; // single params
  total += 1;    // all params
  total += 1;    // non-empty
  for (let k = 2; k <= Math.min(maxSize, n); k++) {
    let c = 1;
    for (let i = 0; i < k; i++) c = (c * (n - i)) / (i + 1);
    total += c;
  }
  return total;
}

// ─── Main ───────────────────────────────────────────────────────

function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    printUsage();
    return;
  }

  // Parse CLI args
  let captureFile = null;
  let inlineBody = null;
  let keys = [];
  let sourceDir = null;
  let urlFilter = null;
  let signField = "sign";
  let maxParams = 8;
  let showPatterns = false;
  let hintFile = null;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--key":
        keys.push(...args[++i].split(","));
        break;
      case "--source":
        sourceDir = args[++i];
        break;
      case "--hint":
        hintFile = args[++i];
        break;
      case "--url":
        urlFilter = args[++i];
        break;
      case "--sign-field":
        signField = args[++i];
        break;
      case "--max-params":
        maxParams = parseInt(args[++i]);
        break;
      case "--inline":
        inlineBody = args[++i];
        break;
      case "--patterns":
        showPatterns = true;
        break;
      default:
        if (!args[i].startsWith("--")) captureFile = args[i];
    }
  }

  console.log("╔══════════════════════════════════════╗");
  console.log("║  sign-crack 签名参数穷举破解        ║");
  console.log("╚══════════════════════════════════════╝\n");

  // analyze → crack 自动桥：从 mp_analyze 的 report.json 直接载入破解线索
  if (hintFile) {
    try {
      const report = JSON.parse(readFileSync(hintFile, "utf8"));
      const h = report.crackHint || report; // 允许直接传 crackHint
      console.log(`从 analyze 报告载入线索: ${hintFile}`);
      if (h.candidateKeys?.length) {
        keys.push(...h.candidateKeys);
        console.log(`  候选密钥 ${h.candidateKeys.length} 个`);
      }
      if (h.algorithms?.length) console.log(`  算法提示: ${h.algorithms.join(", ")}`);
      if (h.paramOrder?.length) console.log(`  参数序提示: ${h.paramOrder.join(" & ")}`);
      if (h.signFieldGuesses?.length) console.log(`  签名字段猜测: ${h.signFieldGuesses.join(", ")}`);
      if (h.patterns?.length) {
        console.log(`  签名模式(${h.patterns.length}):`);
        for (const p of h.patterns.slice(0, 5)) console.log(`    ${p.endpoint}: ${p.algorithm}(${p.params.join(" & ")})`);
      }
      // 未显式指定 --source 时，用报告里的 mainDir 兜底补充密钥
      if (!sourceDir && report.unpack?.mainDir && existsSync(report.unpack.mainDir)) sourceDir = report.unpack.mainDir;
      console.log();
    } catch (e) {
      console.error(`⚠️ --hint 读取失败: ${e.message}\n`);
    }
  }

  // Extract keys from source if provided
  if (sourceDir) {
    console.log(`从源码提取候选密钥: ${sourceDir}`);
    const extracted = extractKeysFromSource(sourceDir);
    if (extracted.length) {
      console.log(`  找到 ${extracted.length} 个候选密钥:`);
      for (const k of extracted) {
        console.log(`    ${k.length > 40 ? k.substring(0, 40) + "..." : k}`);
      }
      keys.push(...extracted);
    } else {
      console.log("  未找到候选密钥");
    }
    console.log();
  }

  // Show sign patterns from source
  if (showPatterns && sourceDir) {
    console.log("源码中的签名模式:");
    const patterns = extractSignPatterns(sourceDir);
    const seen = new Set();
    for (const p of patterns) {
      const key = `${p.endpoint}:${p.params.join(",")}`;
      if (seen.has(key)) continue;
      seen.add(key);
      console.log(`  ${p.endpoint}: ${p.algorithm}(${p.params.join(" & ")})`);
    }
    console.log();
  }

  if (!keys.length) {
    console.error("❌ 未指定密钥。使用 --key <key> 或 --source <dir>");
    process.exit(1);
  }
  keys = [...new Set(keys)];

  // Load requests
  let requests;
  if (inlineBody) {
    const params = parseFormBody(inlineBody);
    if (!params[signField]) {
      console.error(`❌ inline body 中未找到 ${signField} 字段`);
      process.exit(1);
    }
    requests = [{ url: "(inline)", params, sign: params[signField] }];
  } else if (captureFile) {
    requests = loadCapture(captureFile, urlFilter, signField);
    if (!requests.length) {
      console.error(`❌ 未找到包含 ${signField} 字段的请求` + (urlFilter ? ` (URL 过滤: ${urlFilter})` : ""));
      process.exit(1);
    }
  } else {
    console.error("❌ 需要 <capture.jsonl> 或 --inline");
    process.exit(1);
  }

  console.log(`待破解请求: ${requests.length} 条`);
  console.log(`候选密钥: ${keys.length} 个`);
  console.log(`最大参数子集: ${maxParams}`);
  console.log(`签名字段: ${signField}\n`);

  // Crack each request
  const formulas = new Map();
  let cracked = 0;
  const hasherCount = makeHashers(keys[0]).length;

  for (const req of requests) {
    const paramCount = Object.keys(req.params).filter((k) => k !== signField).length;
    const combos = estimateCombinations(paramCount, maxParams) * keys.length * hasherCount;

    // Extract endpoint from URL for display
    const urlPath = req.url.split("?")[0].split("/").pop() || req.url;
    console.log(`── ${urlPath} ──`);
    console.log(`   参数: ${paramCount} 个, 预计尝试: ~${Math.round(combos / 1000)}K 组合`);
    console.log(`   sign: ${req.sign.substring(0, 32)}...`);

    const t0 = Date.now();
    const results = crackSign(req.params, req.sign, keys, signField, maxParams);
    const elapsed = Date.now() - t0;

    if (results[0]?.error) {
      console.log(`   ✗ 未破解 (尝试 ${results[0].tried} 组合, ${elapsed}ms)\n`);
    } else {
      const r = results[0];
      cracked++;
      console.log(`   ✓ 破解成功! (${elapsed}ms, 第 ${r.tried} 次尝试)`);
      console.log(`   算法: ${r.algorithm}`);
      console.log(`   密钥: ${r.key}`);
      console.log(`   签名参数: ${r.params.join(", ")}`);
      console.log(`   明文: ${r.plain}`);
      console.log();

      const formulaKey = r.params.join(",");
      if (!formulas.has(formulaKey)) {
        formulas.set(formulaKey, { ...r, endpoints: [urlPath] });
      } else {
        formulas.get(formulaKey).endpoints.push(urlPath);
      }
    }
  }

  // Summary
  console.log("═══════════════════════════════════════");
  console.log(`破解结果: ${cracked}/${requests.length} 条请求\n`);

  if (formulas.size > 0) {
    console.log("发现的签名公式:");
    for (const [, f] of formulas) {
      console.log(`  ${f.algorithm}(${f.params.join(" & ")}, key="${f.key.substring(0, 20)}...")`);
      console.log(`    端点: ${f.endpoints.join(", ")}`);
    }

    // Generate code snippet
    console.log("\n生成的 Node.js 签名代码:");
    for (const [, f] of formulas) {
      const algo = f.algorithm.toLowerCase();
      if (algo.startsWith("hmac-")) {
        const hashAlgo = algo.replace("hmac-", "");
        console.log(`
  function sign(params) {
    const fields = ${JSON.stringify(f.params)};
    const sorted = fields
      .map(k => k + "=" + (typeof params[k] === "object" ? JSON.stringify(params[k]) : params[k]))
      .join("&");
    return createHmac("${hashAlgo}", "${f.key}").update(sorted).digest("hex");
  }`);
      } else if (algo === "md5+token") {
        console.log(`
  function sign(params) {
    const fields = ${JSON.stringify(f.params)};
    const sorted = fields.map(k => k + "=" + params[k]).join("&");
    return createHash("md5").update(sorted + "&token=${f.key}").digest("hex");
  }`);
      } else if (algo.match(/^aes-|^(3?)des-/)) {
        const isB64 = algo.includes("-b64");
        const fmt = isB64 ? "base64" : "hex";
        const clean = algo.replace(/-b64$/, "");
        const parts = clean.split("-");
        let cipherName, ivCode, keyCode;
        if (parts[0] === "3des") {
          cipherName = `des-ede3-${parts[1]}`;
          ivCode = parts[1] === "ecb" ? "null" : "Buffer.alloc(8, 0)";
          keyCode = `(() => { const k = Buffer.alloc(24, 0); Buffer.from("${f.key}").copy(k, 0, 0, 24); return k; })()`;
        } else if (parts[0] === "des") {
          cipherName = `des-${parts[1]}`;
          ivCode = parts[1] === "ecb" ? "null" : "Buffer.alloc(8, 0)";
          keyCode = `Buffer.from("${f.key}").subarray(0, 8)`;
        } else {
          const tag = parts[1];
          const mode = parts[2];
          const bits = tag.replace(/[pmh]$/, "");
          cipherName = `aes-${bits}-${mode}`;
          if (mode === "ecb") ivCode = "null";
          else if (parts[3] === "0iv") ivCode = "Buffer.alloc(16, 0)";
          else ivCode = "aesKey.subarray(0, 16)";
          if (tag.endsWith("m")) keyCode = `createHash("md5").update("${f.key}").digest()`;
          else if (tag.endsWith("h")) keyCode = `Buffer.from("${f.key}", "hex")`;
          else keyCode = `Buffer.from("${f.key}").subarray(0, ${bits === "256" ? 32 : 16})`;
        }
        console.log(`
  function sign(params) {
    const fields = ${JSON.stringify(f.params)};
    const sorted = fields.map(k => k + "=" + params[k]).join("&");
    const aesKey = ${keyCode};
    const cipher = createCipheriv("${cipherName}", aesKey, ${ivCode});
    return Buffer.concat([cipher.update(sorted, "utf8"), cipher.final()]).toString("${fmt}");
  }`);
      }
    }
  }
}

function printUsage() {
  console.log(`sign-crack — 通用小程序签名参数穷举破解

用法:
  node scripts/sign-crack.mjs <capture.jsonl> --key <key>
  node scripts/sign-crack.mjs <capture.jsonl> --source <unpacked_dir>
  node scripts/sign-crack.mjs --inline "a=1&sign=abc" --key <key>

选项:
  --key <key>           HMAC 密钥 (逗号分隔多个)
  --source <dir>        从解包目录自动提取候选密钥
  --url <pattern>       只破解 URL 包含此字符串的请求
  --sign-field <name>   签名字段名 (默认: sign)
  --max-params <n>      最大参数子集大小 (默认: 8)
  --patterns            显示源码中发现的签名模式
  --inline <body>       直接传入 URL-encoded 参数

示例:
  # 从解包源码自动提取密钥
  node scripts/sign-crack.mjs /tmp/capture.jsonl \\
    --source static/unpacked/<appid> --patterns

  # 手动指定密钥 + URL 过滤
  node scripts/sign-crack.mjs /tmp/capture.jsonl \\
    --key "your_hmac_key_here" \\
    --url /api/order`);
}

main();
