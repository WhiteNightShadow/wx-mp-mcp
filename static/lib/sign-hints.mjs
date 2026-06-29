/**
 * sign-hints — 从解包源码提取「破解线索」，桥接 analyze 与 sign-crack。
 *
 * - extractKeysFromSource(dir)  : 扫源码里硬编码的候选密钥(HMAC/MD5/token 等)
 * - extractSignPatterns(dir)    : 抽签名调用点的参数名 + 算法
 * - buildCrackHint(mainDir, crypto): 汇总成 report.json 的 crackHint 块，
 *   让 sign-crack --hint 直接消费(候选密钥 + 算法 + 参数序 + 签名字段猜测)，
 *   省掉「analyze 出结果 → 人工搬给 sign-crack」这一步。
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

function walkJs(dir) {
  const out = [];
  function walk(d) {
    for (const f of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, f.name);
      if (f.isDirectory() && !f.name.startsWith(".")) walk(full);
      else if (f.name.endsWith(".js")) out.push(full);
    }
  }
  walk(dir);
  return out;
}

/** 扫源码里硬编码的候选密钥。 */
export function extractKeysFromSource(dir) {
  const keys = new Set();
  for (const file of walkJs(dir)) {
    const code = readFileSync(file, "utf8");
    // HmacSHA256(x, "KEY") — CryptoJS
    for (const m of code.matchAll(/HmacSHA256\(\w+,\s*["']([^"']+)["']\)/g)) keys.add(m[1]);
    // createHmac('sha256', "KEY")
    for (const m of code.matchAll(/createHmac\(['"]sha256['"],\s*["']([^"']+)["']\)/g)) keys.add(m[1]);
    // hex_md5(x + "KEY") / md5(x + "KEY")
    for (const m of code.matchAll(/(?:hex_)?md5\([^)]*["']([A-Za-z0-9]{16,})["']\)/g)) keys.add(m[1]);
    // "&token=" + "KEY"
    for (const m of code.matchAll(/["']&token=["']\s*\+\s*["']([^"']+)["']/g)) keys.add(m[1]);
    // 长字母数字常量紧跟 ).toString()
    for (const m of code.matchAll(/["']([A-Za-z0-9]{20,64})["'](?=\)\.toString\(\))/g)) keys.add(m[1]);
  }
  return [...keys];
}

/** 抽签名调用点的参数名 + 算法。 */
export function extractSignPatterns(dir) {
  const patterns = [];
  for (const file of walkJs(dir)) {
    const code = readFileSync(file, "utf8");
    for (const m of code.matchAll(/HmacSHA256\((\w+),/g)) {
      const ctx = code.substring(Math.max(0, m.index - 600), m.index);
      const paramKeys = [...ctx.matchAll(/["'&](\w+)=["']\s*\+/g)].map((p) => p[1]);
      const after = code.substring(m.index, Math.min(code.length, m.index + 500));
      const ep = after.match(/bE\)\(["'](\w+)["']/);
      if (paramKeys.length > 0) {
        patterns.push({ endpoint: ep ? ep[1] : "?", params: [...new Set(paramKeys)].sort(), file: file.replace(dir, ""), algorithm: "HMAC-SHA256" });
      }
    }
    for (const m of code.matchAll(/hex_md5\((\w+)\)/g)) {
      const ctx = code.substring(Math.max(0, m.index - 600), m.index);
      const paramKeys = [...ctx.matchAll(/["'&](\w+)=["']\s*\+/g)].map((p) => p[1]);
      const hasToken = ctx.includes("&token=");
      if (paramKeys.length > 0) {
        patterns.push({ endpoint: "?", params: [...new Set(paramKeys)].sort(), file: file.replace(dir, ""), algorithm: hasToken ? "MD5+token" : "MD5" });
      }
    }
  }
  return patterns;
}

function dedupePatterns(patterns) {
  const seen = new Set();
  const out = [];
  for (const p of patterns) {
    const k = `${p.endpoint}:${p.params.join(",")}:${p.algorithm}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(p);
  }
  return out;
}

/**
 * 汇总成 crackHint。crypto = locateCrypto() 的返回。
 * @returns {{candidateKeys, algorithms, paramOrder, signFieldGuesses, patterns}}
 */
export function buildCrackHint(mainDir, crypto) {
  const candidateKeys = extractKeysFromSource(mainDir);
  const algorithms = [...new Set((crypto?.algorithms || []).map((a) => a.algo))];
  const patterns = dedupePatterns(extractSignPatterns(mainDir)).slice(0, 20);

  // 参数序：从 score 最高、有签名串骨架的签名函数里解析 "k=" 顺序
  let paramOrder = [];
  const sf = (crypto?.signFunctions || []).find((f) => f.signTemplate && f.signTemplate.skeleton);
  if (sf) paramOrder = [...String(sf.signTemplate.skeleton).matchAll(/([A-Za-z_$][\w$]*)\s*=/g)].map((m) => m[1]).slice(0, 16);

  // 签名字段猜测：来自签名头信号 + 模式 + 常见默认
  const headerSignals = (crypto?.signingSignals || [])
    .filter((s) => /header|key/i.test(s.kind || "") || /^[\w-]{2,32}$/.test(s.signal || "") && /sign|sig|token|nonce/i.test(s.signal || ""))
    .map((s) => s.signal);
  const signFieldGuesses = [...new Set([...headerSignals, "sign", "signature", "_sign"])].filter(Boolean).slice(0, 8);

  return { candidateKeys, algorithms, paramOrder, signFieldGuesses, patterns };
}
