#!/usr/bin/env node
/**
 * capture-import — 把任意来源的抓包归一成 sign-crack 兼容的 JSONL。
 *
 * 支持输入:
 *   - HAR        (.har, Charles / Fiddler / Chrome DevTools "Save all as HAR")
 *   - cURL       (DevTools "Copy as cURL"，支持 bash $'...' / Windows cmd ^ / 多条 / 续行)
 *   - JSON body  (只有请求体的 JSON，配 --api-url 指定接口)
 *   - JSONL      (已是内部格式 → 归一重编码透传)
 *
 * 归一目标(每行一条):
 *   {"url","method","req_body":"k=v&k=v(URL-encoded)","raw_body?","req_headers?","status?","res_body?","ts"}
 *   - req_body 一律经 enc() 编码：base64 的 + → %2B、/ → %2F、= → %3D，下游 byte-perfect 还原。
 *   - JSON 体扁平化(a.b / a[0])；GET / POST 的 URL query 参数都会并入 req_body。
 *
 * 用法:
 *   node scripts/capture-import.mjs <文件> [--format auto|har|curl|json|jsonl]
 *        [--url <子串过滤>] [--api-url <url>] [--method POST] [--out <路径>]
 *   pbpaste | node scripts/capture-import.mjs --format curl --out captures/x.jsonl
 */
import { readFileSync, writeFileSync, mkdirSync, readFileSync as _rf } from "node:fs";
import { join, dirname, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(__dirname, "..");

// ─── 编码：统一把 [k,v] 对编成 req_body ───────────────────────────
const enc = (s) => encodeURIComponent(String(s));
const pairsToReqBody = (pairs) => pairs.map(([k, v]) => `${enc(k)}=${enc(v)}`).join("&");

/** 嵌套 JSON 扁平化成 [k,v] 对 (dot / [i])，与 mitm-capture.py 一致。 */
function flattenJson(obj, prefix = "") {
  const out = [];
  if (obj === null || obj === undefined) {
    if (prefix) out.push([prefix, ""]);
    return out;
  }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => out.push(...flattenJson(v, `${prefix}[${i}]`)));
  } else if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      const key = prefix ? `${prefix}.${k}` : k;
      if (v !== null && typeof v === "object") out.push(...flattenJson(v, key));
      else out.push([key, v === null || v === undefined ? "" : v]);
    }
  } else {
    if (prefix) out.push([prefix, obj]);
  }
  return out;
}

/**
 * 解析 query / form body 成 [k,v] 对（值解码后保持原始字节）。
 * 注意：本工具面向「签名还原」，base64 签名里的字面 + 远多于「空格编码成 +」，
 * 故【不】做 +→空格 转换，保留 + 为字面量（下游 enc() 会编成 %2B）。
 */
function parsePairs(s) {
  const out = [];
  for (const pair of s.split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const k = eq === -1 ? pair : pair.slice(0, eq);
    const v = eq === -1 ? "" : pair.slice(eq + 1);
    let dk = k, dv = v;
    try { dk = decodeURIComponent(k); } catch { /* keep raw */ }
    try { dv = decodeURIComponent(v); } catch { /* keep raw */ }
    out.push([dk, dv]);
  }
  return out;
}

const looksJson = (s) => /^\s*[[{]/.test(s);

/** 请求体 → [k,v] 对。返回 {pairs, raw}；pairs=null 表示无法解析(纯文本)。 */
function bodyToPairs(bodyText, contentType) {
  const raw = (bodyText ?? "").trim();
  if (!raw) return { pairs: [], raw: "" };
  const ct = (contentType || "").toLowerCase();
  // 内容嗅探优先于声明的 content-type：体明显是 JSON({ 或 [ 开头)就按 JSON 解析，
  // 即使 header 把 content-type 错标成 form(HAR 大小写重复头可能选错变体)。
  if (looksJson(raw) || ct.includes("json")) {
    try { return { pairs: flattenJson(JSON.parse(raw)), raw }; } catch { /* fall through */ }
  }
  if (raw.includes("=")) return { pairs: parsePairs(raw), raw };
  return { pairs: null, raw }; // 纯文本，无法拆成 k=v
}

/** 取 URL query 为 [k,v] 对。 */
function urlQueryPairs(url) {
  const qi = (url || "").indexOf("?");
  if (qi === -1) return [];
  return parsePairs(url.slice(qi + 1));
}

/** 组装一条归一记录。body 参数 + URL query 参数合并(query 不覆盖已有 body 键)。 */
function makeEntry({ url, method, bodyText, bodyPairs, contentType, headers, status, resBody }) {
  let pairs, raw = "";
  if (bodyPairs) { pairs = [...bodyPairs]; }
  else { const r = bodyToPairs(bodyText, contentType); pairs = r.pairs ? [...r.pairs] : null; raw = r.raw; }

  const hasBody = (bodyPairs && bodyPairs.length) || (raw && raw.length);
  method = (method || (hasBody ? "POST" : "GET")).toUpperCase();

  // URL query 并入(GET 签名常在 query；POST 也可能 query+body 都进签名)
  const list = pairs || [];
  const have = new Set(list.map(([k]) => k));
  for (const [k, v] of urlQueryPairs(url || "")) if (!have.has(k)) { list.push([k, v]); have.add(k); }

  const e = { url: url || "", method, req_body: list.length ? pairsToReqBody(list) : "" };
  if (raw && (pairs === null || !pairs.length)) e.raw_body = raw; // 仅保留无法拆解的原文(JSON 原文也留，便于整体哈希型签名)
  else if (raw && looksJson(raw)) e.raw_body = raw;
  if (headers && Object.keys(headers).length) e.req_headers = headers;
  if (status !== undefined && status !== null) e.status = status;
  if (resBody) e.res_body = String(resBody).slice(0, 4096);
  e.ts = Math.floor(Date.now() / 1000);
  return e;
}

// ─── HAR ─────────────────────────────────────────────────────────
function parseHar(text) {
  const har = JSON.parse(text);
  const entries = har?.log?.entries || [];
  const out = [];
  for (const it of entries) {
    const req = it.request || {};
    const headers = {};
    const ctVals = [];
    for (const h of req.headers || []) {
      if (!h.name || h.name.startsWith(":")) continue; // 丢 HTTP/2 伪头
      const ln = h.name.toLowerCase();
      headers[ln] = h.value;                            // 大小写归一，去重
      if (ln === "content-type") ctVals.push(h.value);
    }
    // 多个 content-type 变体时优先取 json 那条(而非盲取末位)
    const contentType = req.postData?.mimeType || ctVals.find((v) => /json/i.test(v)) || ctVals[ctVals.length - 1] || "";
    const bodyText = req.postData?.text || "";
    let bodyPairs = null;
    if (!bodyText && Array.isArray(req.postData?.params)) {
      // 直接产出 [k,v] 对，绕开「拼假 form 串再反解」的破坏回路
      bodyPairs = req.postData.params.map((p) => [p.name, p.value ?? ""]);
    }
    let resBody = it.response?.content?.text;
    if (resBody && it.response?.content?.encoding === "base64") {
      try { resBody = Buffer.from(resBody, "base64").toString("utf8"); } catch { /* keep */ }
    }
    out.push(makeEntry({
      url: req.url, method: req.method, bodyText, bodyPairs, contentType, headers,
      status: it.response?.status, resBody,
    }));
  }
  return out;
}

// ─── cURL ────────────────────────────────────────────────────────
/** Windows cmd 转义预处理：^" → "、^& → &、^^ → ^、行尾 ^ → 续行。 */
function stripCmdCarets(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    if (text[i] !== "^") { out += text[i]; continue; }
    const nx = text[i + 1];
    if (nx === undefined) continue;                       // 结尾孤立 ^
    if (nx === "\n") { i += 1; continue; }                // ^\n 续行
    if (nx === "\r" && text[i + 2] === "\n") { i += 2; continue; }
    out += nx; i += 1;                                    // ^X → X
  }
  return out;
}

/** 把一段文本切成「一条或多条」curl 命令(处理 \ 续行)。 */
function splitCurlCommands(text) {
  const joined = text.replace(/\\\r?\n/g, " ");
  const re = /(^|\n|;|&&)\s*curl\b/g;
  const starts = [];
  let m;
  while ((m = re.exec(joined))) starts.push(joined.indexOf("curl", m.index));
  if (!starts.length) return [];
  const cmds = [];
  for (let i = 0; i < starts.length; i++) {
    cmds.push(joined.slice(starts[i], i + 1 < starts.length ? starts[i + 1] : undefined));
  }
  return cmds;
}

/** shell 词法切分：'single' / "double" / $'ansi-c' / 裸 token / 转义。 */
function tokenizeShell(s) {
  const toks = [];
  let i = 0, cur = "", has = false;
  const push = () => { if (has) { toks.push(cur); cur = ""; has = false; } };
  while (i < s.length) {
    const c = s[i];
    if (c === " " || c === "\t" || c === "\n" || c === "\r") { push(); i++; continue; }
    has = true;
    if (c === "'") { // single-quote: literal
      i++; while (i < s.length && s[i] !== "'") cur += s[i++]; i++; continue;
    }
    if (c === "$" && s[i + 1] === "'") { // ANSI-C $'...'
      i += 2;
      const bytes = [];
      const flush = () => { if (bytes.length) { cur += Buffer.from(bytes).toString("utf8"); bytes.length = 0; } };
      while (i < s.length && s[i] !== "'") {
        if (s[i] !== "\\") { flush(); cur += s[i++]; continue; }
        const n = s[i + 1];
        if (n === "x") { // \xHH (1-2 hex) → 字节，累积后按 UTF-8 解码
          let h = "", j = i + 2;
          while (h.length < 2 && /[0-9a-fA-F]/.test(s[j] || "")) h += s[j++];
          if (h) { bytes.push(parseInt(h, 16)); i = j; }
          else { flush(); cur += "x"; i += 2; }
        } else if (n >= "0" && n <= "7") { // \nnn 八进制字节
          let o = "", j = i + 1;
          while (o.length < 3 && /[0-7]/.test(s[j] || "")) o += s[j++];
          bytes.push(parseInt(o, 8) & 0xff); i = j;
        } else if (n === "u" || n === "U") { // \uHHHH / \UHHHHHHHH 码点
          flush();
          const len = n === "u" ? 4 : 8;
          cur += String.fromCodePoint(parseInt(s.slice(i + 2, i + 2 + len), 16) || 0);
          i += 2 + len;
        } else {
          flush();
          const map = { n: "\n", t: "\t", r: "\r", "'": "'", '"': '"', "\\": "\\", a: "\x07", b: "\b", f: "\f", v: "\v" };
          cur += (n in map) ? map[n] : n;
          i += 2;
        }
      }
      flush(); i++; continue;
    }
    if (c === '"') { // double-quote
      i++;
      while (i < s.length && s[i] !== '"') {
        if (s[i] === "\\" && '"\\$`'.includes(s[i + 1])) { cur += s[i + 1]; i += 2; }
        else cur += s[i++];
      }
      i++; continue;
    }
    if (c === "\\") { cur += s[i + 1] ?? ""; i += 2; continue; }
    cur += c; i++;
  }
  push();
  return toks;
}

function parseOneCurl(cmd) {
  const toks = tokenizeShell(cmd);
  let url = "", method = "", contentType = "";
  const headers = {};
  const dataParts = [];
  for (let i = 0; i < toks.length; i++) {
    let t = toks[i];
    if (t === "curl") continue;
    const val = () => toks[++i] ?? "";
    let inlineVal = null;
    if (t.startsWith("--") && t.includes("=")) { const k = t.slice(0, t.indexOf("=")); inlineVal = t.slice(t.indexOf("=") + 1); t = k; }
    if (t === "-X" || t === "--request") method = inlineVal ?? val();
    else if (t === "-H" || t === "--header") {
      const h = inlineVal ?? val();
      const ci = h.indexOf(":");
      if (ci > -1) {
        const name = h.slice(0, ci).trim(); const value = h.slice(ci + 1).trim();
        if (!name.startsWith(":")) { headers[name] = value; if (/^content-type$/i.test(name)) contentType = value; }
      }
    } else if (t === "-d" || t === "--data" || t === "--data-raw" || t === "--data-ascii" || t === "--data-binary" || t === "--data-urlencode") {
      dataParts.push(inlineVal ?? val());
    } else if (t === "-b" || t === "--cookie") {
      headers["Cookie"] = inlineVal ?? val();
    } else if (t === "--url") {
      url = inlineVal ?? val();
    } else if (t.startsWith("-")) {
      if (["-A", "--user-agent", "-e", "--referer", "-u", "--user", "--connect-timeout", "-m", "--max-time", "-x", "--proxy", "-o", "--output"].includes(t)) { if (inlineVal === null) val(); }
    } else if (!url) {
      const cleaned = t.replace(/^\^+|\^+$/g, ""); // 容错残留 caret
      if (/^https?:\/\//i.test(cleaned)) url = cleaned;
      else if (/^[a-z0-9.-]+\.[a-z]{2,}/i.test(cleaned)) url = "https://" + cleaned;
    }
  }
  return makeEntry({ url, method, bodyText: dataParts.join("&"), contentType, headers });
}

function parseCurl(text) {
  // Windows cmd 风格检测(^" / ^& / ^换行)→ 先 de-caret
  if (/\^"/.test(text) || /\^&/.test(text) || /\^\r?\n/.test(text)) text = stripCmdCarets(text);
  return splitCurlCommands(text).map(parseOneCurl).filter((e) => e.url);
}

// ─── JSON body（只有请求体） ──────────────────────────────────────
function parseJsonBody(text, apiUrl, method) {
  const data = JSON.parse(text);
  const arr = Array.isArray(data) ? data : [data];
  return arr.map((obj) => {
    const u = (obj && (obj._url || obj.url)) || apiUrl || "";
    const body = (obj && (obj._url || obj.url)) ? { ...obj } : obj;
    if (body && body._url) delete body._url;
    return makeEntry({ url: u, method: method || "POST", bodyText: JSON.stringify(body), contentType: "application/json" });
  });
}

// ─── JSONL 归一(重编码透传) ──────────────────────────────────────
function parseJsonl(text) {
  const out = [];
  for (const line of text.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let e;
    try { e = JSON.parse(t); } catch { continue; } // 跳过损坏行
    if (!e || typeof e !== "object") continue;
    const body = e.req_body ?? e.request_body ?? "";
    if (!e.url && !body) continue; // url/body 都没有 → 无用，跳过
    const reqBody = body ? pairsToReqBody(parsePairs(String(body))) : ""; // 重编码：字面 + → %2B
    const norm = { url: e.url || "", method: (e.method || (body ? "POST" : "GET")).toUpperCase(), req_body: reqBody };
    if (e.raw_body) norm.raw_body = e.raw_body;
    if (e.req_headers) norm.req_headers = e.req_headers;
    if (e.status !== undefined && e.status !== null) norm.status = e.status;
    if (e.res_body) norm.res_body = e.res_body;
    norm.ts = e.ts || Math.floor(Date.now() / 1000);
    out.push(norm);
  }
  return out;
}

// ─── 自动识别格式 ────────────────────────────────────────────────
function detectFormat(text) {
  // 整段是单个/数组 JSON？(HAR 也是 JSON)
  try {
    const j = JSON.parse(text);
    if (j?.log?.entries) return "har";
    return "json";
  } catch { /* not single json */ }
  // 含 curl(含 Windows cmd ^curl)
  if (/(^|\n|;|&&)\s*curl\b/.test(text)) return "curl";
  // 多行 JSON → jsonl(容忍损坏行：只要有一行像内部记录)
  const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
  let recordish = false;
  for (const l of lines) { try { const o = JSON.parse(l); if (o && (o.url || o.req_body || o.request_body)) { recordish = true; break; } } catch { /* skip */ } }
  if (recordish) return "jsonl";
  return "unknown";
}

// ─── CLI ─────────────────────────────────────────────────────────
function parseArgs() {
  const a = process.argv.slice(2);
  const o = { input: null, format: "auto", url: null, apiUrl: null, method: null, out: null };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === "--format") o.format = a[++i];
    else if (a[i] === "--url") o.url = a[++i];
    else if (a[i] === "--api-url") o.apiUrl = a[++i];
    else if (a[i] === "--method") o.method = a[++i];
    else if (a[i] === "--out") o.out = a[++i];
    else if (!a[i].startsWith("-")) o.input = a[i];
  }
  return o;
}

function readInput(inputPath) {
  if (inputPath) return readFileSync(inputPath, "utf8");
  try { return _rf(0, "utf8"); } catch { return ""; }
}

// 签名类字段名(容忍 _ / - 前缀)
const SIGN_RE = /^[_-]?(sign|signature|sig|token|hmac|hash|digest|nonce|_signature|wsgsig|mtgsig|x[-_]?s|a_?bogus|ms?token)/i;

function main() {
  const o = parseArgs();
  const text = readInput(o.input);
  if (!text.trim()) { console.error("❌ 无输入。传文件路径或用管道喂入。"); process.exit(1); }

  const fmt = o.format === "auto" ? detectFormat(text) : o.format;
  let entries = [];
  try {
    if (fmt === "har") entries = parseHar(text);
    else if (fmt === "curl") entries = parseCurl(text);
    else if (fmt === "json") entries = parseJsonBody(text, o.apiUrl, o.method);
    else if (fmt === "jsonl") entries = parseJsonl(text);
    else { console.error("❌ 无法识别格式（试试 --format har|curl|json|jsonl）"); process.exit(1); }
  } catch (e) {
    console.error(`❌ 解析失败 (format=${fmt}): ${e.message}`);
    process.exit(1);
  }

  if (o.url) entries = entries.filter((e) => (e.url || "").includes(o.url));
  if (fmt === "json" && entries.some((e) => !e.url)) {
    console.error("⚠️ JSON 体缺少接口 URL，请加 --api-url <接口地址>（或在对象里放 _url 字段）。");
  }

  const outPath = o.out
    ? (isAbsolute(o.out) ? o.out : join(PROJECT_ROOT, o.out))
    : join(PROJECT_ROOT, "captures", `imported-${Math.floor(Date.now() / 1000)}.jsonl`);
  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, entries.map((e) => JSON.stringify(e)).join("\n") + (entries.length ? "\n" : ""));

  const withSign = [];
  for (const e of entries) {
    const keys = (e.req_body || "").split("&").map((p) => { try { return decodeURIComponent(p.split("=")[0] || ""); } catch { return p.split("=")[0] || ""; } });
    const hit = keys.filter((k) => SIGN_RE.test(k));
    if (hit.length) withSign.push({ url: e.url, method: e.method, signFields: hit });
  }

  console.log(JSON.stringify({
    format: fmt,
    imported: entries.length,
    withSignFields: withSign.length,
    outputPath: outPath,
    signCandidates: withSign.slice(0, 10),
    next: withSign.length
      ? `node scripts/sign-crack.mjs ${outPath} --source static/unpacked/<appid> --patterns`
      : "未发现 sign 类字段；可手动指定 --sign-field 或核对抓包内容",
  }, null, 2));
}

main();
