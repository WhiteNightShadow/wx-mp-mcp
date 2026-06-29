/**
 * Module 2: crypto-locate — signing / encryption locator for unpacked WeChat mini programs.
 *
 * Goal: given an unpacked mini-program source tree (or an explicit list of .js files),
 * precisely locate signature/encryption LOGIC — far beyond `grep sign`.
 *
 * It answers, for an arbitrary program:
 *   - Does it sign requests at all?  (hasSigning + verdict)
 *   - Which crypto algorithms are really used (md5 / hmac-sha256 / sha256 / aes / rsa)?
 *   - Where are the sign FUNCTION DEFINITIONS (name, file, full source, algo, inputs)?
 *   - What is fed to the signature (appId / nonceStr / timestamp / body / key / secret ...)?
 *   - Where is the sign->request mount point (interceptor / header injection before wx.request)?
 *   - The complete sign-function source, ready for offline re-implementation.
 *
 * Tested on multiple mini-programs with signed (MD5 / HMAC-SHA256) and unsigned APIs.
 *
 * Design notes for the orchestrator:
 *   - Pure static analysis on minified webpack bundles. No AST dependency: we use
 *     brace-balanced slicing seeded from robust definition anchors, which survives the
 *     single-line minified bundles these packages ship as.
 *   - Files are deduplicated by content hash. WeChat ships near-identical twins
 *     (`app-service.js` vs `appservice.app.js`); we keep one representative and remember
 *     the aliases so we never double-count or double-report.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join, extname, relative } from "node:path";
import { createHash } from "node:crypto";

// ----------------------------------------------------------------------------
// File collection
// ----------------------------------------------------------------------------

/** Recursively collect *.js files under a directory. */
function collectJsFiles(dir, acc = []) {
  for (const ent of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, ent.name);
    if (ent.isDirectory()) collectJsFiles(full, acc);
    else if (ent.isFile() && extname(ent.name) === ".js") acc.push(full);
  }
  return acc;
}

/**
 * Normalize input into [{file, rel, text}], deduplicated by content hash.
 * Returns { units, aliases } where aliases maps kept-file -> [duplicate files].
 */
function loadUnits(input) {
  let files;
  let root = null;
  if (Array.isArray(input)) {
    files = input;
  } else {
    root = input;
    files = collectJsFiles(input);
  }

  const seen = new Map(); // contentHash -> kept file path
  const aliases = new Map();
  const units = [];
  for (const file of files) {
    let text;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const h = createHash("sha1").update(text).digest("hex");
    if (seen.has(h)) {
      const kept = seen.get(h);
      if (!aliases.has(kept)) aliases.set(kept, []);
      aliases.get(kept).push(file);
      continue;
    }
    seen.set(h, file);
    units.push({ file, rel: root ? relative(root, file) : file, text });
  }
  return { units, aliases };
}

// ----------------------------------------------------------------------------
// Brace-balanced body extraction (works on minified single-line bundles)
// ----------------------------------------------------------------------------

/**
 * From `text`, starting at the first `{` at or after `openSearchFrom`, return the
 * substring up to and including the matching `}`. String/escape aware. Caps at maxLen.
 */
function sliceBalanced(text, openSearchFrom, maxLen = 9000) {
  let i = text.indexOf("{", openSearchFrom);
  if (i === -1) return null;
  const start = i;
  let depth = 0;
  let inStr = null; // quote char
  let prev = "";
  const end = Math.min(text.length, start + maxLen);
  for (; i < end; i++) {
    const c = text[i];
    if (inStr) {
      if (c === inStr && prev !== "\\") inStr = null;
      prev = c === "\\" && prev === "\\" ? "" : c;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") {
      inStr = c;
      prev = c;
      continue;
    }
    if (c === "{") depth++;
    else if (c === "}") {
      depth--;
      if (depth === 0) return text.slice(start, i + 1);
    }
    prev = c;
  }
  return text.slice(start, end); // truncated
}

// ----------------------------------------------------------------------------
// Sign-function definition anchors
// ----------------------------------------------------------------------------

// Names that strongly indicate a signing routine when they appear as a DEFINITION.
// We anchor on definition syntax (`name=function`, `name:function`, `name=(args)=>`),
// NOT on bare mentions, which is what kills the "thousands of sign occurrences" noise.
const SIGN_NAME_RE =
  "(?:get_?[Ss]ign(?:[A-Za-z]*)?|_?sign(?:MD5|Md5|Hmac|HMAC|Data|String|Str|Params?|Parmas|Request|Req|Way|Config)?|cryptoMD5|cryptoSign|make_?[Ss]ign|create_?[Ss]ign|calc_?[Ss]ign|build_?[Ss]ign|gen_?[Ss]ign|encryptSign|signParamsHandler)";

// Names that are sign-LOOKING but are usually business logic, not crypto. Down-ranked
// unless the body actually contains a hash/crypto call.
const WEAK_NAME_RE =
  /^(getSignInfo|getSignInfoReq|getSigningInfo|signIn|signUp|signOut|signin|signup|signature$|designSign|signed?$)/i;

function buildDefRegex() {
  // capture group 1/2/3 = function name
  return new RegExp(
    "(?:" +
      // function NAME(
      "function\\s+(" + SIGN_NAME_RE + ")\\s*\\(" +
      "|" +
      // NAME = / NAME : [async] function (
      "(?:[\\.\\w$]*?\\b)(" + SIGN_NAME_RE + ")\\s*[:=]\\s*(?:async\\s+)?function\\s*\\(" +
      "|" +
      // NAME = / NAME : (args) => {   or   NAME = arg => {
      "(?:[\\.\\w$]*?\\b)(" + SIGN_NAME_RE + ")\\s*[:=]\\s*(?:async\\s+)?(?:\\([^)]*\\)|[\\w$]+)\\s*=>\\s*\\{" +
      ")",
    "g",
  );
}

// ----------------------------------------------------------------------------
// Algorithm detection from a function body (or any code snippet)
// ----------------------------------------------------------------------------

// Each entry: [label, INVOKED regex (an actual call/usage), weight].
// We deliberately match CALL forms (CryptoJS.X(, md5(, .HmacSHA256() ) rather than the
// bare identifier, because the bundled crypto-js library DEFINES every algorithm as an
// export (HmacSHA1, TripleDES, AES...) even when the app never calls them. Matching the
// definition would falsely report aes/des/hmac-sha1 for a program that only uses MD5.
const ALGO_SIGNATURES = [
  ["hmac-sha256", /(?:Crypto(?:JS)?\.)?HmacSHA256\s*\(|hmac[-_ ]?sha-?256/i, 5],
  ["hmac-sha1", /(?:Crypto(?:JS)?\.)?HmacSHA1\s*\(/i, 5],
  ["hmac-md5", /(?:Crypto(?:JS)?\.)?HmacMD5\s*\(/i, 5],
  // require an invocation (SHA256() / .SHA256() ) — a bare "sha256" string literal
  // (header name, comment, algorithm label) is not evidence the app computes it.
  ["sha256", /(?:Crypto(?:JS)?\.)?SHA256\s*\(/i, 3],
  ["sha1", /(?:Crypto(?:JS)?\.)?SHA1\s*\(/i, 2],
  // md5: CryptoJS.MD5(  | bare md5(  | minified default-import call (0,u.default)(f).toUpperCase
  // (when the module imports the `md5` npm package and stores it in `u`)
  ["md5", /(?:Crypto(?:JS)?\.)?MD5\s*\(|\bmd5\s*\(|\(0,\s*[a-z$_]\.default\)\s*\([^)]*\)\.toUpperCase|require\(["']md5["']\)/i, 3],
  ["aes", /(?:Crypto(?:JS)?\.)?AES\.(?:encrypt|decrypt)\s*\(|new\s+aesjs\b|aes-js|ModeOfOperation|AES_CBC_decrypt_buffer|AES_init_ctx/i, 4],
  ["des", /(?:Crypto(?:JS)?\.)?(?:TripleDES|DES)\.(?:encrypt|decrypt)\s*\(/i, 4],
  ["rsa", /\bJSEncrypt\b|setPublicKey\s*\(|setPrivateKey\s*\(|new\s+RSAKey\b|rsaBase64/i, 5],
  // RC4: 显式关键字, 或 PRGA 双 %256 + 交换(swap)的强特征。不靠裸 new Array(256)(误报多)。
  ["rc4", /\brc4\b|\bRC4\b|%\s*256\b[\s\S]{0,120}%\s*256\b/i, 3],
  ["base64", /CryptoJS\.enc\.Base64|sjcl\.codec\.base64/i, 1],
];

function detectAlgorithms(snippet) {
  const found = [];
  for (const [label, re, weight] of ALGO_SIGNATURES) {
    if (re.test(snippet)) found.push({ algo: label, weight });
  }
  return found;
}

/** Does this snippet contain any *real* crypto primitive (not just base64)? */
function hasRealCrypto(snippet) {
  return detectAlgorithms(snippet).some((a) => a.weight >= 2);
}

// ----------------------------------------------------------------------------
// CryptoJS / crypto-lib call extraction
// ----------------------------------------------------------------------------

function extractCryptoCalls(text) {
  const calls = new Map(); // call string -> count
  const re = /(?:CryptoJS|Crypto)\.(?:[A-Za-z0-9]+)(?:\.[A-Za-z0-9]+)?/g;
  let m;
  while ((m = re.exec(text))) calls.set(m[0], (calls.get(m[0]) || 0) + 1);
  return [...calls.entries()].map(([call, count]) => ({ call, count })).sort((a, b) => b.count - a.count);
}

// ----------------------------------------------------------------------------
// Input-parameter extraction from a sign-function body
// ----------------------------------------------------------------------------

// Canonical signing inputs and the surface forms we accept in minified code.
const INPUT_SIGNALS = [
  ["timestamp", /\b(?:time[sS]tamp|timeStamp|ts|_t|reqTime|currentTime)\b|new Date\)?\.getTime|Date\.now\(\)|toUTCString\(\)/],
  ["nonce", /\bnonce[sS]tr?\b|\bnonce\b|randomWord|randomStr|\bsalt\b/i],
  ["appId", /\bapp_?[iI]d\b/],
  ["appKey", /\bapp_?[kK]ey\b|accessKey|access_key|ACCESS_KEY/],
  ["secret", /\bsecret\b|app_?secret|ACCESS_SECRET|privateKey|\bkey\b\s*[:=)]/i],
  ["body", /\brequest[bB]ody\b|\bbody\b|JSON\.stringify|\bpayload\b|\bdata\b\s*[,)]/],
  ["url", /\bsignUrl\b|\.url\b|requestLine|request-line|POST |GET /],
  ["token", /\btoken\b|access_?token/i],
  ["version", /\bversion\b|\bappVersion\b|\b_v\b/i],
  ["method", /\bmethod\b|"POST"|"GET"/],
];

function extractInputs(body) {
  const inputs = [];
  for (const [name, re] of INPUT_SIGNALS) {
    if (re.test(body)) inputs.push(name);
  }
  return inputs;
}

/**
 * Try to recover the literal "signing string" template — the concatenation that is
 * actually hashed. Looks for "appId=".concat(...) chains, `appId=${...}` template
 * literals, or [...].join("&"). Returns {raw, skeleton} or null.
 */
function extractSignTemplate(body) {
  const concatChain = body.match(/"[^"]*?=?"\.concat\([^;]{0,400}?\)(?:\.concat\([^;]{0,400}?\))*/);
  if (concatChain) {
    const keys = [...concatChain[0].matchAll(/"([^"]*?=)"|"(&[^"]*?=)"/g)].map((m) => m[1] || m[2]).join("");
    return { raw: concatChain[0].slice(0, 300), skeleton: keys || null };
  }
  const tmpl = body.match(/`[^`]*\$\{[^`]{0,300}`/);
  if (tmpl) return { raw: tmpl[0].slice(0, 300), skeleton: tmpl[0].replace(/\$\{[^}]*\}/g, "{}").slice(0, 200) };
  const joined = body.match(/\[[^\]]{0,400}\]\.join\(["'][^"']*["']\)/);
  if (joined) return { raw: joined[0].slice(0, 300), skeleton: null };
  return null;
}

// ----------------------------------------------------------------------------
// Sign -> request linkage detection
// ----------------------------------------------------------------------------

function ctx(text, idx, span) {
  const a = Math.max(0, idx - span);
  return text.slice(a, idx + span).replace(/\s+/g, " ").trim();
}

/**
 * Find mount points where a sign value is attached to a request before wx.request.
 *   - interceptors.request.use(<fn>)                  (axios-style request interceptor)
 *   - Object.assign(header, {sign:..., nonceStr:...})  / header.sign = ...
 *   - data/params get a sign field
 */
function findRequestLinkage(unit) {
  const { text, rel } = unit;
  const links = [];

  // 1. interceptor registration
  for (const m of text.matchAll(/interceptors\.request\.use\(\s*([\w$.]+)\s*\)/g)) {
    links.push({ type: "request-interceptor", file: rel, handler: m[1], snippet: ctx(text, m.index, 80) });
  }

  // 2. header injection. Require a real signature key (sign/signature/nonceStr) — NOT
  // bare appId, which appears in countless SDK config objects (analytics projectId+appId).
  for (const m of text.matchAll(
    /Object\.assign\(\s*[\w$.]+(?:\|\|\s*\{\})?\s*,\s*\{[^}]*\b(?:sign|signature|nonceStr)\b[^}]*\}\s*\)/g,
  )) {
    if (!/\bsign\b|\bsignature\b/.test(m[0])) continue;
    links.push({ type: "header-assign", file: rel, snippet: m[0].slice(0, 200) });
  }
  for (const m of text.matchAll(/(?:header|headers)\s*(?:\[\s*["']sign["']\s*\]|\.sign)\s*=/g)) {
    links.push({ type: "header-field", file: rel, snippet: ctx(text, m.index, 80) });
  }

  // 3. sign written into data/params
  for (const m of text.matchAll(/\b(?:data|params)\.(?:sign|signature)\s*=/g)) {
    links.push({ type: "body-field", file: rel, snippet: ctx(text, m.index, 80) });
  }

  return links;
}

// ----------------------------------------------------------------------------
// 签名/加密【信号】检测 — 现代小程序的签名几乎都在拦截器/封装层/安全SDK里,
// 不在 wx.request 调用点的字面量上。靠"信号"识别比靠"函数名锚点"召回率高得多。
// 这是消除"对重度签名 app 误报无签名"假阴性的关键。
// ----------------------------------------------------------------------------

// 请求级签名开关(命中=该请求要签名,强信号)
const SIGN_FLAG_RE =
  /\buseSign(?:AndSiua)?\b|\bmtSecuritySign\b|\bmtSecuritySiua\b|\bmustSign\b|\bneedSign\b|\bsignWay\b/;

// 安全 SDK【强信号】:几乎只在业务请求签名/反爬里出现,误报率低
const SECURITY_SDK_STRONG_RE =
  /\bsignWithSiua\b|\bgetSiua\b|\bjsGuardInstant\b|\bH5Guard\b|@mtfe\/wx-?jsguard|\bwx-?jsguard\b|\byodaReady\b|finger\.sign|aes\.wasm|AES_CBC_decrypt_buffer|AES_init_ctx/;

// 安全 SDK【弱信号】:也可能是第三方 SDK 自用(QQ地图 getSig、图像处理 WASM 等),只提示 verify
const SECURITY_SDK_WEAK_RE =
  /\bgetSig\b|WXWebAssembly|\byoda\b|\bSiua\b/;

// 签名 header 字段名(出现在 header 构造里 = 请求被签名)
const SIGN_HEADER_KEY_RE =
  /["'`](?:x[-_]?ca[-_]?sign|x[-_]?sign|sign|signature|nonce[-_]?str|Operation-Type|x[-_]?ca[-_]?key|x[-_]?ca[-_]?nonce|x[-_]?ca[-_]?timestamp|MOLE)["'`]\s*:/i;

// 响应体解密 / 请求体整体加密(body-encrypted 模式)
const BODY_CRYPTO_RE =
  /\bAES\.decrypt\s*\(|\bdecrypt(?:Data|Resp|Response)?\s*\(|\bjiemi\b|["'`]encrypted["'`]\s*:|\.encrypted\b|encryptedData2?\b|rsaBase64|\.encrypt\s*\([^)]*(?:mobile|phone|passwd|password|pwd)/i;

/**
 * 扫描一个 unit,返回签名/加密【信号】列表。每条 {kind, signal, file, snippet}。
 * kind: sign-flag | security-sdk | sign-header | body-crypto | interceptor-crypto
 */
function findSigningSignals(unit) {
  const { text, rel } = unit;
  const signals = [];
  const push = (kind, m, signal) =>
    signals.push({ kind, signal: signal || m[0].slice(0, 60), file: rel, snippet: ctx(text, m.index, 70) });

  for (const m of text.matchAll(new RegExp(SIGN_FLAG_RE, "g"))) push("sign-flag", m);
  for (const m of text.matchAll(new RegExp(SECURITY_SDK_STRONG_RE, "g"))) push("security-sdk", m);
  for (const m of text.matchAll(new RegExp(SECURITY_SDK_WEAK_RE, "g"))) push("security-sdk-weak", m);
  for (const m of text.matchAll(new RegExp(SIGN_HEADER_KEY_RE, "gi"))) push("sign-header", m);
  for (const m of text.matchAll(new RegExp(BODY_CRYPTO_RE, "gi"))) push("body-crypto", m);

  // 拦截器体内含 crypto/sign → 强信号(签名在拦截器里算)
  for (const m of text.matchAll(/interceptors\.request\.use\(/g)) {
    const body = sliceBalanced(text, m.index + m[0].length, 4000) || "";
    if (/\bsign|HmacSHA|\.MD5\(|AES\.|x[-_]?ca[-_]?sign|nonce|timestamp/i.test(body)) {
      push("interceptor-crypto", m, "interceptors.request.use{…crypto/sign…}");
    }
  }
  return signals;
}

// ----------------------------------------------------------------------------
// Main locator
// ----------------------------------------------------------------------------

/**
 * Locate signing / encryption logic in an unpacked mini-program.
 *
 * @param {string|string[]} input  Either a source directory (recursively scanned for
 *   *.js) or an explicit array of .js file paths.
 * @returns {Promise<{
 *   hasSigning: boolean,
 *   verdict: string,
 *   algorithms: {algo:string, weight:number}[],
 *   signFunctions: {name:string, file:string, algo:string[], inputs:string[],
 *                   signTemplate:object|null, source:string, sourceLen:number, score:number}[],
 *   requestSignLinkage: object[],
 *   cryptoLibs: {lib:string}[],
 *   cryptoCalls: {call:string, count:number}[],
 *   stats: object,
 * }>}
 */
export async function locateCrypto(input) {
  const { units, aliases } = loadUnits(input);
  const defRe = buildDefRegex();

  const signFunctions = [];
  const requestSignLinkage = [];
  const signingSignals = [];
  const algoTally = new Map();
  const cryptoCallTally = new Map();
  const cryptoLibs = new Set();
  let totalSignWord = 0;

  for (const unit of units) {
    const { text } = unit;
    totalSignWord += (text.match(/sign/gi) || []).length;

    // 签名/加密信号(拦截器/封装层/安全SDK/响应解密) — 比函数名锚点召回率高
    for (const s of findSigningSignals(unit)) signingSignals.push(s);

    // crypto libraries actually imported
    if (/require\(["']crypto-js["']\)|\bCryptoJS\b/.test(text)) cryptoLibs.add("crypto-js");
    if (/require\(["']md5["']\)|__importDefault\(\w+\(["']md5["']\)\)/.test(text)) cryptoLibs.add("md5(npm)");
    if (/require\(["']js-?sha256["']\)/.test(text)) cryptoLibs.add("js-sha256");
    if (/\bJSEncrypt\b/.test(text)) cryptoLibs.add("jsencrypt");
    if (/require\(["']jsbn["']\)|\bRSAKey\b/.test(text)) cryptoLibs.add("jsbn/rsa");

    // CryptoJS call inventory
    for (const c of extractCryptoCalls(text)) {
      cryptoCallTally.set(c.call, (cryptoCallTally.get(c.call) || 0) + c.count);
    }

    // request linkage
    for (const l of findRequestLinkage(unit)) requestSignLinkage.push(l);

    // sign function definitions
    defRe.lastIndex = 0;
    let m;
    const seenBodies = new Set();
    while ((m = defRe.exec(text))) {
      const name = m[1] || m[2] || m[3];
      if (!name) continue;
      const body = sliceBalanced(text, m.index + name.length, 9000);
      if (!body || body.length < 12) continue;
      const bodyKey = name + ":" + body.length + ":" + body.slice(0, 40);
      if (seenBodies.has(bodyKey)) continue;
      seenBodies.add(bodyKey);

      // 捕获形参列表(在 name 与 body 起始的 '{' 之间), 以便重建完整可移植的函数声明。
      // preamble 形如: "(e,t)" | "=function(e,t)" | ":function(e,t)" | "=(e,t)=>" | "=e=>"
      const braceIdx = text.indexOf("{", m.index + name.length);
      const preamble = braceIdx > -1 ? text.slice(m.index + name.length, braceIdx) : "";
      let params = "";
      const paren = preamble.match(/\(([^)]*)\)/);
      if (paren) params = paren[1].trim();
      else {
        const arrow1 = preamble.match(/[:=]\s*([\w$]+)\s*=>/); // 单参箭头无括号
        if (arrow1) params = arrow1[1];
      }
      // 规范化为独立函数声明: function NAME(params){body} —— 避免裸 body 顶层 return 非法
      const declaration = `function ${name}(${params}) ${body}`;

      const algos = detectAlgorithms(body).map((a) => a.algo);
      const inputs = extractInputs(body);
      const isWeak = WEAK_NAME_RE.test(name);
      const realCrypto = hasRealCrypto(body);

      // Scoring: a *real* sign function has a crypto primitive AND signing inputs.
      let score = 0;
      if (realCrypto) score += 5;
      score += Math.min(inputs.length, 4);
      if (/\b(?:nonce|appId|secret|key)\b/i.test(inputs.join(","))) score += 1;
      if (isWeak && !realCrypto) score -= 6;
      if (/^(?:signMD5|cryptoMD5|signParamsHandler|getSignParmas)$/.test(name)) score += 4;

      if (realCrypto || score >= 3) {
        signFunctions.push({
          name,
          file: unit.rel,
          algo: algos,
          inputs,
          params,
          signTemplate: extractSignTemplate(body),
          // source = 完整函数声明(保留全文以便移植; 截断会破坏括号配平导致语法错)
          source: declaration,
          sourceLen: declaration.length,
          score,
        });
        for (const a of detectAlgorithms(body)) algoTally.set(a.algo, a.weight);
      }
    }
  }

  // Fold in algorithms from ACTUAL invocations across the bundle (call-form regex, so
  // bundled-library definitions never leak in), e.g. inline HTTP-signature digest+Hmac.
  for (const unit of units) {
    for (const a of detectAlgorithms(unit.text)) {
      if (!algoTally.has(a.algo)) algoTally.set(a.algo, a.weight);
    }
  }

  // de-dup + rank sign functions; collapse exact-duplicate bodies that survived twins
  const uniq = [];
  const bodySeen = new Set();
  for (const f of signFunctions.sort((a, b) => b.score - a.score)) {
    const k = f.name + "|" + f.sourceLen + "|" + f.source.slice(0, 60);
    if (bodySeen.has(k)) continue;
    bodySeen.add(k);
    uniq.push(f);
  }

  const algorithms = [...algoTally.entries()]
    .map(([algo, weight]) => ({ algo, weight }))
    .sort((a, b) => b.weight - a.weight);

  const cryptoCalls = [...cryptoCallTally.entries()]
    .map(([call, count]) => ({ call, count }))
    .sort((a, b) => b.count - a.count);

  // ── 信号聚合(对抗验证后新增:现代小程序签名几乎都在拦截器/封装层/安全SDK) ──
  const signalKinds = new Set(signingSignals.map((s) => s.kind));
  const interceptorSigns = requestSignLinkage.some(
    (l) => l.type === "request-interceptor" && /sign|crypto|auth/i.test(l.handler || ""),
  ) || signalKinds.has("interceptor-crypto");
  const headerInjectsSign = requestSignLinkage.some(
    (l) => l.type === "header-assign" || l.type === "header-field" || l.type === "body-field",
  ) || signalKinds.has("sign-header");
  const hasSecuritySdk = signalKinds.has("security-sdk");
  const hasSignFlag = signalKinds.has("sign-flag");
  const hasBodyCrypto = signalKinds.has("body-crypto");
  const hasSignFn = uniq.some((f) => f.score >= 5);

  // 强信号任一命中 → 判定有签名/加密(消除"重度签名却报无签名"的假阴性)
  const hasSigning =
    hasSignFn || interceptorSigns || headerInjectsSign || hasSecuritySdk || hasSignFlag;
  // body 整体加密(响应解密/请求体字段加密)单列:即便无签名也属"需还原加密"
  const hasEncryption = hasBodyCrypto || algorithms.some((a) => ["aes", "des", "rsa", "rc4"].includes(a.algo) && a.weight >= 3 && (hasSignFn || hasSecuritySdk || hasBodyCrypto));

  // 信号摘要(给人看为什么判有签名)
  const sigSummary = [];
  if (hasSignFn) sigSummary.push(`${uniq.length}个签名函数`);
  if (hasSecuritySdk) sigSummary.push(`安全SDK[${[...new Set(signingSignals.filter((s) => s.kind === "security-sdk").map((s) => s.signal))].slice(0, 4).join("/")}]`);
  if (hasSignFlag) sigSummary.push(`签名开关[${[...new Set(signingSignals.filter((s) => s.kind === "sign-flag").map((s) => s.signal))].slice(0, 3).join("/")}]`);
  if (signalKinds.has("interceptor-crypto")) sigSummary.push("拦截器内签名");
  if (headerInjectsSign) sigSummary.push("签名header");
  if (hasBodyCrypto) sigSummary.push("body加密/响应解密");

  let verdict;
  if (hasSigning) {
    verdict =
      `SIGNED — 命中: ${sigSummary.join(", ") || "签名信号"}; 算法: ${algorithms.map((a) => a.algo).join(", ") || "n/a"}; ` +
      `${signingSignals.length}个签名信号/${requestSignLinkage.length}个挂载点。` +
      (hasSignFn ? "复现需移植列出的 signFunctions。" : "签名在拦截器/封装层/安全SDK,签名函数未直接抽到——见 signingSignals 指向的文件人工定位。") +
      (hasBodyCrypto ? " ⚠️ 另检出 body 加密/响应解密,需一并还原。" : "");
  } else if (hasBodyCrypto) {
    verdict = `ENCRYPTED(可能无签名但有加解密) — 检出 body 加密/响应解密(${algorithms.map((a) => a.algo).join(", ")}); 见 signingSignals。复现需还原加解密逻辑。`;
  } else if (algorithms.length === 0) {
    verdict = "NO SIGNING — 无加密原语/签名函数/签名信号。请求可直接复现(填 url+data 即可)。";
  } else {
    verdict = `LIKELY UNSIGNED — 检出加密原语(${algorithms.map((a) => a.algo).join(", ")})但无签名挂载信号,疑为第三方SDK(地图/OAuth)自用,非业务请求签名。建议人工抽查 1-2 个请求确认。`;
  }

  return {
    hasSigning,
    hasEncryption: hasBodyCrypto,
    verdict,
    algorithms,
    signFunctions: uniq,
    requestSignLinkage,
    signingSignals,
    cryptoLibs: [...cryptoLibs].map((lib) => ({ lib })),
    cryptoCalls,
    stats: {
      filesScanned: units.length,
      duplicateFilesSkipped: [...aliases.values()].reduce((n, a) => n + a.length, 0),
      rawSignWordOccurrences: totalSignWord,
      signFunctionsFound: uniq.length,
      signingSignals: signingSignals.length,
    },
  };
}

export default locateCrypto;