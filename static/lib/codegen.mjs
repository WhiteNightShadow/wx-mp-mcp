// codegen.mjs — Module 3: 微信小程序接口复现代码生成
// 导出 extractApis(jsFiles) 与 generateReproCode(apiList, signInfo, {lang})。
// 主 CLI 直接 import 即可;无 main()。
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

// ───────────────────────── helpers ─────────────────────────

function listJsFiles(dir) {
  const out = [];
  for (const f of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, f.name);
    if (f.isDirectory()) out.push(...listJsFiles(full));
    else if (f.name.endsWith(".js")) out.push(full);
  }
  return out;
}

// jsFiles 可为: 目录路径(字符串) / 路径数组 / {path,code} 对象数组
function normalizeFiles(jsFiles) {
  if (!jsFiles || jsFiles.length === 0) return [];
  // 单个目录路径字符串 → 递归展开
  if (typeof jsFiles === "string") {
    try {
      if (statSync(jsFiles).isDirectory()) {
        return listJsFiles(jsFiles).map((f) => ({ path: f, code: readFileSync(f, "utf8") }));
      }
      return [{ path: jsFiles, code: readFileSync(jsFiles, "utf8") }];
    } catch { return []; }
  }
  if (typeof jsFiles[0] === "string") {
    const expanded = [];
    for (const p of jsFiles) {
      try {
        if (statSync(p).isDirectory()) {
          for (const f of listJsFiles(p)) expanded.push({ path: f, code: readFileSync(f, "utf8") });
        } else {
          expanded.push({ path: p, code: readFileSync(p, "utf8") });
        }
      } catch { /* skip unreadable */ }
    }
    return expanded;
  }
  return jsFiles.map((f) => ({ path: f.path || f.file || "?", code: f.code ?? readFileSync(f.path || f.file, "utf8") }));
}

// 从 openIdx(指向 '{')起配平大括号
function matchBraces(src, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < src.length; i++) {
    const c = src[i];
    if (c === "{") depth++;
    else if (c === "}") { depth--; if (depth === 0) return src.slice(openIdx, i + 1); }
  }
  return src.slice(openIdx);
}

// 收集顶层 var X="https://..." 这类 base-URL 绑定
function collectBaseVars(code) {
  const vars = {};
  const re = /\b([A-Za-z_$][\w$]*)\s*=\s*["'`](https?:\/\/[^"'`]+)["'`]/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    if (!vars[m[1]]) vars[m[1]] = m[2];
  }
  return vars;
}

// 解析 URL 表达式:  "".concat(d).concat(e) | "".concat(t,"/api/x")
//   | "".concat(base,"/api/chat/").concat(id) | "/api/x" | x
// → { template(含 {占位}), dynamicSegs, baseVar, raw }
function resolveUrlExpr(expr, baseVars, baseAliasNames, code, atIdx) {
  expr = expr.trim();
  let lit = expr.match(/^["'`]([^"'`]*)["'`]$/);
  if (lit) return { template: lit[1], dynamicSegs: [], baseVar: null, raw: expr };

  // 裸标识符:尝试在同文件解析 x="".concat(...) 或三元赋值(取第一分支)
  if (/^[A-Za-z_$][\w$]*$/.test(expr) && code) {
    const assignRe = new RegExp("\\b" + expr.replace(/\$/g, "\\$") + "\\s*=\\s*(\"\"\\.concat\\([\\s\\S]{0,200}?\\))(?=[,;)])", "g");
    let best = null, am;
    while ((am = assignRe.exec(code)) !== null) { if (atIdx == null || am.index < atIdx) best = am[1]; }
    if (best) { const r = resolveUrlExpr(best, baseVars, baseAliasNames); r.raw = expr + " = " + best; return r; }
    const ternRe = new RegExp("\\b" + expr.replace(/\$/g, "\\$") + "\\s*=\\s*[^?;]{0,40}\\?\\s*(\"\"\\.concat\\([\\s\\S]{0,160}?\\))\\s*:", "g");
    let tm, tbest = null;
    while ((tm = ternRe.exec(code)) !== null) { if (atIdx == null || tm.index < atIdx) tbest = tm[1]; }
    if (tbest) { const r = resolveUrlExpr(tbest, baseVars, baseAliasNames); r.raw = expr + " (三元,取第一分支) = " + tbest; return r; }
  }

  // .concat() 链:逐 concat 配平括号取参(可处理 getApp().globalData.baseUrl)
  if (/\.concat\(/.test(expr) || /^["'`]/.test(expr)) {
    const pieces = [];
    const lead = expr.match(/^["'`]([^"'`]*)["'`]/);
    if (lead) pieces.push({ type: "str", v: lead[1] });
    let pos = 0;
    while ((pos = expr.indexOf(".concat(", pos)) !== -1) {
      const argStart = pos + ".concat(".length;
      let depth = 1, j = argStart, q = null;
      for (; j < expr.length; j++) {
        const c = expr[j];
        if (q) { if (c === q) q = null; continue; }
        if (c === '"' || c === "'" || c === "`") { q = c; continue; }
        if (c === "(") depth++;
        else if (c === ")") { depth--; if (depth === 0) break; }
      }
      const argStr = expr.slice(argStart, j);
      pos = j + 1;
      for (const arg of splitArgs(argStr)) {
        const a = arg.trim();
        const sl = a.match(/^["'`]([^"'`]*)["'`]$/);
        if (sl) pieces.push({ type: "str", v: sl[1] });
        else pieces.push({ type: "var", v: a });
      }
    }
    return assemblePieces(pieces, baseVars, baseAliasNames, expr);
  }

  if (baseVars[expr]) return { template: baseVars[expr], dynamicSegs: [], baseVar: expr, raw: expr };
  return { template: "{URL_EXPR}", dynamicSegs: [{ name: "URL_EXPR", src: expr }], baseVar: null, raw: expr };
}

// 顶层逗号切分(尊重引号与括号深度)
function splitArgs(s) {
  const out = []; let depth = 0, cur = "", q = null;
  for (const c of s) {
    if (q) { cur += c; if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === "`") { q = c; cur += c; continue; }
    if (c === "(" || c === "[") depth++;
    if (c === ")" || c === "]") depth--;
    if (c === "," && depth === 0) { out.push(cur); cur = ""; continue; }
    cur += c;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

function assemblePieces(pieces, baseVars, baseAliasNames, raw) {
  let template = "", baseVar = null;
  const dynamicSegs = [];
  for (let i = 0; i < pieces.length; i++) {
    const p = pieces[i];
    if (p.type === "str") { template += p.v; continue; }
    const isFirstVar = (i === 0 || (i === 1 && pieces[0].type === "str" && pieces[0].v === ""));
    const next = pieces[i + 1];
    const nextIsPath = next && next.type === "str" && next.v.startsWith("/");
    // 首个变量片段:名字含 base/host 或紧跟 "/..." 字面量 → 判为 base URL
    const looksLikeBase = baseVars[p.v] || baseAliasNames.has(p.v) || /baseUrl|baseURL|host|domain/i.test(p.v) || (isFirstVar && nextIsPath);
    if (isFirstVar && looksLikeBase) {
      if (baseVars[p.v]) { baseVar = p.v; template += baseVars[p.v]; continue; }
      baseVar = p.v; template += "{BASE_URL}"; continue;
    }
    const name = guessParamName(p.v, template);
    template += "{" + name + "}";
    dynamicSegs.push({ name, src: p.v });
  }
  return { template, dynamicSegs, baseVar, raw };
}

function guessParamName(varExpr, templateSoFar) {
  const tail = templateSoFar.match(/\/([A-Za-z_-]+)\/?$/);
  if (tail) return tail[1].replace(/-/g, "_") + "_id";
  const id = varExpr.match(/([A-Za-z_$][\w$]*)$/);
  return (id ? id[1] : "param");
}

// header 对象片段 → {name:{value,source,note,raw}}
function parseHeaders(headerBlock) {
  const headers = {};
  if (!headerBlock) return headers;
  const inner = headerBlock.replace(/^\{/, "").replace(/\}$/, "");
  for (const part of splitArgs(inner)) {
    const kv = part.match(/^\s*["'`]?([\w-]+)["'`]?\s*:\s*([\s\S]+)$/);
    if (!kv) continue;
    headers[kv[1]] = classifyHeaderValue(kv[1], kv[2].trim());
  }
  return headers;
}

function classifyHeaderValue(key, val) {
  const lit = val.match(/^["'`]([^"'`]*)["'`]$/);
  if (lit) return { value: lit[1], source: "static" };
  if (/Bearer/.test(val) || /token/i.test(val)) return { value: null, source: "user", note: "Bearer token", raw: val };
  if (/sign/i.test(val)) return { value: null, source: "sign", raw: val };
  if (/nonce/i.test(val)) return { value: null, source: "computed", note: "nonce", raw: val };
  if (/(timestamp|timeStamp|Date\.now|getTime)/i.test(val)) return { value: null, source: "computed", note: "timestamp", raw: val };
  return { value: null, source: "dynamic", raw: val };
}

// data:{...} → 字段来源映射;非对象表达式记为 {_raw,_source}
function parseData(dataExpr) {
  if (!dataExpr) return null;
  const t = dataExpr.trim();
  if (!t.startsWith("{")) return { _raw: t, _source: "dynamic" };
  const fields = {};
  const inner = matchBraces(t, 0).replace(/^\{/, "").replace(/\}$/, "");
  for (const part of splitArgs(inner)) {
    const kv = part.match(/^\s*["'`]?([\w$]+)["'`]?\s*:\s*([\s\S]+)$/);
    if (!kv) continue;
    const k = kv[1], v = kv[2].trim();
    const lit = v.match(/^["'`]([^"'`]*)["'`]$/);
    const num = v.match(/^-?\d+(\.\d+)?$/);
    if (lit) fields[k] = { example: lit[1], source: "static" };
    else if (num) fields[k] = { example: Number(v), source: "static" };
    else if (/sign/i.test(v)) fields[k] = { example: null, source: "sign", raw: v };
    else if (/nonce/i.test(v)) fields[k] = { example: null, source: "computed", raw: v };
    else if (/(timestamp|Date\.now)/i.test(v)) fields[k] = { example: null, source: "computed", raw: v };
    else fields[k] = { example: null, source: "user", raw: v };
  }
  return fields;
}

// ───────────────────────── extractApis ─────────────────────────

/**
 * 从解包后的 JS 抽取结构化 API 清单。
 * @param {Array<string>|Array<{path,code}>} jsFiles 路径数组/目录/对象数组
 * @returns {Array<Object>} 每项: { file, urlTemplate, baseUrl, method, dynamicSegs, headers, data, signRefs, enableChunked, raw }
 */
export function extractApis(jsFiles) {
  const files = normalizeFiles(jsFiles);
  const globalBaseVals = {};
  const baseAliasNames = new Set(["baseUrl", "baseURL", "BASE_URL", "host", "apiHost", "domain"]);
  for (const { code } of files) {
    const bv = collectBaseVars(code);
    for (const k of Object.keys(bv)) { globalBaseVals[k] = bv[k]; baseAliasNames.add(k); }
  }
  // globalData.baseUrl=X → 封装层 url 的真实 origin
  let wrapperBaseUrl = null;
  for (const { code } of files) {
    const m = code.match(/baseUrl\s*:\s*([A-Za-z_$][\w$]*)\b/);
    if (m && globalBaseVals[m[1]]) wrapperBaseUrl = globalBaseVals[m[1]];
  }

  const apis = [];
  const seen = new Set();
  const addEntry = (entry) => {
    if (!entry) return;
    const key = entry.method + " " + entry.urlTemplate;
    if (seen.has(key)) return;
    seen.add(key);
    apis.push(entry);
  };

  for (const { path, code } of files) {
    const baseVars = { ...globalBaseVals };

    // Pass 1: 字面量 wx.request({...}) — 高精度
    let idx = 0;
    while ((idx = code.indexOf("wx.request(", idx)) !== -1) {
      const braceStart = code.indexOf("{", idx);
      if (braceStart === -1) break;
      const obj = matchBraces(code, braceStart);
      idx = braceStart + obj.length;
      addEntry(parseRequestObject(obj, baseVars, baseAliasNames, wrapperBaseUrl, path, code, braceStart));
    }

    // Pass 2: 封装层 + 配置对象端点。现代小程序几乎都把请求经自定义封装(bridge.request /
    // requestSdk.wxRequest / axios v.request)发出, 端点以 {url:"/api/...", method:"post"}
    // 形式定义。扫描所有 url:<路径字面量>, 捕获其所在的小对象作为请求配置。
    for (const m of code.matchAll(/\burl\s*:\s*(["'`])((?:\/|https?:\/\/)[^"'`]{2,200})\1/g)) {
      const urlLit = m[2];
      // 端点过滤: 必须像 API 路径(含路径分隔/含 api|v\d|cgi 等), 排除静态资源/图片
      if (/\.(png|jpe?g|gif|svg|webp|css|woff2?|ttf|ico|mp4|mp3)$/i.test(urlLit)) continue;
      const looksApi = /^https?:\/\//.test(urlLit) || /^\/[\w]/.test(urlLit);
      if (!looksApi) continue;
      // 取该 url 所在的最近对象 {...}
      const objStart = code.lastIndexOf("{", m.index);
      if (objStart === -1) continue;
      const obj = matchBraces(code, objStart);
      // 对象需在合理大小内且确实包含此 url(避免跨对象误配)
      if (obj.length > 4000 || !obj.includes(urlLit)) {
        // 退化: 仅按 url 字面量产出一个最小条目
        addEntry(makeMinimalEntry(urlLit, path, wrapperBaseUrl));
        continue;
      }
      const entry = parseRequestObject(obj, baseVars, baseAliasNames, wrapperBaseUrl, path, code, objStart);
      if (entry) addEntry(entry);
      else addEntry(makeMinimalEntry(urlLit, path, wrapperBaseUrl));
    }
  }
  return apis;
}

/** 仅从 url 字面量产出最小 API 条目(配置对象无 method/data 时的退化路径)。 */
function makeMinimalEntry(urlLit, file, wrapperBaseUrl) {
  const isAbs = /^https?:\/\//.test(urlLit);
  const urlTemplate = isAbs ? urlLit : (wrapperBaseUrl ? wrapperBaseUrl + urlLit : "{BASE_URL}" + urlLit);
  return {
    file, urlTemplate, baseUrl: isAbs ? null : (wrapperBaseUrl || null),
    method: "POST", // 封装层端点多为 POST; 仅作占位, 注释提示核对
    dynamicSegs: [], headers: {}, data: null, signRefs: [],
    enableChunked: false, raw: { url: urlLit, note: "配置对象/封装层端点(method默认POST,请核对)" },
  };
}

function fieldAfter(obj, key) {
  const re = new RegExp("(?:^|[,{\\s])" + key + "\\s*:\\s*", "g");
  let m;
  while ((m = re.exec(obj)) !== null) return readValue(obj, m.index + m[0].length);
  return null;
}

function readValue(obj, start) {
  let i = start;
  while (i < obj.length && /\s/.test(obj[i])) i++;
  if (obj[i] === "{") return matchBraces(obj, i);
  let depth = 0, q = null, out = "";
  for (; i < obj.length; i++) {
    const c = obj[i];
    if (q) { out += c; if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === "`") { q = c; out += c; continue; }
    if (c === "(" || c === "{" || c === "[") depth++;
    if (c === ")" || c === "}" || c === "]") { if (depth === 0) break; depth--; }
    if (c === "," && depth === 0) break;
    out += c;
  }
  return out.trim();
}

function parseRequestObject(obj, baseVars, baseAliasNames, wrapperBaseUrl, file, code, atIdx) {
  const urlExpr = fieldAfter(obj, "url");
  if (!urlExpr) return null;
  const methodExpr = fieldAfter(obj, "method");
  const headerExpr = fieldAfter(obj, "header");
  const dataExpr = fieldAfter(obj, "data");

  const resolved = resolveUrlExpr(urlExpr, baseVars, baseAliasNames, code, atIdx);
  let urlTemplate = resolved.template;
  let baseUrl = resolved.baseVar ? baseVars[resolved.baseVar] || wrapperBaseUrl : null;

  // 封装层 "".concat(d).concat(e):d=globalData.baseUrl, e=传入路径
  if (resolved.raw && /concat\([a-z]\)\.concat\([a-z]\)/.test(resolved.raw.replace(/\s/g, ""))) {
    baseUrl = wrapperBaseUrl;
    urlTemplate = (baseUrl || "{BASE_URL}") + "{PATH}";
    resolved.dynamicSegs = [{ name: "PATH", src: "wrapper path arg" }];
  } else if (urlTemplate.includes("{BASE_URL}")) {
    if (wrapperBaseUrl) { urlTemplate = urlTemplate.replace("{BASE_URL}", wrapperBaseUrl); baseUrl = wrapperBaseUrl; }
    else baseUrl = null; // 留 {BASE_URL} 让用户填
  }

  const method = (methodExpr && methodExpr.match(/["'`]([A-Z]+)["'`]/)?.[1]) || "GET";
  const headers = parseHeaders(headerExpr);
  const data = parseData(dataExpr);

  const signRefs = [];
  for (const [k, v] of Object.entries(headers)) if (v.source === "sign") signRefs.push({ in: "header", name: k, raw: v.raw });
  if (data && !data._raw) for (const [k, v] of Object.entries(data)) if (v.source === "sign") signRefs.push({ in: "data", name: k, raw: v.raw });

  return {
    file, urlTemplate, baseUrl, method,
    dynamicSegs: resolved.dynamicSegs, headers, data, signRefs,
    enableChunked: /enableChunked\s*:\s*!?0|enableChunked\s*:\s*true/.test(obj),
    raw: { url: urlExpr },
  };
}

// ───────────────────────── generateReproCode ─────────────────────────

/**
 * 生成可运行复现代码。
 * @param {Array<Object>|Object} apiList  extractApis 输出(或子集/单项)
 * @param {Object|null} signInfo  模块2 提供:
 *   { transplantable:boolean, lang:{node?:string, python?:string},
 *     fnName:string, callExpr?:string, callExprPython?:string, note?:string }
 * @param {{lang:'node'|'python'}} opts
 * @returns {string}
 */
export function generateReproCode(apiList, signInfo, { lang = "node" } = {}) {
  if (!Array.isArray(apiList)) apiList = [apiList];
  return lang === "python" ? genPython(apiList, signInfo) : genNode(apiList, signInfo);
}

function placeholdersFor(api, signInfo) {
  const ph = [];
  // base URL 未解析时,声明 BASE_URL 占位(Node ${BASE_URL} / Python f"{BASE_URL}")
  if ((api.urlTemplate || "").includes("{BASE_URL}")) {
    ph.push({ key: "BASE_URL", comment: "接口根地址 (源码未能静态解析, 请填真实 origin, 如 https://api.example.com)" });
  }
  const hasSign = (api.signRefs && api.signRefs.length) ||
    Object.values(api.headers || {}).some((v) => v.source === "sign") ||
    (api.data && !api.data._raw && Object.values(api.data).some((v) => v.source === "sign"));
  if (hasSign && signInfo && signInfo.transplantable) {
    const exprs = [signInfo.callExpr, signInfo.callExprPython].filter(Boolean).join(" ");
    for (const cm of exprs.matchAll(/\b([A-Z][A-Z0-9_]{2,})\b/g)) {
      if (cm[1] === "TODO_SIGN") continue;
      ph.push({ key: cm[1], comment: "签名所需常量/随机值 (来源: 签名函数入参, 例如 nonce/appSecret)" });
    }
  }
  for (const seg of api.dynamicSegs || []) {
    if (seg.name === "PATH") ph.push({ key: "API_PATH", comment: "请求路径 (来源: 运行时由调用方传入 wx.request 封装, 例如 /api/quota)" });
    else ph.push({ key: seg.name.toUpperCase(), comment: `路径动态段 (来源代码变量: ${seg.src})` });
  }
  for (const [k, v] of Object.entries(api.headers || {})) {
    if (v.source === "user") ph.push({ key: "TOKEN", comment: `用户态: ${v.note || "登录后获得的 token"} (header ${k})` });
  }
  if (api.data && !api.data._raw) {
    for (const [k, v] of Object.entries(api.data)) {
      if (v.source === "user") ph.push({ key: "DATA_" + k.toUpperCase(), comment: `请求体字段 ${k} (用户填: 代码变量 ${v.raw || "?"})` });
    }
  }
  const seen = new Set();
  return ph.filter((p) => !seen.has(p.key) && seen.add(p.key));
}

// ---------- Node 生成 ----------
function genNode(apiList, signInfo) {
  const L = [];
  L.push("// 自动生成: 微信小程序接口复现 (Node.js, 内置 fetch / Node >=18)");
  L.push("// 由 Module3 codegen 生成. 参数来源: static=源码硬编码, user=需你填, sign=签名算出, computed=运行时计算");
  L.push("");
  const signNode = signInfo && signInfo.transplantable && signInfo.lang && signInfo.lang.node;
  if (signNode) {
    L.push("// ───── 移植自小程序的签名函数 (Module2 定位) ─────");
    L.push(signNode.trim()); L.push("");
  } else if (signInfo && !signInfo.transplantable) {
    L.push("// ⚠️ 签名函数无法静态移植 (依赖运行时上下文). 见各请求 TODO.");
    L.push(`//    Module2 备注: ${signInfo && signInfo.note ? signInfo.note : "需在真机/沙箱中求值"}`);
    L.push("");
  }
  L.push("// ───── 用户态占位变量 (请填写真实值) ─────");
  const allPh = new Map();
  for (const api of apiList) for (const p of placeholdersFor(api, signInfo)) allPh.set(p.key, p.comment);
  if (allPh.size === 0) L.push("// (本组接口无需用户态参数)");
  for (const [k, c] of allPh) L.push(`const ${k} = ""; // ${c}`);
  L.push("");

  apiList.forEach((api, i) => {
    const fn = "api_" + i + "_" + api.method.toLowerCase();
    L.push(`// ── 接口 #${i}  [${api.method}] ${api.urlTemplate}  (来源文件: ${api.file}) ──`);
    L.push(`async function ${fn}() {`);
    L.push(`  // URL 来源: static base + ${api.dynamicSegs.length ? "动态段" : "固定路径"}`);
    L.push("  const url = " + nodeUrlExpr(api) + ";");
    const hasBody = api.data && api.method !== "GET";
    if (hasBody) L.push("  const body = " + nodeBodyExpr(api, signInfo) + ";"); // body 先于 headers,便于签名引用
    L.push("  const headers = {");
    for (const [k, v] of Object.entries(api.headers || {})) {
      if (v.source === "static") L.push(`    ${JSON.stringify(k)}: ${JSON.stringify(v.value)}, // static`);
      else if (v.source === "user") L.push(`    ${JSON.stringify(k)}: \`Bearer \${TOKEN}\`, // user: ${v.note || "token"}`);
      else if (v.source === "sign") L.push(`    ${JSON.stringify(k)}: ${signRefExprNode(signInfo)}, // sign`);
      else if (v.source === "computed") L.push(`    ${JSON.stringify(k)}: ${v.note === "timestamp" ? "Date.now().toString()" : "Math.random().toString(36).slice(2)"}, // computed: ${v.note || ""}`);
      else L.push(`    // TODO ${JSON.stringify(k)}: 动态 (源码: ${v.raw}) — 请确认值`);
    }
    L.push("  };");
    if (api.signRefs.length && !(signInfo && signInfo.transplantable)) {
      L.push("  // TODO[SIGN]: 该接口需要签名, 但签名函数无法静态移植.");
      for (const s of api.signRefs) L.push(`  //   需补 ${s.in}.${s.name} (源码: ${s.raw})`);
    }
    L.push("  const res = await fetch(url, {");
    L.push(`    method: ${JSON.stringify(api.method)},`);
    L.push("    headers,");
    if (hasBody) L.push("    body: JSON.stringify(body),");
    L.push("  });");
    if (api.enableChunked) L.push("  // 注意: 原接口为 SSE 流式 (enableChunked); 如需逐块读取请用 res.body 的 reader");
    L.push("  const text = await res.text();");
    L.push("  console.log(`#" + i + " ${res.status}`, text.slice(0, 500));");
    L.push("  return { status: res.status, text };");
    L.push("}"); L.push("");
  });

  L.push("// ───── 运行入口 ─────");
  L.push("(async () => {");
  apiList.forEach((api, i) => {
    const needsUser = placeholdersFor(api, signInfo).length > 0;
    L.push(`  try { await api_${i}_${api.method.toLowerCase()}(); } catch (e) { console.error("#${i} 失败", e); }${needsUser ? "  // 需先填占位变量" : ""}`);
  });
  L.push("})();");
  return L.join("\n");
}

function nodeUrlExpr(api) {
  let t = api.urlTemplate;
  if (t.includes("{BASE_URL}")) t = t.replace("{BASE_URL}", "${BASE_URL}");
  let hasTpl = false;
  for (const seg of api.dynamicSegs || []) {
    const key = seg.name === "PATH" ? "API_PATH" : seg.name.toUpperCase();
    t = t.split("{" + seg.name + "}").join("${" + key + "}");
    hasTpl = true;
  }
  if (t.includes("${")) hasTpl = true;
  return hasTpl ? "`" + t + "`" : JSON.stringify(t);
}

function nodeBodyExpr(api, signInfo) {
  if (api.data._raw) return "{} /* TODO: 源码为动态 body: " + api.data._raw + " */";
  const parts = [];
  for (const [k, v] of Object.entries(api.data)) {
    if (v.source === "static") parts.push(`${JSON.stringify(k)}: ${JSON.stringify(v.example)}`);
    else if (v.source === "user") parts.push(`${JSON.stringify(k)}: DATA_${k.toUpperCase()}`);
    else if (v.source === "computed") parts.push(`${JSON.stringify(k)}: ${v.raw && /timestamp|Date\.now/i.test(v.raw) ? "Date.now()" : "Math.random().toString(36).slice(2)"}`);
    else if (v.source === "sign") parts.push(`${JSON.stringify(k)}: ${signRefExprNode(signInfo)}`);
  }
  return "{ " + parts.join(", ") + " }";
}

function signRefExprNode(signInfo) {
  if (signInfo && signInfo.transplantable && signInfo.fnName) return (signInfo.callExpr || `${signInfo.fnName}(/* params */ {})`);
  return '"TODO_SIGN" /* 无法移植: 见 Module2 备注 */';
}

// ---------- Python 生成 ----------
function genPython(apiList, signInfo) {
  const L = [];
  L.push("# 自动生成: 微信小程序接口复现 (Python 3, requests)");
  L.push("# 参数来源: static=源码硬编码, user=需你填, sign=签名算出, computed=运行时计算");
  L.push("import requests, time, json, random, string");
  L.push("");
  const signPy = signInfo && signInfo.transplantable && signInfo.lang && signInfo.lang.python;
  if (signPy) {
    L.push("# ───── 移植自小程序的签名函数 (Module2 定位) ─────");
    L.push(signPy.trim()); L.push("");
  } else if (signInfo && !signInfo.transplantable) {
    L.push("# ⚠️ 签名函数无法静态移植 (依赖运行时上下文). 见各请求 TODO.");
    L.push(`#    Module2 备注: ${signInfo && signInfo.note ? signInfo.note : "需在真机/沙箱中求值"}`);
    L.push("");
  }
  L.push("# ───── 用户态占位变量 (请填写真实值) ─────");
  const allPh = new Map();
  for (const api of apiList) for (const p of placeholdersFor(api, signInfo)) allPh.set(p.key, p.comment);
  if (allPh.size === 0) L.push("# (本组接口无需用户态参数)");
  for (const [k, c] of allPh) L.push(`${k} = ""  # ${c}`);
  L.push("");

  apiList.forEach((api, i) => {
    const fn = "api_" + i + "_" + api.method.toLowerCase();
    L.push(`# ── 接口 #${i}  [${api.method}] ${api.urlTemplate}  (来源文件: ${api.file}) ──`);
    L.push(`def ${fn}():`);
    L.push("    url = " + pyUrlExpr(api));
    L.push("    headers = {");
    for (const [k, v] of Object.entries(api.headers || {})) {
      if (v.source === "static") L.push(`        ${JSON.stringify(k)}: ${JSON.stringify(v.value)},  # static`);
      else if (v.source === "user") L.push(`        ${JSON.stringify(k)}: f"Bearer {TOKEN}",  # user: ${v.note || "token"}`);
      else if (v.source === "sign") L.push(`        ${JSON.stringify(k)}: ${signRefExprPy(signInfo)},  # sign`);
      else if (v.source === "computed") L.push(`        ${JSON.stringify(k)}: ${v.note === "timestamp" ? "str(int(time.time()*1000))" : "''.join(random.choices(string.ascii_lowercase+string.digits, k=16))"},  # computed`);
      else L.push(`        # TODO ${JSON.stringify(k)}: 动态 (源码: ${v.raw})`);
    }
    L.push("    }");
    const hasBody = api.data && api.method !== "GET";
    if (hasBody) L.push("    body = " + pyBodyExpr(api, signInfo));
    if (api.signRefs.length && !(signInfo && signInfo.transplantable)) {
      L.push("    # TODO[SIGN]: 该接口需要签名, 但签名函数无法静态移植.");
      for (const s of api.signRefs) L.push(`    #   需补 ${s.in}.${s.name} (源码: ${s.raw})`);
    }
    if (hasBody) L.push(`    resp = requests.${api.method.toLowerCase()}(url, headers=headers, json=body)`);
    else L.push(`    resp = requests.${api.method.toLowerCase()}(url, headers=headers)`);
    if (api.enableChunked) L.push("    # 注意: 原接口为 SSE 流式; 如需逐块读取请用 requests(..., stream=True) + resp.iter_lines()");
    L.push("    print(f'#" + i + " {resp.status_code}', resp.text[:500])");
    L.push("    return resp"); L.push("");
  });

  L.push('if __name__ == "__main__":');
  apiList.forEach((api, i) => {
    L.push(`    try:\n        api_${i}_${api.method.toLowerCase()}()\n    except Exception as e:\n        print("#${i} 失败", e)`);
  });
  return L.join("\n");
}

function pyUrlExpr(api) {
  let t = api.urlTemplate;
  let isF = false;
  if (t.includes("{BASE_URL}")) isF = true; // 留作 f-string,需用户声明 BASE_URL
  for (const seg of api.dynamicSegs || []) {
    const key = seg.name === "PATH" ? "API_PATH" : seg.name.toUpperCase();
    t = t.split("{" + seg.name + "}").join("{" + key + "}");
    isF = true;
  }
  return (isF ? "f" : "") + JSON.stringify(t);
}

function pyBodyExpr(api, signInfo) {
  if (api.data._raw) return "{}  # TODO: 源码为动态 body: " + api.data._raw;
  const parts = [];
  for (const [k, v] of Object.entries(api.data)) {
    if (v.source === "static") parts.push(`${JSON.stringify(k)}: ${JSON.stringify(v.example)}`);
    else if (v.source === "user") parts.push(`${JSON.stringify(k)}: DATA_${k.toUpperCase()}`);
    else if (v.source === "computed") parts.push(`${JSON.stringify(k)}: ${v.raw && /timestamp|Date\.now/i.test(v.raw) ? "int(time.time()*1000)" : "''.join(random.choices(string.ascii_lowercase+string.digits, k=16))"}`);
    else if (v.source === "sign") parts.push(`${JSON.stringify(k)}: ${signRefExprPy(signInfo)}`);
  }
  return "{ " + parts.join(", ") + " }";
}

function signRefExprPy(signInfo) {
  if (signInfo && signInfo.transplantable && signInfo.fnName) return (signInfo.callExprPython || `${signInfo.fnName}({})`);
  return '"TODO_SIGN"  # 无法移植: 见 Module2 备注';
}