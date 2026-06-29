/**
 * Generic WeChat mini-program sandbox engine.
 *
 * Loads any mini-program's app-service.js bundle into a Node vm context with
 * WeChat environment stubs (wx API, App/Page/Component, define/require shim,
 * module path resolution). Used for offline signature reproduction, SDK
 * analysis, and automated testing.
 *
 * Usage:
 *   import { loadBundle } from "./lib/wx-sandbox.mjs";
 *   const ctx = loadBundle({
 *     appid: "wx1234567890abcdef",
 *     bundlePath: "/path/to/app-service.js",
 *     storage: { "key": value },  // optional pre-seeded storage
 *     appVersion: "1.0.0",        // optional
 *   });
 *   const mod = ctx.requireMod("npm/some-sdk/dist/index.js");
 */
import { readFileSync } from "node:fs";
import { randomFillSync } from "node:crypto";
import vm from "node:vm";

// 默认 UA（微信 macOS 版）；可被 loadBundle({ ua }) 覆盖。VMP 常把 UA 编进签名，需与目标客户端一致。
const DEFAULT_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) " +
  "Chrome/132.0.0.0 Safari/537.36 MicroMessenger/7.0.20 MiniProgramEnv/Mac MacWechat/3.8.7";

function buildWxStub(appid, storage, appVersion, log) {
  const sysInfo = {
    platform: "mac", system: "Mac OS X 14.2.0", version: "8.0.0",
    SDKVersion: "3.8.7", model: "Mac15,3", brand: "apple",
    screenWidth: 1512, screenHeight: 982, windowWidth: 1512, windowHeight: 982,
    pixelRatio: 2, language: "zh_CN", fontSizeSetting: 16, statusBarHeight: 0,
    safeArea: { top: 0, left: 0, right: 1512, bottom: 982, width: 1512, height: 982 },
  };
  return {
    getStorageSync: (k) => (k in storage ? storage[k] : ""),
    setStorageSync: (k, v) => { storage[k] = v; },
    getStorage: (o) => { const v = storage[o.key]; o.success?.({ data: v }); },
    setStorage: (o) => { storage[o.key] = o.data; o.success?.({}); o.complete?.({}); },
    removeStorageSync: (k) => { delete storage[k]; },
    getSystemInfoSync: () => sysInfo,
    getSystemInfo: (o) => o.success?.(sysInfo),
    getSystemSetting: () => ({ wifiEnabled: true, bluetoothEnabled: false, locationEnabled: true, deviceOrientation: "portrait" }),
    getAppBaseInfo: () => ({ SDKVersion: "3.8.7", version: "8.0.0", language: "zh_CN", enableDebug: false }),
    getDeviceInfo: () => ({ platform: "mac", system: "Mac OS X 14.2.0", model: "Mac15,3", brand: "apple" }),
    getNetworkType: (o) => o.success?.({ networkType: "wifi" }),
    getConnectedWifi: (o) => o.fail?.({ errMsg: "not supported" }),
    getPrivacySetting: (o) => o.success?.({ needAuthorization: false }),
    getAccountInfoSync: () => ({ miniProgram: { appId: appid, envVersion: "release", version: appVersion } }),
    getLaunchOptionsSync: () => ({ scene: 1001, path: "", query: {}, referrerInfo: {} }),
    getEnterOptionsSync: () => ({ scene: 1001, path: "", query: {} }),
    onAppShow: () => {}, onAppHide: () => {}, onError: () => {},
    request: (o) => { log(`[wx.request] ${o.method || "GET"} ${o.url}`); },
    getPerformance: () => ({
      now: () => Date.now(),
      createObserver: () => ({ observe() {}, disconnect() {} }),
      getEntries: () => [], getEntriesByName: () => [], getEntriesByType: () => [],
    }),
    getBatteryInfoSync: () => ({ level: 80, isCharging: false }),
    onNetworkStatusChange: () => {}, onMemoryWarning: () => {},
    env: { USER_DATA_PATH: "/tmp" },
    canIUse: () => true,
    nextTick: (fn) => Promise.resolve().then(fn),
    // 微信版 tweetnacl 等加密库在 load 时自检 wx.getRandomValues,并以【同步回调】取随机数。
    // 用 node crypto 同步回填,缺它会抛 "No suitable random number generator available."
    getRandomValues: (o) => {
      const n = (o && o.length) || 0;
      const buf = new Uint8Array(n);
      if (n) randomFillSync(buf);
      o && o.success && o.success({ randomValues: buf.buffer });
    },
    // 部分 SDK 顶层即 wx.getLogManager({})/getRealtimeLogManager() → 缺则加载即崩。no-op 即可。
    getLogManager: () => ({ log() {}, info() {}, warn() {}, debug() {}, setFilterMsg() {}, addFilterMsg() {} }),
    getRealtimeLogManager: () => ({ info() {}, warn() {}, error() {}, setFilterMsg() {}, addFilterMsg() {}, in() { return this; } }),
  };
}

function createSandbox(appid, storage, appVersion, log, ua) {
  const wx = buildWxStub(appid, storage, appVersion, log);
  const modules = {};
  const cache = {};
  const state = { suppressRequire: true, missing: new Set() };

  function normalize(p) {
    const parts = p.split("/");
    const out = [];
    for (const seg of parts) {
      if (seg === "" || seg === ".") continue;
      if (seg === "..") out.pop();
      else out.push(seg);
    }
    return out.join("/");
  }
  function dirnamePath(p) { const i = p.lastIndexOf("/"); return i < 0 ? "" : p.slice(0, i); }

  function resolveKey(fromPath, spec) {
    const candidates = [];
    if (spec.startsWith(".")) {
      const base = normalize(dirnamePath(fromPath) + "/" + spec);
      candidates.push(base, base + ".js", base + "/index.js", base + ".cjs.js", base + "/index.cjs.js");
    } else {
      const base = normalize(spec);
      candidates.push(base, base + ".js", base + "/index.js", base + ".cjs.js", base + "/index.cjs.js");
    }
    for (const c of candidates) if (c in modules) return c;
    return null;
  }

  function instantiate(key) {
    if (key in cache) return cache[key];
    const factory = modules[key];
    const mod = { exports: {} };
    cache[key] = mod.exports;
    const localRequire = (spec) => {
      const rk = resolveKey(key, spec);
      if (!rk) {
        state.missing.add(spec + "  (from " + key + ")");
        if (state.suppressRequire) return {};
        throw new Error("cannot resolve: " + spec + " (from " + key + ")");
      }
      return instantiate(rk);
    };
    // 21 params matching WeChat's define(path, function(require,module,exports,window,...){})
    factory(
      localRequire, mod, mod.exports,
      undefined, undefined, undefined, sandbox,
      undefined, sandbox.navigator, undefined, undefined,
      undefined, sandbox.screen, undefined, undefined, undefined,
      undefined, undefined, sandbox.Reporter, undefined,
      sandbox.WeixinJSCore
    );
    cache[key] = mod.exports;
    return mod.exports;
  }

  function requireMod(path) {
    if (state.suppressRequire) { state.missing.add(path); return {}; }
    const key = resolveKey("", path) || (path in modules ? path : null);
    if (!key) { state.missing.add(path); throw new Error("module not registered: " + path); }
    return instantiate(key);
  }

  function defineMod(path, factory) { modules[path] = factory; }

  let appInstance = null;
  const appOpts = {};
  function App(opts) {
    Object.assign(appOpts, opts);
    appInstance = { ...opts, globalData: opts.globalData || {} };
    try { opts.onLaunch?.call(appInstance, {}); } catch (e) { log("[App.onLaunch err] " + e.message); }
  }
  function getApp() { return appInstance; }

  // 可选确定性(默认关闭)：seeded random + 固定时间戳。
  // ★不替换整个 Math/Date 内建★(那会制造跨 realm 不一致、且易被反调试检测)；
  //   仅在 loadBundle({ deterministic: true }) 时由 in-realm 方式给上下文原生对象打补丁。
  let _seed = 42;
  const seededRandom = () => { _seed = (_seed * 16807 + 0) % 2147483647; return (_seed - 1) / 2147483646; };
  let _mockTs = Date.now();
  const setTimestamp = (ts) => { _mockTs = ts; };

  // WXML rendering engine stub — Proxy that returns no-op for any property (a-z, A-Z, aa, etc.)
  // Pre-defining __g skips the bundle's own IIFE WXML compiler, which we don't need for logic analysis.
  const noopFn = () => {};
  const __g = new Proxy({}, { get: () => noopFn });

  // __wxCodeSpace__: newer WeChat bundles register compiled scripts/templates here.
  // Proxy fallback handles any future methods without explicit stubs.
  const _codeSpaceImpl = {
    _$runtimeGlobals: null, gdc: (v) => v,
    setRuntimeGlobals(factory) {
      try { this._$runtimeGlobals = factory(); this.gdc = this._$runtimeGlobals; } catch (_) {}
    },
    batchAddCompiledScripts(fn) {
      try { fn({}, defineMod, () => {}, this.gdc || ((v) => v)); } catch (_) {}
    },
  };
  const __wxCodeSpace__ = new Proxy(_codeSpaceImpl, {
    get(target, prop) {
      if (prop in target) return target[prop];
      return noopFn;
    },
  });

  // ── 浏览器/H5 环境 stub（navigator / location / storage / document）──
  const _ls = {};
  const localStorage = {
    getItem: (k) => (k in _ls ? _ls[k] : null),
    setItem: (k, v) => { _ls[k] = String(v); },
    removeItem: (k) => { delete _ls[k]; },
    clear: () => { for (const k of Object.keys(_ls)) delete _ls[k]; },
    key: (i) => Object.keys(_ls)[i] ?? null,
    get length() { return Object.keys(_ls).length; },
  };
  const navigator = {
    userAgent: ua || DEFAULT_UA,
    platform: "MacIntel", language: "zh-CN", languages: ["zh-CN"], onLine: true, sendBeacon: () => true,
  };
  const screen = { width: 1512, height: 982, availWidth: 1512, availHeight: 982, colorDepth: 24, pixelDepth: 24 };
  const location = { href: `https://servicewechat.com/${appid}/${appVersion}/page-frame.html`, protocol: "https:", host: "servicewechat.com", hostname: "servicewechat.com", port: "", pathname: "/", search: "", hash: "", origin: "https://servicewechat.com" };
  // performance / atob / btoa：VMP 平台检测与 base64 编解码常用，缺则走异常分支或抛错
  const _perfOrigin = Date.now();
  const performance = {
    now: () => Date.now() - _perfOrigin, timeOrigin: _perfOrigin,
    getEntries: () => [], getEntriesByName: () => [], getEntriesByType: () => [],
    mark: noopFn, measure: noopFn, clearMarks: noopFn, clearMeasures: noopFn,
  };
  const atob = (s) => Buffer.from(String(s), "base64").toString("binary");
  const btoa = (s) => Buffer.from(String(s), "binary").toString("base64");
  const documentObj = {
    cookie: "", readyState: "complete",
    createElement: () => ({ getContext: () => null, style: {}, setAttribute() {}, appendChild() {} }),
    documentElement: { style: {} }, head: {}, body: {},
    getElementsByTagName: () => [], querySelector: () => null, querySelectorAll: () => [],
    addEventListener: noopFn, removeEventListener: noopFn, createEvent: () => ({ initEvent() {} }),
  };
  // console 必须补全：JSVMP 签名器算完常调 console.groupEnd()，缺方法会把已算好的结果又抛掉
  const fullConsole = {
    log: (...a) => log("[mp] " + a.join(" ")), info: (...a) => log("[mp] " + a.join(" ")),
    warn: (...a) => log("[mp-warn] " + a.join(" ")), error: (...a) => log("[mp-err] " + a.join(" ")),
    debug: noopFn, trace: noopFn, group: noopFn, groupEnd: noopFn, groupCollapsed: noopFn,
    table: noopFn, dir: noopFn, dirxml: noopFn, count: noopFn, countReset: noopFn,
    time: noopFn, timeEnd: noopFn, timeLog: noopFn, assert: noopFn, clear: noopFn,
  };

  // ★只注入「环境 stub」，绝不注入 Array/Object/JSON/Symbol/Math/Date/TypedArray 等核心内建★
  //   vm.createContext 后上下文自带原生 intrinsics；注入外层 realm 的会让
  //   [].push !== Array.prototype.push（跨 realm 身份不一致），破坏 JSVMP 等依赖原型/构造器的代码。
  const sandbox = {};
  Object.assign(sandbox, {
    define: defineMod, require: requireMod,
    wx, App, getApp,
    Page() {}, Component() {}, Behavior(x) { return x; },
    definePlugin() {}, requirePlugin() { return {}; },
    getCurrentPages: () => [],
    WeixinJSCore: { invokeHandler() {}, publishHandler() {}, on() {} },
    __wxConfig: { appLaunchInfo: {}, accountInfo: { appId: appid }, envVersion: "release", platform: "mac" },
    __wxAppCode__: {}, __wxAppData: {},
    __WXML_GLOBAL__: { entrys: {}, defines: {}, modules: {}, ops: [], wxs_nf_init: undefined, total_ops: 0, ops_cached: {}, ops_set: {}, ops_init: {} },
    __GWX_GLOBAL__: {},
    __vd_version_info__: {},
    __g,
    __wxCodeSpace__,
    $gwx: () => noopFn,
    __wxRoute: "", __wxRouteBegin: "", __wxAppCurrentFile__: "",
    Reporter: { error() {}, info() {}, getReportData: () => ({}) },
    console: fullConsole,
    setTimeout, clearTimeout, setInterval, clearInterval,
    navigator, screen, location, localStorage, document: documentObj,
    performance, atob, btoa,
  });
  sandbox.global = sandbox;
  sandbox.self = sandbox;
  sandbox.window = sandbox;
  // globalThis 在 vm.createContext 之后再指回 sandbox（见 loadBundle），保持 realm 自洽

  return { sandbox, modules, cache, requireMod, state, setTimestamp, storage, appOpts, getApp, _seededRandom: seededRandom, _getTs: () => _mockTs };
}

/**
 * Load and eval a mini-program bundle.
 *
 * @param {object} opts
 * @param {string} opts.appid - Mini-program appid
 * @param {string} opts.bundlePath - Absolute path to app-service.js
 * @param {object} [opts.storage] - Pre-seeded wx storage entries
 * @param {string} [opts.appVersion] - App version string (default "1.0.0")
 * @param {function} [opts.log] - Logging callback (default: collect to array)
 * @param {number} [opts.timeout] - Bundle eval timeout in ms (default 20000)
 * @returns {{ sandbox, modules, cache, requireMod, state, setTimestamp, storage, appOpts, getApp, logs }}
 */
export function loadBundle(opts) {
  const { appid, bundlePath, bundlePaths, storage = {}, appVersion = "1.0.0", timeout = 20000, deterministic = false, ua } = opts;
  const logs = [];
  const log = opts.log || ((m) => logs.push(m));

  // 多 bundle 协同(分包签名 SDK 常 require 主包 ../../bund.js)：按顺序【拼接成一份、单次加载】，
  // 避免同进程二次加载导致 preamble 重定义(nv_length 等)报错。bundlePaths 优先,回退 bundlePath。
  const paths = (Array.isArray(bundlePaths) && bundlePaths.length) ? bundlePaths : [bundlePath];
  const src = paths.map((p) => readFileSync(p, "utf8")).join("\n;\n");

  const ctx = createSandbox(appid, storage, appVersion, log, ua);
  vm.createContext(ctx.sandbox);
  ctx.sandbox.globalThis = ctx.sandbox; // realm 自洽：globalThis 指回 sandbox（用上下文原生 intrinsics）

  // 可选确定性(默认关闭)：只 in-realm 给上下文原生对象打补丁，不替换整个内建。
  if (deterministic) {
    try { ctx.sandbox.Math.random = ctx._seededRandom; } catch (_) {}
    try { ctx.sandbox.Date.now = () => ctx._getTs(); } catch (_) {}
  }

  ctx.state.suppressRequire = true;
  vm.runInContext(src, ctx.sandbox, { filename: "app-service.js", timeout });
  ctx.state.suppressRequire = false;

  // ── webpack 模块惰性获取（不引导 app）──
  // 覆盖两种常见形态：
  //   (A) 全局 jsonp:   (global.webpackChunkX = ... || []).push([[id],{mods},cb])  → 扫 webpackChunk* 全局
  //   (B) 内嵌模块表:   define 模块里的 {id:function(e,n,t){…}, …}                → 从 bundle 源码静态收割
  // 自建 __webpack_require__ 只实例化被请求的模块及其依赖子树，不跑 webpack 入口 bootstrap。
  let _wpRequire = null;
  const liveFactories = {}; // jsonp 注册的真函数对象（context realm）
  const srcFactories = {};  // 静态收割的工厂源码字符串（按需在 context 内编译）
  const compiled = {};

  function collectJsonpChunks() {
    for (const key of Object.keys(ctx.sandbox)) {
      if (!/^webpackChunk/.test(key)) continue;
      const arr = ctx.sandbox[key];
      if (!Array.isArray(arr)) continue;
      for (const entry of arr) {
        const mods = entry && entry[1];
        if (mods && typeof mods === "object") for (const id of Object.keys(mods)) if (typeof mods[id] === "function") liveFactories[id] = mods[id];
      }
    }
  }
  // 静态收割 `<id>:function(e,n,t){…}` 工厂（括号配平，string/escape 感知）
  function harvestEmbedded() {
    const code = src;
    const re = /(?:^|[,{])\s*(\d{1,6}):function\(\w+,\w+,\w+\)\{/g;
    let m;
    while ((m = re.exec(code))) {
      const id = m[1];
      if (id in srcFactories) continue;
      const openIdx = code.indexOf("{", m.index + m[0].length - 1);
      let depth = 0, i = openIdx, inStr = null, esc = false;
      for (; i < code.length; i++) {
        const c = code[i];
        if (inStr) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === inStr) inStr = null; continue; }
        if (c === '"' || c === "'" || c === "`") { inStr = c; continue; }
        if (c === "{") depth++;
        else if (c === "}") { depth--; if (depth === 0) { i++; break; } }
      }
      srcFactories[id] = "(function(e,n,t){" + code.slice(openIdx + 1, i - 1) + "})";
    }
  }

  function getFactory(id) {
    if (id in liveFactories) return liveFactories[id];
    if (compiled[id]) return compiled[id];
    const s = srcFactories[id];
    if (!s) return null;
    try { return (compiled[id] = vm.runInContext(s, ctx.sandbox, { filename: `wpmod-${id}.js` })); } catch (_) { return null; }
  }

  function buildWebpackRequire() {
    collectJsonpChunks();
    // jsonp 尚未填充时：require 含 "webpackChunk" 的 define 模块以触发 push（只注册，不跑入口）
    if (!Object.keys(liveFactories).length) {
      for (const key of Object.keys(ctx.modules)) {
        let s = ""; try { s = ctx.modules[key].toString(); } catch (_) {}
        if (s.includes("webpackChunk")) { try { ctx.requireMod(key); } catch (_) {} }
      }
      collectJsonpChunks();
    }
    harvestEmbedded(); // 内嵌形态（及兜底）
    if (!Object.keys(liveFactories).length && !Object.keys(srcFactories).length) return null;

    const wcache = {};
    const wreq = (id) => {
      id = String(id);
      if (wcache[id]) return wcache[id].exports;
      const fn = getFactory(id);
      if (!fn) throw new Error("webpack module not found: " + id);
      const mod = (wcache[id] = { exports: {}, id, loaded: false });
      fn.call(mod.exports, mod, mod.exports, wreq);
      mod.loaded = true;
      return mod.exports;
    };
    wreq.o = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
    wreq.d = (ex, df) => { for (const k in df) if (wreq.o(df, k) && !wreq.o(ex, k)) Object.defineProperty(ex, k, { enumerable: true, get: df[k] }); };
    wreq.r = (ex) => { if (typeof Symbol !== "undefined" && Symbol.toStringTag) Object.defineProperty(ex, Symbol.toStringTag, { value: "Module" }); Object.defineProperty(ex, "__esModule", { value: true }); };
    wreq.n = (m) => { const g = m && m.__esModule ? () => m.default : () => m; wreq.d(g, { a: g }); return g; };
    wreq.g = ctx.sandbox; wreq.c = wcache; wreq.e = () => Promise.resolve(); wreq.u = () => ""; wreq.f = {}; wreq.p = "";
    wreq.m = new Proxy({}, { get: (_t, k) => getFactory(String(k)), has: (_t, k) => (String(k) in liveFactories) || (String(k) in srcFactories) });
    wreq.nmd = (m) => { m.paths = []; m.children = m.children || []; return m; }; wreq.hmd = (m) => m;
    return wreq;
  }

  function wpRequire(moduleId) {
    if (!_wpRequire) {
      _wpRequire = buildWebpackRequire();
      if (!_wpRequire) {
        // 末路兜底：旧的「某模块导出对象上有 .push」运行时探针
        for (const key of Object.keys(ctx.modules)) {
          try {
            const exp = ctx.requireMod(key);
            if (exp && typeof exp.push === "function") {
              let cap = null;
              exp.push([["__probe__"], {}, (o) => { cap = o; }]);
              if (cap) { _wpRequire = cap; break; }
            }
          } catch (_) {}
        }
      }
    }
    if (!_wpRequire) throw new Error("no webpack runtime found in bundle");
    return _wpRequire(moduleId);
  }

  return { ...ctx, logs, wpRequire };
}
