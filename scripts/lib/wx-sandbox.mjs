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
import vm from "node:vm";

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
  };
}

function createSandbox(appid, storage, appVersion, log) {
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

  // seeded PRNG for deterministic Math.random
  let _seed = 42;
  const seededRandom = () => { _seed = (_seed * 16807 + 0) % 2147483647; return (_seed - 1) / 2147483646; };
  const mockMath = Object.create(Math);
  mockMath.random = seededRandom;

  // controllable Date — VMP may capture Date.now in closures at load time
  let _mockTs = Date.now();
  const _MockDate = class extends Date {
    constructor(...a) { if (a.length === 0) super(_mockTs); else super(...a); }
    static now() { return _mockTs; }
    static parse(s) { return Date.parse(s); }
    static UTC(...a) { return Date.UTC(...a); }
  };
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

  const sandbox = {};
  Object.assign(sandbox, {
    Math: mockMath,
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
    console: { log: (...a) => log("[mp] " + a.join(" ")), warn() {}, error: (...a) => log("[mp-err] " + a.join(" ")), info() {} },
    setTimeout, clearTimeout, setInterval, clearInterval,
    Date: _MockDate, JSON, Object, Array, String, Number, Boolean, RegExp, Error, Symbol, Promise,
    Uint8Array, Int8Array, Uint32Array, Int32Array, Float64Array, ArrayBuffer, DataView, Map, Set, WeakMap, WeakSet,
    parseInt, parseFloat, isNaN, isFinite, encodeURIComponent, decodeURIComponent, encodeURI, decodeURI,
    navigator: undefined, screen: undefined,
  });
  sandbox.global = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;

  return { sandbox, modules, cache, requireMod, state, setTimestamp, storage, appOpts, getApp };
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
  const { appid, bundlePath, storage = {}, appVersion = "1.0.0", timeout = 20000 } = opts;
  const logs = [];
  const log = opts.log || ((m) => logs.push(m));

  const ctx = createSandbox(appid, storage, appVersion, log);
  const src = readFileSync(bundlePath, "utf8");
  vm.createContext(ctx.sandbox);
  ctx.state.suppressRequire = true;
  vm.runInContext(src, ctx.sandbox, { filename: "app-service.js", timeout });
  ctx.state.suppressRequire = false;

  // webpack module access — capture __webpack_require__ from any define'd webpack bundle
  let _wpRequire = null;
  function wpRequire(moduleId) {
    if (!_wpRequire) {
      for (const key of Object.keys(ctx.modules)) {
        try {
          const exp = ctx.requireMod(key);
          if (exp && typeof exp.push === "function") {
            exp.push([["__probe__"], {}, (o) => { _wpRequire = o; }]);
            if (_wpRequire) break;
          }
        } catch (_) {}
      }
    }
    if (!_wpRequire) throw new Error("no webpack runtime found in bundle");
    return _wpRequire(moduleId);
  }

  return { ...ctx, logs, wpRequire };
}
