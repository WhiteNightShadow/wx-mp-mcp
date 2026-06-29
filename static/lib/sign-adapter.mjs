/**
 * sign-adapter — 把模块2(crypto-locate)的输出转成模块3(codegen)期望的 signInfo 契约。
 *
 * 模块2 产出: { hasSigning, signFunctions:[{name,file,source,algo,inputs,signTemplate,score}], ... }
 * 模块3 期望: signInfo = {
 *   transplantable: boolean,
 *   fnName: string,
 *   callExpr?: string, callExprPython?: string,
 *   lang: { node?: string, python?: string },
 *   note?: string,
 * }
 *
 * 设计原则(诚实):
 *  - 签名函数几乎都依赖 CryptoJS / md5 等库 + 运行时入参(nonce/secret/body),
 *    无法保证“贴进去就能跑”。所以 transplantable 的语义是“值得作为移植起点”,
 *    而非“开箱即用”。我们把真实函数源码原样给 codegen 作 lang.node(JS 本身可跑在 Node,
 *    前提是 npm i 对应 crypto 库 + 接好入参),并在 note 里讲清前置条件。
 *  - Python 侧无法自动把 JS 签名函数翻成 Python(那是另一个移植任务),所以
 *    lang.python 不提供 → codegen 在 Python 模式下会标注“无法静态移植”并留 TODO。
 *  - 选 score 最高、且能抽到 source 的签名函数作为代表。
 */

/** crypto 库名 → npm 包名 + import 行(Node)。 */
const CRYPTO_LIB_HINT = {
  "crypto-js": { pkg: "crypto-js", imp: 'const CryptoJS = require("crypto-js");' },
  "md5(npm)": { pkg: "md5", imp: 'const md5 = require("md5");' },
  "js-sha256": { pkg: "js-sha256", imp: 'const { sha256 } = require("js-sha256");' },
  "jsencrypt": { pkg: "jsencrypt", imp: 'const { JSEncrypt } = require("jsencrypt");' },
  "jsbn/rsa": { pkg: "jsbn", imp: '// RSA via jsbn — 需手动接 RSAKey' },
};

/**
 * @param {object} cryptoResult  模块2 locateCrypto() 的返回
 * @returns {object|null} signInfo(无签名时返回 null)
 */
export function toSignInfo(cryptoResult) {
  if (!cryptoResult || !cryptoResult.hasSigning) return null;

  const fns = (cryptoResult.signFunctions || [])
    .filter((f) => f.source && f.source.length > 12)
    .sort((a, b) => (b.score || 0) - (a.score || 0));

  // 推断需要哪些 crypto 库的 import 前导
  const libs = (cryptoResult.cryptoLibs || []).map((l) => l.lib);
  const imports = [];
  const pkgs = [];
  for (const lib of libs) {
    const hint = CRYPTO_LIB_HINT[lib];
    if (hint) {
      imports.push(hint.imp);
      if (hint.pkg) pkgs.push(hint.pkg);
    }
  }

  if (!fns.length) {
    // 有签名(拦截器/header 注入判定)但抽不到函数体 → 不可移植,但要告知 codegen 接口需签名
    return {
      transplantable: false,
      fnName: "",
      lang: {},
      note:
        `检测到请求签名(${cryptoResult.verdict})但未能静态抽出签名函数体` +
        `(可能在拦截器/封装层或被混淆)。算法: ${(cryptoResult.algorithms || []).map((a) => a.algo).join(", ") || "未知"}。` +
        `需在真机/沙箱中对签名调用点求值,或人工阅读 requestSignLinkage 指向的文件。`,
    };
  }

  const primary = fns[0];
  const algoStr = (primary.algo || []).join("+") || (cryptoResult.algorithms || []).map((a) => a.algo).join("+");
  const inputsStr = (primary.inputs || []).join(", ");
  const skeleton = primary.signTemplate?.skeleton || primary.signTemplate?.raw || null;

  // 检测函数体里的自由闭包引用(压缩模块引用 a.b / (0,a.b)() / 裸调用),它们移植后会 undefined。
  const freeRefs = detectFreeRefs(primary.source, primary.params);

  // Node 侧: import 前导 + 真实签名函数源码
  const nodeBlock = [
    ...imports,
    ...(imports.length ? [""] : []),
    `// 签名函数 ${primary.name} (抽取自 ${primary.file}, 算法: ${algoStr || "?"})`,
    ...(skeleton ? [`// 签名串骨架: ${String(skeleton).slice(0, 160)}`] : []),
    primary.source,
  ].join("\n");

  // callExpr: codegen 会把它放到 header/data 的 sign 字段。入参未知 → 给占位对象 + 注释
  const callExpr = `${primary.name}(/* 入参: ${inputsStr || "见函数源码"} */ SIGN_PARAMS)`;

  return {
    transplantable: true,
    fnName: primary.name,
    callExpr,
    // 不提供 callExprPython / lang.python: JS→Python 需人工移植
    lang: { node: nodeBlock },
    npmDeps: pkgs,
    algo: algoStr,
    inputs: primary.inputs || [],
    signTemplate: primary.signTemplate || null,
    candidates: fns.slice(0, 5).map((f) => ({ name: f.name, file: f.file, algo: f.algo, score: f.score })),
    freeRefs,
    note:
      `代表签名函数: ${primary.name} (算法 ${algoStr || "?"}, 入参 ${inputsStr || "?"})。` +
      (pkgs.length ? ` 移植需: npm i ${pkgs.join(" ")}。` : "") +
      ` 入参 SIGN_PARAMS 需你按函数源码补齐(常见: nonce/timestamp/body/secret)。` +
      (freeRefs.length
        ? ` ⚠️ 函数体引用了 ${freeRefs.length} 个外部闭包变量需手动接线: ${freeRefs.map((r) => r.hint ? `${r.ref}(≈${r.hint})` : r.ref).join(", ")}。`
        : "") +
      (fns.length > 1 ? ` 另有 ${fns.length - 1} 个候选签名函数见 candidates。` : ""),
  };
}

/** 检测压缩函数体里的自由闭包引用(移植后会 undefined)。返回 [{ref, hint}]。 */
function detectFreeRefs(source, params) {
  if (!source) return [];
  const paramSet = new Set((params || "").split(",").map((p) => p.trim()).filter(Boolean));
  const refs = new Map();
  // 形如 (0,X.Y)( 的间接调用 与 X.Y( 的成员调用
  for (const m of source.matchAll(/\(0,\s*([a-zA-Z_$][\w$]*)\.([a-zA-Z_$][\w$]*)\)|([a-zA-Z_$][\w$]*)\.([a-zA-Z_$][\w$]*)\s*\(/g)) {
    const obj = m[1] || m[3];
    const member = m[2] || m[4];
    if (!obj || paramSet.has(obj)) continue;
    // 跳过常见全局/已导入对象
    if (/^(CryptoJS|JSON|Math|Object|Array|String|Number|Date|console|window|globalThis|md5)$/.test(obj)) continue;
    const ref = `${obj}.${member}`;
    let hint = null;
    if (/default/.test(member)) hint = "可能是默认导入(如 md5)";
    else if (/random|nonce|uuid/i.test(member)) hint = "随机串生成器";
    else if (/stringify|qs|param/i.test(member)) hint = "查询串/序列化";
    if (!refs.has(ref)) refs.set(ref, { ref, hint });
  }
  return [...refs.values()].slice(0, 12);
}

export default toSignInfo;
