/**
 * 模块1: 批量解包引擎 (batch-unpack)
 *
 * 对任意微信小程序,自动 解密(V1MMWX) + 解包(0xBE wxapkg) 其
 * 【主包 + 所有命名分包 + 插件包(__PLUGINCODE__)】,产出一棵完整源码树。
 *
 * ── 实测结论(基于本机 31 个缓存小程序的真实数据)─────────────────────
 *  1. V1MMWX 解密的密钥【始终由“缓存目录名 appid”派生】——主包、命名分包、
 *     __PLUGINCODE__ 三类包全部用同一个 (目录) appid 即可解出有效 0xBE 头。
 *     (实测: __PLUGINCODE__ 用宿主 appid 可解; 插件应用目录用自身 appid 可解。
 *      结论: 解密 appid = 缓存目录名。)
 *
 *  2. 命名分包(_packages_xxx_.wxapkg / _pages_xxx_.wxapkg)无需 wxappUnpacker 的
 *     `-s` 合并逻辑:每个分包内部的文件路径【已经是 app-root 相对路径并带 root 前缀】
 *     (如 /packages/dish/...、/pages/query/...)。因此把【所有包解包进同一个根目录】
 *     就天然合并成连贯源码树, 主包与分包零路径冲突(实测 wx734/wxd4185 均成立)。
 *
 *  3. __PLUGINCODE__ 的内部路径语义【不同】:它是【相对插件自身根】的
 *     (/plugin.json、/appservice.js、/components/...),不带 app-root 前缀。
 *     若直接铺进 app 根会与主包文件冲突/污染, 故插件包【单独解到 plugins/<标识> 子目录】。
 *     宿主主包通过 /__plugin__/<pluginAppid>/... 引用插件, 解包侧不强行重定位。
 *
 *  4. 多版本目录(如 .../667/、.../699/、.../70/ vs /82/)全为纯数字, 取【数值最大】=最新。
 *     版本目录内只含 *.wxapkg, 无其它文件。
 *
 *  5. wxappUnpacker(2020 版)对现代分包/config 会抛错(subPackage.pages is not iterable /
 *     “请用 -s 指定” / -o 跳过合并)。本模块【不依赖 wxappUnpacker 做解包/合并】, 改用
 *     内置 0xBE 解析器, 既稳又可控; wxappUnpacker 留给模块2 按需做源码还原。
 *
 * 导出:
 *   - listAllApps(opts)            枚举缓存里全部小程序(本机 31 个)
 *   - findAppPackages(appid, opts) 选最新版本目录, 分类列出 main/subPackages/plugins
 *   - decryptWxapkgFile(buf,appid) V1MMWX → 明文 0xBE buffer(未加密则原样返回)
 *   - parseWxapkg(buf)             解析 0xBE 头与文件表
 *   - unpackInto(buf, appid, dir)  解密+解包一个包到指定目录
 *   - batchUnpack(appid,outRoot,opts) ★主入口: 解全部包成一棵树, 返回结构化结果
 */
import {
  readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync, statSync,
} from "node:fs";
import { join, dirname, sep } from "node:path";
import { createDecipheriv, pbkdf2Sync } from "node:crypto";
import { WXAPKG_ROOT, WXAPKG_ROOTS } from "./wx-roots.mjs";

// ── 常量 ────────────────────────────────────────────────────────────────
// 缓存根目录探测已抽到 wx-roots.mjs(支持多账号 / 多版本布局自动发现)。
// WXAPKG_ROOT = 主包根(向后兼容); WXAPKG_ROOTS = 全部包根(多账号合并用)。
export { WXAPKG_ROOT, WXAPKG_ROOTS };

const V1MMWX = Buffer.from("V1MMWX");
const SALT = "saltiest";
const IV = Buffer.from("the iv: 16 bytes");
const PBKDF2_ITER = 1000;
const KEY_LEN = 32;
const AES_BLOCK = 1024;
const APPID_RE = /^(wx[0-9a-f]{16}|tt[0-9a-f]{16})$/i;

// ── V1MMWX 解密 ──────────────────────────────────────────────────────────
function deriveKey(appid) {
  return pbkdf2Sync(appid, SALT, PBKDF2_ITER, KEY_LEN, "sha1");
}

/** 判断 buffer 是否 V1MMWX 加密包。 */
export function isEncrypted(buf) {
  return buf.length >= 6 && buf.subarray(0, 6).equals(V1MMWX);
}

/** 判断 buffer 是否已是明文 0xBE wxapkg。 */
export function isPlainWxapkg(buf) {
  return buf.length >= 1 && buf[0] === 0xbe;
}

/**
 * 解密 V1MMWX 包 → 明文 0xBE buffer。若已是明文则原样返回。
 * 算法:PBKDF2(appid,"saltiest",1000,32,sha1) → AES-256-CBC 解前1024字节取前1023,
 *       XOR key = appid 倒数第二字符, 对 enc[1024..] 逐字节 XOR。
 */
export function decryptWxapkgFile(buf, appid) {
  if (isPlainWxapkg(buf) && !isEncrypted(buf)) return buf;
  if (!isEncrypted(buf)) {
    throw new Error("不是 V1MMWX 加密包, 也不是 0xBE 明文包(头部错误)");
  }
  const encrypted = buf.subarray(6);
  const key = deriveKey(appid);
  const decipher = createDecipheriv("aes-256-cbc", key, IV);
  decipher.setAutoPadding(false);
  const decrypted = Buffer.concat([
    decipher.update(encrypted.subarray(0, AES_BLOCK)),
    decipher.final(),
  ]);
  const xorKey = appid.charCodeAt(appid.length - 2);
  const aesUsable = AES_BLOCK - 1; // 1023
  const xorPart = encrypted.subarray(AES_BLOCK);
  const out = Buffer.alloc(aesUsable + xorPart.length);
  decrypted.copy(out, 0, 0, aesUsable);
  for (let i = 0; i < xorPart.length; i++) {
    out[aesUsable + i] = xorPart[i] ^ xorKey;
  }
  return out;
}

// ── 0xBE wxapkg 解析 ─────────────────────────────────────────────────────
/**
 * 解析明文 0xBE wxapkg 头与文件表。
 * 返回 { fileCount, files:[{name, offset, size}], indexInfoLength }。
 */
export function parseWxapkg(buf) {
  let o = 0;
  const firstMark = buf.readUInt8(o); o += 1;
  o += 4;                                   // unknownInfo
  const indexInfoLength = buf.readUInt32BE(o); o += 4;
  o += 4;                                   // bodyInfoLength
  const lastMark = buf.readUInt8(o); o += 1;
  if (firstMark !== 0xbe || lastMark !== 0xed) {
    throw new Error(
      `非法 wxapkg 标记: first=0x${firstMark.toString(16)} last=0x${lastMark.toString(16)}`,
    );
  }
  const fileCount = buf.readUInt32BE(o); o += 4;
  const files = [];
  for (let i = 0; i < fileCount; i++) {
    if (o + 4 > buf.length) break;
    const nameLen = buf.readUInt32BE(o); o += 4;
    if (nameLen > 4096 || o + nameLen + 8 > buf.length) break;
    const name = buf.subarray(o, o + nameLen).toString("utf8"); o += nameLen;
    const fileOffset = buf.readUInt32BE(o); o += 4;
    const fileSize = buf.readUInt32BE(o); o += 4;
    files.push({ name, offset: fileOffset, size: fileSize });
  }
  return { fileCount, files, indexInfoLength };
}

/** 把解析出的文件写到 outDir。name 以 "/" 开头时去前导斜杠落地为相对路径。含目录穿越防护。返回写出列表。 */
function writeFiles(buf, parsed, outDir) {
  const written = [];
  const baseNorm = outDir.split(sep).join("/").replace(/\/+$/, "") + "/";
  for (const f of parsed.files) {
    const rel = f.name.replace(/^\/+/, "");          // 去前导斜杠
    const outPath = join(outDir, rel);
    const norm = outPath.split(sep).join("/");
    if (!norm.startsWith(baseNorm)) continue;        // 防目录穿越
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, buf.subarray(f.offset, f.offset + f.size));
    written.push({ rel, abs: outPath, size: f.size });
  }
  return written;
}

/**
 * 解密 + 解包一个包到 outDir。返回 { fileCount, written:[{rel,abs,size}] }。
 */
export function unpackInto(buf, appid, outDir) {
  const plain = decryptWxapkgFile(buf, appid);
  const parsed = parseWxapkg(plain);
  mkdirSync(outDir, { recursive: true });
  const written = writeFiles(plain, parsed, outDir);
  return { fileCount: parsed.fileCount, written };
}

// ── 缓存枚举 ──────────────────────────────────────────────────────────────
/** 包文件分类:main / subpackage / plugin。 */
function classifyPkg(filename) {
  if (filename === "__APP__.wxapkg") return "main";
  if (filename === "__PLUGINCODE__.wxapkg") return "plugin";
  // _xxx_.wxapkg 命名分包(微信缓存把分包 root 的斜杠替换成下划线再前后包下划线)
  if (/^_.*_\.wxapkg$/.test(filename)) return "subpackage";
  if (filename.endsWith(".wxapkg")) return "subpackage"; // 兜底
  return null;
}

/** 要搜索的包根列表: 显式 opts.root 优先, 否则用全部探测到的包根(多账号合并)。 */
function rootsToSearch(opts = {}) {
  if (opts.root) return [opts.root];
  return WXAPKG_ROOTS.length ? WXAPKG_ROOTS : [WXAPKG_ROOT];
}

/** 选某 appid 下数值最大(最新)且含 .wxapkg 的版本目录。返回 {version, dir, root} 或 null。 */
export function findLatestVersionDir(appid, root = WXAPKG_ROOT) {
  const appDir = join(root, appid);
  if (!existsSync(appDir)) return null;
  let versions;
  try {
    versions = readdirSync(appDir)
      .filter((v) => /^\d+$/.test(v) && statSync(join(appDir, v)).isDirectory())
      .sort((a, b) => Number(b) - Number(a));
  } catch { return null; }
  for (const v of versions) {
    const vdir = join(appDir, v);
    if (readdirSync(vdir).some((f) => f.endsWith(".wxapkg"))) {
      return { version: v, dir: vdir, root };
    }
  }
  return null;
}

/** 跨所有包根找某 appid 的最新版本目录, 命中多个根时取版本号最大者。 */
export function findLatestVersionDirAnyRoot(appid, roots = rootsToSearch()) {
  let best = null;
  for (const root of roots) {
    const ver = findLatestVersionDir(appid, root);
    if (ver && (!best || Number(ver.version) > Number(best.version))) best = ver;
  }
  return best;
}

/** 在某版本目录里分类列出 main/subPackages/plugins/all。 */
function collectPackages(versionDir) {
  const files = readdirSync(versionDir).filter((f) => f.endsWith(".wxapkg"));
  const r = { main: null, subPackages: [], plugins: [], all: [] };
  for (const f of files) {
    const type = classifyPkg(f);
    const entry = { path: join(versionDir, f), filename: f, type };
    r.all.push(entry);
    if (type === "main") r.main = entry;
    else if (type === "plugin") r.plugins.push(entry);
    else r.subPackages.push(entry);
  }
  return r;
}

/**
 * 枚举某 appid 的全部包(选最新版本, 或 opts.version 强制指定)。
 * 返回 { appid, version, versionDir, main, subPackages[], plugins[], all[] } 或 null。
 * main 可能为 null(纯插件应用)。
 */
export function findAppPackages(appid, opts = {}) {
  let versionDir, version;
  if (opts.version != null) {
    // 指定版本: 在显式 root 或全部包根里找到该版本目录。
    const roots = rootsToSearch(opts);
    versionDir = null;
    for (const root of roots) {
      const cand = join(root, appid, String(opts.version));
      if (existsSync(cand)) { versionDir = cand; break; }
    }
    if (!versionDir) return null;
    version = String(opts.version);
  } else {
    const ver = opts.root
      ? findLatestVersionDir(appid, opts.root)
      : findLatestVersionDirAnyRoot(appid);
    if (!ver) return null;
    versionDir = ver.dir;
    version = ver.version;
  }
  const pkgs = collectPackages(versionDir);
  return { appid, version, versionDir, ...pkgs };
}

/**
 * 枚举缓存里全部小程序。返回数组,每项:
 *   { appid, versions:[...降序], latest:{version,dir}|null,
 *     packages:{ main:bool, subCount, pluginCount, total } }
 */
export function listAllApps(opts = {}) {
  const roots = rootsToSearch(opts);
  const byAppid = new Map(); // appid → entry(跨账号合并, 取最新版本所在根)
  for (const root of roots) {
    if (!existsSync(root)) continue;
    let dirs;
    try { dirs = readdirSync(root); } catch { continue; }
    for (const d of dirs) {
      if (!APPID_RE.test(d)) continue;
      const appDir = join(root, d);
      let versions;
      try {
        versions = readdirSync(appDir)
          .filter((v) => /^\d+$/.test(v) && statSync(join(appDir, v)).isDirectory())
          .sort((a, b) => Number(b) - Number(a));
      } catch { continue; }
      const latest = findLatestVersionDir(d, root);
      let pkgs = { main: false, subCount: 0, pluginCount: 0, total: 0 };
      if (latest) {
        const fp = findAppPackages(d, { root });
        pkgs = {
          main: !!fp.main,
          subCount: fp.subPackages.length,
          pluginCount: fp.plugins.length,
          total: fp.all.length,
        };
      }
      const entry = { appid: d, root, versions, latest, packages: pkgs };
      const prev = byAppid.get(d);
      // 同一 appid 在多个根都有 → 留版本号最大(有包优先)的那个。
      if (!prev) { byAppid.set(d, entry); continue; }
      const pv = prev.latest ? Number(prev.latest.version) : -1;
      const cv = latest ? Number(latest.version) : -1;
      if (cv > pv) byAppid.set(d, entry);
    }
  }
  return [...byAppid.values()].sort((a, b) => a.appid.localeCompare(b.appid));
}

// ── 主入口: 批量解包 ──────────────────────────────────────────────────────
/**
 * 解密+解包一个 appid 的【主包 + 全部命名分包 + 插件包】成一棵完整源码树。
 *
 * 布局策略(实测依据见文件头):
 *   - 主包与命名分包 → 全部解进同一个 mainDir(opts.mergeRoot, 默认 outRoot/app),
 *     因内部路径自带 root 前缀, 天然合并、零冲突。
 *   - 插件包 __PLUGINCODE__ → 单独解到 outRoot/plugins/<pluginKey>/,
 *     因其内部路径是插件自身根、与主包语义不同。
 *
 * @param {string} appid    缓存目录名 appid(同时作为解密密钥来源)
 * @param {string} outRoot  输出根目录
 * @param {object} opts     { root, version, mergeRoot, pluginDir, onLog }
 * @returns {Promise<object>} {
 *   appid, version, versionDir, mainDir,
 *   subPackages:[{filename,root,fileCount,files[]}],
 *   plugins:[{filename,key,dir,fileCount,files[]}],
 *   allJsFiles:[abs...], stats:{packages,totalFiles,jsFiles}, errors:[{filename,error}]
 * }
 */
export async function batchUnpack(appid, outRoot, opts = {}) {
  const log = opts.onLog || (() => {});
  const found = findAppPackages(appid, { root: opts.root, version: opts.version });
  if (!found) throw new Error(`未找到 appid=${appid} 的缓存包(或无任何版本目录)`);

  const mainDir = opts.mergeRoot || join(outRoot, "app");
  const pluginsRoot = opts.pluginDir || join(outRoot, "plugins");
  mkdirSync(mainDir, { recursive: true });

  const result = {
    appid,
    version: found.version,
    versionDir: found.versionDir,
    mainDir,
    subPackages: [],
    plugins: [],
    allJsFiles: [],
    stats: { packages: 0, totalFiles: 0, jsFiles: 0 },
    errors: [],
  };
  const jsSet = new Set();
  const addWritten = (written) => {
    for (const w of written) {
      result.stats.totalFiles += 1;
      if (w.rel.endsWith(".js")) jsSet.add(w.abs);
    }
  };

  // 1) 主包先解(若存在)
  if (found.main) {
    try {
      const buf = readFileSync(found.main.path);
      const { fileCount, written } = unpackInto(buf, appid, mainDir);
      addWritten(written);
      result.stats.packages += 1;
      log(`[main] ${found.main.filename} → ${written.length}/${fileCount} 文件 → ${mainDir}`);
    } catch (e) {
      result.errors.push({ filename: found.main.filename, error: e.message });
      log(`[main] 解包失败 ${found.main.filename}: ${e.message}`);
    }
  } else {
    log(`[main] 无 __APP__.wxapkg(可能是纯插件应用)`);
  }

  // 2) 命名分包解进同一个 mainDir(内部路径自带 root 前缀 → 天然合并)
  for (const sp of found.subPackages) {
    try {
      const buf = readFileSync(sp.path);
      const { fileCount, written } = unpackInto(buf, appid, mainDir);
      addWritten(written);
      result.stats.packages += 1;
      const root = inferSubpackageRoot(written);
      result.subPackages.push({
        filename: sp.filename, root, fileCount, files: written.map((w) => w.rel),
      });
      log(`[sub ] ${sp.filename} → ${written.length}/${fileCount} 文件 (root=${root})`);
    } catch (e) {
      result.errors.push({ filename: sp.filename, error: e.message });
      log(`[sub ] 解包失败 ${sp.filename}: ${e.message}`);
    }
  }

  // 3) 插件包单独解(内部路径是插件自身根 → 隔离到 plugins/<key>/)
  for (const pg of found.plugins) {
    try {
      const buf = readFileSync(pg.path);
      // 插件包用宿主目录 appid 解密(实测成立); 多插件同名时加序号去重
      const pluginKey = derivePluginKey(pg, result.plugins);
      const pdir = join(pluginsRoot, pluginKey);
      const { fileCount, written } = unpackInto(buf, appid, pdir);
      addWritten(written);
      result.stats.packages += 1;
      result.plugins.push({
        filename: pg.filename, key: pluginKey, dir: pdir, fileCount,
        files: written.map((w) => w.rel),
      });
      log(`[plug] ${pg.filename} → ${written.length}/${fileCount} 文件 → ${pdir}`);
    } catch (e) {
      result.errors.push({ filename: pg.filename, error: e.message });
      log(`[plug] 解包失败 ${pg.filename}: ${e.message}`);
    }
  }

  result.allJsFiles = [...jsSet].sort();
  result.stats.jsFiles = result.allJsFiles.length;
  return result;
}

/** 从分包写出的相对路径里推断 app-root 相对 root(公共目录前缀)。 */
function inferSubpackageRoot(written) {
  if (!written.length) return "";
  const parts = written.map((w) => w.rel.split("/"));
  let prefix = parts[0].slice(0, -1); // 去文件名
  for (const p of parts.slice(1)) {
    const segs = p.slice(0, -1);
    let i = 0;
    while (i < prefix.length && i < segs.length && prefix[i] === segs[i]) i++;
    prefix = prefix.slice(0, i);
    if (!prefix.length) break;
  }
  return prefix.join("/");
}

/** 为插件包生成唯一目录键。__PLUGINCODE__ → 'PLUGINCODE'; 多插件同名加序号。 */
function derivePluginKey(pg, existing) {
  let base = pg.filename.replace(/\.wxapkg$/, "").replace(/^_+|_+$/g, "") || "plugin";
  let key = base, n = 1;
  const used = new Set(existing.map((p) => p.key));
  while (used.has(key)) key = `${base}_${n++}`;
  return key;
}