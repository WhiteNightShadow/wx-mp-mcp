/**
 * 模块0: 微信小程序缓存「包根目录」探测 (wx-roots)
 *
 * ── 为什么需要它 ─────────────────────────────────────────────────────────
 * 不同微信版本 / 多账号登录会把 .wxapkg 缓存放在【不同层级】，硬编码单一路径
 * (旧实现只认 radium/Applet/packages) 会导致一部分用户「找不到任何缓存包」。
 * 实测已知的几种 Mac 布局:
 *   A) radium/Applet/packages/<appid>/<ver>/*.wxapkg          ← 常见(单/共享)
 *   B) radium/users/<账号哈希>/.../<appid>/<ver>/*.wxapkg     ← 多账号 / 新版
 *   C) radium/Applet/<账号哈希>/.../packages/<appid>/...      ← 变体
 * Windows 同理:WeChat Files / xwechat 下也有账号子目录分叉。
 *
 * ── 策略 ─────────────────────────────────────────────────────────────────
 * 不再写死路径，而是从若干「锚点根」(radium / WeChat Files 等) 出发，
 * 有界递归(默认深度 6)寻找所有满足「直接含 <appid>/<数字版本>/*.wxapkg」的目录，
 * 把它们全部作为【包根】返回。多账号 = 多个包根，调用方合并即可。
 *
 * WXAPKG_ROOT 环境变量仍可手动覆盖，支持用 path.delimiter(: 或 ;)传多个路径。
 *
 * 导出:
 *   - APPID_RE            appid 目录名正则 (wx/tt + 16 hex)
 *   - detectWxapkgRoots() 探测并返回所有包根目录数组(可能为空)
 *   - WXAPKG_ROOTS        模块加载时探测一次的结果数组
 *   - WXAPKG_ROOT         主包根(WXAPKG_ROOTS[0] 或回退默认值)，向后兼容旧 API
 */
import { readdirSync, existsSync, statSync, realpathSync } from "node:fs";
import { join, delimiter, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir, platform } from "node:os";

export const APPID_RE = /^(wx[0-9a-f]{16}|tt[0-9a-f]{16})$/i;

const MAX_SCAN_DEPTH = 6;
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

// 递归时跳过的「重目录」(聊天文件/媒体/备份/缓存等，永远不含 wxapkg)。
// 既提速，也避免去扫 xwechat_files 下几十 GB 的聊天归档。
// 注意：包路径组件(radium/Applet/packages/users/<wxid>/<appid>/<版本>)均不在此表。
const SKIP_DIR_NAMES = new Set([
  "msg", "filestorage", "file", "attach", "attachment", "favorite",
  "video", "image", "img", "voice", "audio", "emoji", "emoticon", "sns",
  "backup", "all_users", "db_storage", "cache", "wmpfcache", "web", "xworker",
  "mmkv", "crashinfo", "log", "logs", "temp", "tmp", "matrix", "xeditor", "xfile",
]);

// 扫描过程中收集的权限错误(EPERM/EACCES)，供上层诊断 macOS TCC 容器保护。
const _accessErrors = [];

function safeReaddir(dir) {
  try { return readdirSync(dir); }
  catch (e) {
    if (e && (e.code === "EPERM" || e.code === "EACCES")) {
      _accessErrors.push({ dir, code: e.code });
    }
    return null;
  }
}
function isDir(p) {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

/** 返回扫描期间收集到的权限错误快照。 */
function accessErrorsSnapshot() {
  return _accessErrors.slice();
}

/** 某版本目录是否含 .wxapkg。 */
function versionDirHasPkg(dir) {
  const entries = safeReaddir(dir);
  return !!entries && entries.some((f) => f.endsWith(".wxapkg"));
}

/**
 * 判断 dir 是否「包根」: 直接含至少一个 <appid>/<数字版本>/*.wxapkg。
 * 用 .wxapkg 实测过滤，避免把账号下的 storage 目录(同样以 appid 命名但无版本包)误判。
 */
export function isPackageRoot(dir) {
  const entries = safeReaddir(dir);
  if (!entries) return false;
  for (const e of entries) {
    if (!APPID_RE.test(e)) continue;
    const appDir = join(dir, e);
    const versions = safeReaddir(appDir);
    if (!versions) continue;
    for (const v of versions) {
      if (!/^\d+$/.test(v)) continue;
      const vdir = join(appDir, v);
      if (isDir(vdir) && versionDirHasPkg(vdir)) return true;
    }
  }
  return false;
}

function scanForPackageRoots(dir, out, depth) {
  if (depth > MAX_SCAN_DEPTH || !isDir(dir)) return;
  if (isPackageRoot(dir)) {
    out.add(dir);
    return; // 找到包根即停，不再下钻其内部的 <appid>/<ver>
  }
  if (depth === MAX_SCAN_DEPTH) return;
  const entries = safeReaddir(dir);
  if (!entries) return;
  for (const e of entries) {
    // appid 命名的叶子目录不是「中转目录」(包根已在上一层命中)，跳过省时
    if (APPID_RE.test(e)) continue;
    if (SKIP_DIR_NAMES.has(e.toLowerCase())) continue; // 跳过聊天/媒体/缓存等重目录
    const child = join(dir, e);
    if (isDir(child)) scanForPackageRoots(child, out, depth + 1);
  }
}

/** 平台对应的探测锚点(从这些目录开始递归找包根)。 */
function anchorDirs() {
  const home = homedir();
  // 副本兜底锚点(所有平台):把受保护的 packages 复制到这些无保护位置即可被自动发现。
  const copyAnchors = [
    join(REPO_ROOT, "wxapkg-cache"),
    join(process.cwd(), "wxapkg-cache"),
    join(home, "Desktop", "wxapkg-cache"),
    join(home, "Downloads", "wxapkg-cache"),
  ];
  if (platform() === "win32") {
    const appdata = process.env.APPDATA || "";          // …/AppData/Roaming
    const localAppData = process.env.LOCALAPPDATA || ""; // …/AppData/Local
    return [
      // 微信 4.0 (xwechat / 新版)：小程序 wxapkg 在 %APPDATA%/Tencent/xwechat/radium/Applet
      join(appdata, "Tencent/xwechat/radium"),
      join(appdata, "Tencent/xwechat"),
      join(home, "Documents/xwechat_files"),  // 新版数据根(主要是聊天文件，偶有账号级 applet 缓存)
      // 旧版微信 3.x：Documents/WeChat Files/Applet
      join(home, "Documents/WeChat Files"),
      join(home, "Documents/Tencent Files"),
      join(appdata, "Tencent/WeChat"),
      localAppData ? join(localAppData, "Tencent/xwechat") : "",
      ...copyAnchors,
    ].filter(Boolean);
  }
  // macOS: 大小写两种 bundle id 都试(xinWeChat / xinWechat)，文件系统通常大小写不敏感，留作保险。
  return [
    join(home, "Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium"),
    join(home, "Library/Containers/com.tencent.xinWechat/Data/Documents/app_data/radium"),
    ...copyAnchors,
  ];
}

/** macOS 沙盒容器根(用于权限探测)。 */
function macContainerProbes() {
  const home = homedir();
  return [
    join(home, "Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium"),
    join(home, "Library/Containers/com.tencent.xinWechat/Data/Documents/app_data/radium"),
  ];
}

/**
 * 诊断微信容器是否因 macOS 权限(TCC / 完全磁盘访问)而不可读。
 * existsSync 在 EPERM 时也返回 false(与「不存在」无法区分)，故用 statSync 捕获 code。
 * 返回 { blocked:bool, blockedPaths:[], hint:string }。
 */
export function diagnoseAccess() {
  const errors = [...accessErrorsSnapshot()];
  if (platform() === "darwin") {
    for (const p of macContainerProbes()) {
      try { readdirSync(p); }
      catch (e) {
        if (e && (e.code === "EPERM" || e.code === "EACCES")) errors.push({ dir: p, code: e.code });
      }
    }
  }
  const blockedPaths = [...new Set(errors.filter((e) => e.code === "EPERM" || e.code === "EACCES").map((e) => e.dir))];
  const blocked = blockedPaths.length > 0;
  const hint = blocked
    ? [
        "⚠️ 微信容器目录受 macOS 权限保护(TCC)，当前进程无权读取。",
        "这通常是【拉起本 MCP 的程序】缺少『完全磁盘访问权限』。两种解法:",
        "  ① 推荐(不用复制):系统设置 → 隐私与安全性 → 完全磁盘访问权限 →",
        "     添加运行 MCP 的程序(Terminal / iTerm / Cursor / Claude) → 完全退出再重开。",
        "  ② 兜底(复制副本):用访达把 packages 目录复制到下列任一位置,会被自动发现:",
        `       ${join(REPO_ROOT, "wxapkg-cache")}`,
        "       ~/Desktop/wxapkg-cache  或  ~/Downloads/wxapkg-cache",
        "     或复制到任意目录后设环境变量 WXAPKG_ROOT 指向它。",
      ].join("\n")
    : "";
  return { blocked, blockedPaths, hint };
}

/** 回退默认值(探测不到任何包根时用，仅用于展示/报错提示)。 */
export function defaultRoot() {
  const home = homedir();
  return platform() === "win32"
    ? join(home, "Documents/WeChat Files/Applet")
    : join(home, "Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium/Applet/packages");
}

/**
 * 探测所有包根目录。
 * - 设了 WXAPKG_ROOT 环境变量 → 按 path.delimiter 拆成多个路径直接用(不递归)。
 * - 否则从锚点递归探测，返回去重后的包根数组(可能为空)。
 */
export function detectWxapkgRoots() {
  const env = process.env.WXAPKG_ROOT;
  if (env && env.trim()) {
    return dedupByRealpath(env.split(delimiter).map((s) => s.trim()).filter(Boolean));
  }
  const out = new Set();
  for (const a of anchorDirs()) scanForPackageRoots(a, out, 0);
  return dedupByRealpath([...out]);
}

/** 按真实路径去重(大小写不敏感文件系统上 xinWeChat / xinWechat 会指向同一目录)。 */
function dedupByRealpath(paths) {
  const caseInsensitive = platform() === "win32" || platform() === "darwin";
  const seen = new Map(); // 归一 key → 原始路径(保留首个)
  for (const p of paths) {
    let key;
    try { key = realpathSync(p); } catch { key = p; }
    if (caseInsensitive) key = key.toLowerCase();
    if (!seen.has(key)) seen.set(key, p);
  }
  return [...seen.values()];
}

export const WXAPKG_ROOTS = detectWxapkgRoots();

/** 主包根:第一个探测到的，或回退默认值。向后兼容只认单根的旧调用。 */
export const WXAPKG_ROOT = WXAPKG_ROOTS[0] || defaultRoot();
