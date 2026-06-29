#!/usr/bin/env node
/**
 * wxapkg Decryptor — decrypt and extract WeChat mini program packages.
 *
 * V1MMWX encryption (PC/Mac WeChat):
 *   1. PBKDF2(password=appid, salt="saltiest", iterations=1000, keylen=32, sha1) → AES key
 *   2. IV = "the iv: 16 bytes"
 *   3. AES-256-CBC decrypt first 1024 encrypted bytes → take first 1023 (drop PKCS7 pad)
 *   4. XOR key = appid[len-2] (second-to-last character of appid)
 *   5. XOR remaining encrypted bytes (enc[1024..]) with XOR key
 *   6. Result = AES[0..1022] + XOR'd rest
 *
 * Usage:
 *   node scripts/wxapkg-decrypt.mjs <wxapkg-path> [appid] [output-dir]
 *   node scripts/wxapkg-decrypt.mjs --list    # list cached mini programs
 *   node scripts/wxapkg-decrypt.mjs --active  # find & decrypt active mini program
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import { join, basename, dirname } from "node:path";
import { createDecipheriv, pbkdf2Sync } from "node:crypto";
import { homedir, platform } from "node:os";
import { execSync } from "node:child_process";

function detectWxapkgRoot() {
  const home = homedir();
  const candidates =
    platform() === "win32"
      ? [
          join(home, "Documents/WeChat Files/Applet"),
          join(home, "Documents/WeChat Files/wxamp"),
        ]
      : [
          join(home, "Library/Containers/com.tencent.xinWeChat/Data/Documents/app_data/radium/Applet/packages"),
        ];
  for (const c of candidates) {
    if (existsSync(c)) return c;
  }
  return candidates[0];
}

const WXAPKG_ROOT = process.env.WXAPKG_ROOT || detectWxapkgRoot();

const HEADER = Buffer.from("V1MMWX");
const SALT = "saltiest";
const IV = Buffer.from("the iv: 16 bytes");
const ITERATIONS = 1000;
const KEY_LEN = 32;
const AES_BLOCK = 1024;

function deriveKey(appid) {
  return pbkdf2Sync(appid, SALT, ITERATIONS, KEY_LEN, "sha1");
}

function decryptWxapkg(buf, appid) {
  if (!buf.subarray(0, 6).equals(HEADER)) {
    throw new Error("Not a V1MMWX encrypted wxapkg (wrong header)");
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
  const aesUsable = AES_BLOCK - 1; // 1023 bytes (drop PKCS7 padding byte)
  const xorPart = encrypted.subarray(AES_BLOCK);

  const result = Buffer.alloc(aesUsable + xorPart.length);
  decrypted.copy(result, 0, 0, aesUsable);
  for (let i = 0; i < xorPart.length; i++) {
    result[aesUsable + i] = xorPart[i] ^ xorKey;
  }
  return result;
}

function parseWxapkg(buf) {
  let offset = 0;
  const firstMark = buf.readUInt8(offset); offset += 1;
  const unknown1 = buf.readUInt32BE(offset); offset += 4;
  const indexInfoLength = buf.readUInt32BE(offset); offset += 4;
  const bodyInfoLength = buf.readUInt32BE(offset); offset += 4;
  const lastMark = buf.readUInt8(offset); offset += 1;

  if (firstMark !== 0xbe || lastMark !== 0xed) {
    throw new Error(`Invalid wxapkg marks: first=0x${firstMark.toString(16)} last=0x${lastMark.toString(16)}`);
  }

  const fileCount = buf.readUInt32BE(offset); offset += 4;
  const files = [];
  for (let i = 0; i < fileCount; i++) {
    if (offset + 4 > buf.length) break;
    const nameLen = buf.readUInt32BE(offset); offset += 4;
    if (nameLen > 4096 || offset + nameLen + 8 > buf.length) break;
    const name = buf.subarray(offset, offset + nameLen).toString("utf8"); offset += nameLen;
    const fileOffset = buf.readUInt32BE(offset); offset += 4;
    const fileSize = buf.readUInt32BE(offset); offset += 4;
    files.push({ name, offset: fileOffset, size: fileSize });
  }
  return { fileCount, files };
}

function extractWxapkg(buf, outputDir, parsed) {
  mkdirSync(outputDir, { recursive: true });
  const textExts = new Set(["js", "json", "wxml", "wxss", "html", "css", "wxs"]);
  for (const f of parsed.files) {
    const outPath = join(outputDir, f.name);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, buf.subarray(f.offset, f.offset + f.size));
    const ext = f.name.split(".").pop();
    const tag = textExts.has(ext) ? "" : " [binary]";
    console.log(`  ${f.name} (${f.size} bytes)${tag}`);
  }
}

function findActiveAppId() {
  try {
    const cmd = platform() === "win32"
      ? 'wmic process where "name like \'%WeChatAppEx%\'" get CommandLine /format:list'
      : "ps aux";
    const ps = execSync(cmd, { encoding: "utf8" });
    const match = ps.match(/--wmpf-appid[=\s](wx[a-f0-9]{16})/);
    if (match) return match[1];
  } catch {}
  return null;
}

function findLatestWxapkg(appid) {
  const appDir = join(WXAPKG_ROOT, appid);
  if (!existsSync(appDir)) return null;
  const versions = readdirSync(appDir)
    .filter((v) => /^\d+$/.test(v))
    .sort((a, b) => Number(b) - Number(a));
  for (const v of versions) {
    const vdir = join(appDir, v);
    const app = join(vdir, "__APP__.wxapkg");
    if (existsSync(app)) return { main: app, version: v, dir: vdir };
  }
  return null;
}

function listAppIds() {
  console.log(`wxapkg 缓存目录: ${WXAPKG_ROOT}\n`);
  try {
    const dirs = readdirSync(WXAPKG_ROOT).filter((d) => d.startsWith("wx") || d.startsWith("tt"));
    console.log(`找到 ${dirs.length} 个小程序:`);
    for (const d of dirs) {
      const subdir = join(WXAPKG_ROOT, d);
      try {
        const versions = readdirSync(subdir).filter((v) => /^\d+$/.test(v));
        const pkgs = [];
        for (const v of versions) {
          const vdir = join(subdir, v);
          const files = readdirSync(vdir).filter((f) => f.endsWith(".wxapkg"));
          pkgs.push(...files.map((f) => `v${v}/${f}`));
        }
        console.log(`  ${d}  (${pkgs.length} 个包: ${pkgs.join(", ")})`);
      } catch {
        console.log(`  ${d}  (读取失败)`);
      }
    }
  } catch (e) {
    console.error("读取目录失败:", e.message);
  }
}

function scanApiCalls(outputDir) {
  console.log("\n🔍 扫描 API 调用与加密逻辑...\n");
  const results = { requests: [], crypto: [], storage: [] };
  const jsFiles = [];

  function walk(dir) {
    for (const f of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, f.name);
      if (f.isDirectory()) walk(full);
      else if (f.name.endsWith(".js")) jsFiles.push(full);
    }
  }
  walk(outputDir);

  const patterns = [
    { category: "requests", re: /wx\.(request|uploadFile|downloadFile)\s*\(/g, label: "网络请求" },
    { category: "requests", re: /url\s*:\s*["'`]([^"'`]+)["'`]/g, label: "URL" },
    { category: "crypto", re: /(encrypt|decrypt|sign|hmac|md5|sha\d*|aes|rsa|base64|crypto)/gi, label: "加密关键字" },
    { category: "crypto", re: /["'](secret|key|token|salt|iv|nonce)["']\s*[,:]/gi, label: "密钥字段" },
    { category: "storage", re: /wx\.(getStorage|setStorage|getStorageSync|setStorageSync)\s*\(/g, label: "本地存储" },
  ];

  for (const jsPath of jsFiles) {
    const code = readFileSync(jsPath, "utf8");
    const rel = jsPath.replace(outputDir, "");
    for (const p of patterns) {
      let m;
      while ((m = p.re.exec(code)) !== null) {
        const line = code.substring(0, m.index).split("\n").length;
        const ctx = code.substring(Math.max(0, m.index - 30), Math.min(code.length, m.index + m[0].length + 50)).replace(/\n/g, " ").trim();
        results[p.category].push({ file: rel, line, match: m[0], context: ctx, label: p.label });
      }
    }
  }

  if (results.requests.length) {
    console.log(`📡 网络请求 (${results.requests.length} 处):`);
    const seen = new Set();
    for (const r of results.requests) {
      const key = `${r.file}:${r.line}:${r.match}`;
      if (seen.has(key)) continue;
      seen.add(key);
      console.log(`  ${r.file}:${r.line}  ${r.label}: ${r.context.substring(0, 80)}`);
    }
  }
  if (results.crypto.length) {
    console.log(`\n🔐 加密/签名 (${results.crypto.length} 处):`);
    const seen = new Set();
    for (const r of results.crypto) {
      const key = `${r.file}:${r.line}:${r.match}`;
      if (seen.has(key)) continue;
      seen.add(key);
      console.log(`  ${r.file}:${r.line}  ${r.label}: ${r.context.substring(0, 80)}`);
    }
  }
  if (results.storage.length) {
    console.log(`\n💾 本地存储 (${results.storage.length} 处):`);
    const seen = new Set();
    for (const r of results.storage) {
      const key = `${r.file}:${r.line}:${r.match}`;
      if (seen.has(key)) continue;
      seen.add(key);
      console.log(`  ${r.file}:${r.line}  ${r.label}: ${r.context.substring(0, 80)}`);
    }
  }
  return results;
}

function main() {
  const args = process.argv.slice(2);

  if (args[0] === "--list-appids" || args[0] === "--list") {
    listAppIds();
    return;
  }

  if (args[0] === "--active") {
    const appid = findActiveAppId();
    if (!appid) {
      console.error("未检测到运行中的小程序 (ps 中无 --wmpf-appid)");
      process.exit(1);
    }
    console.log(`检测到活跃小程序: ${appid}`);
    const pkg = findLatestWxapkg(appid);
    if (!pkg) {
      console.error(`未找到 ${appid} 的 wxapkg 缓存`);
      process.exit(1);
    }
    args[0] = pkg.main;
    args[1] = appid;
    console.log(`使用缓存: ${pkg.main} (版本 ${pkg.version})\n`);
  }

  if (args.length < 1) {
    console.log("用法:");
    console.log("  node scripts/wxapkg-decrypt.mjs <wxapkg路径> [appid] [输出目录]");
    console.log("  node scripts/wxapkg-decrypt.mjs --list     # 列出已缓存小程序");
    console.log("  node scripts/wxapkg-decrypt.mjs --active   # 解密当前运行的小程序");
    console.log("");
    console.log("示例:");
    console.log("  node scripts/wxapkg-decrypt.mjs ~/.../wx123456/1/__APP__.wxapkg wx123456");
    return;
  }

  const wxapkgPath = args[0];
  let appid = args[1];
  if (!appid) {
    const match = wxapkgPath.match(/(wx[a-f0-9]{16})/);
    if (match) appid = match[1];
    else {
      console.error("无法自动检测 appid，请手动指定");
      process.exit(1);
    }
  }
  const outputDir = args[2] || join(dirname(wxapkgPath), `${basename(wxapkgPath, ".wxapkg")}_extracted`);

  console.log(`解密 wxapkg: ${wxapkgPath}`);
  console.log(`appid: ${appid}`);
  console.log(`XOR key: 0x${appid.charCodeAt(appid.length - 2).toString(16)} ('${appid[appid.length - 2]}')`);
  console.log(`输出: ${outputDir}`);

  const raw = readFileSync(wxapkgPath);
  console.log(`文件大小: ${raw.length} bytes`);

  let plain;
  if (raw.subarray(0, 6).equals(HEADER)) {
    console.log("检测到 V1MMWX 加密头，解密中...");
    plain = decryptWxapkg(raw, appid);
  } else if (raw[0] === 0xbe) {
    console.log("未加密 wxapkg，直接解析...");
    plain = raw;
  } else {
    console.error("未知文件格式");
    process.exit(1);
  }

  const parsed = parseWxapkg(plain);
  console.log(`\n包含 ${parsed.fileCount} 个文件 (解析到 ${parsed.files.length} 个):\n`);

  extractWxapkg(plain, outputDir, parsed);
  console.log(`\n✅ ${parsed.files.length} 个文件提取到 ${outputDir}`);

  scanApiCalls(outputDir);
}

main();
