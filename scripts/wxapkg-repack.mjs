#!/usr/bin/env node
/**
 * wxapkg Repacker — re-encrypt (V1MMWX) and re-pack (0xBE) WeChat mini program
 * packages, the inverse of scripts/wxapkg-decrypt.mjs. Enables "魔改插桩":
 * decrypt → modify JS → repack → re-encrypt → replace cache.
 *
 * V1MMWX re-encryption (inverse of decrypt; symmetric, key fully known):
 *   1. key  = PBKDF2(appid, "saltiest", 1000, 32, sha1)
 *   2. iv   = "the iv: 16 bytes"
 *   3. plaintext wxapkg (0xBE...) = firstPart(1023 bytes) ++ rest
 *   4. aesBlock = AES-256-CBC-encrypt(firstPart ++ padByte[0x01])  → 1024 bytes
 *   5. encRest  = rest XOR appid[len-2]
 *   6. V1MMWX   = "V1MMWX" ++ aesBlock ++ encRest
 *   (padByte is dropped on decrypt, so its value is free — round-trip exact.)
 *
 * 0xBE repack (inverse of parse/extract):
 *   header(14B) = 0xBE + u32 unknown1(0) + u32 indexLen + u32 bodyLen + 0xED
 *   then u32 fileCount + [u32 nameLen + name + u32 offset + u32 size]*
 *   then file bodies. Offsets absolute from buffer start.
 *
 * Usage:
 *   node scripts/wxapkg-repack.mjs verify-crypto <encrypted-wxapkg> <appid>
 *       — decrypt then re-encrypt, assert byte-identical (validates crypto)
 *   node scripts/wxapkg-repack.mjs verify-pack <encrypted-wxapkg> <appid>
 *       — decrypt→parse→repack→parse, assert same files+content
 *   node scripts/wxapkg-repack.mjs pack <dir> <out-0xBE.wxapkg>
 *   node scripts/wxapkg-repack.mjs encrypt <0xBE.wxapkg> <appid> <out-V1MMWX.wxapkg>
 *   node scripts/wxapkg-repack.mjs decrypt <V1MMWX.wxapkg> <appid> <out-0xBE.wxapkg>
 *
 * ⚠️ 仅用于对【自有 / 已授权】小程序的安全分析与接口对接。
 */
import { readFileSync, writeFileSync, mkdirSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative, sep } from "node:path";
import { createCipheriv, createDecipheriv, pbkdf2Sync } from "node:crypto";

const HEADER = Buffer.from("V1MMWX");
const SALT = "saltiest";
const IV = Buffer.from("the iv: 16 bytes");
const ITERATIONS = 1000;
const KEY_LEN = 32;
const AES_BLOCK = 1024;

function deriveKey(appid) {
  return pbkdf2Sync(appid, SALT, ITERATIONS, KEY_LEN, "sha1");
}

// ── V1MMWX crypto ───────────────────────────────────────────────────
export function decryptV1MMWX(buf, appid) {
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
  const aesUsable = AES_BLOCK - 1; // 1023
  const xorPart = encrypted.subarray(AES_BLOCK);
  const result = Buffer.alloc(aesUsable + xorPart.length);
  decrypted.copy(result, 0, 0, aesUsable);
  for (let i = 0; i < xorPart.length; i++) {
    result[aesUsable + i] = xorPart[i] ^ xorKey;
  }
  return result;
}

export function encryptV1MMWX(plain, appid, padByte = 0x01) {
  const key = deriveKey(appid);
  const xorKey = appid.charCodeAt(appid.length - 2);
  const aesUsable = AES_BLOCK - 1; // 1023
  // firstPart (1023) + padByte → 1024 → AES encrypt
  const aesInput = Buffer.alloc(AES_BLOCK);
  plain.copy(aesInput, 0, 0, Math.min(aesUsable, plain.length));
  aesInput[aesUsable] = padByte;
  const cipher = createCipheriv("aes-256-cbc", key, IV);
  cipher.setAutoPadding(false);
  const aesBlock = Buffer.concat([cipher.update(aesInput), cipher.final()]); // 1024
  // rest (plain[1023..]) XOR xorKey
  const rest = plain.subarray(aesUsable);
  const encRest = Buffer.alloc(rest.length);
  for (let i = 0; i < rest.length; i++) encRest[i] = rest[i] ^ xorKey;
  return Buffer.concat([HEADER, aesBlock, encRest]);
}

// ── 0xBE parse / pack ───────────────────────────────────────────────
export function parseWxapkg(buf) {
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
    const nameLen = buf.readUInt32BE(offset); offset += 4;
    const name = buf.subarray(offset, offset + nameLen).toString("utf8"); offset += nameLen;
    const fileOffset = buf.readUInt32BE(offset); offset += 4;
    const fileSize = buf.readUInt32BE(offset); offset += 4;
    files.push({ name, offset: fileOffset, size: fileSize, data: buf.subarray(fileOffset, fileOffset + fileSize) });
  }
  return { unknown1, indexInfoLength, bodyInfoLength, fileCount, files };
}

/**
 * Pack files [{name, data}] into a 0xBE wxapkg buffer.
 * Preserves the original file order (important — pass files from parseWxapkg).
 */
export function packWxapkg(files, unknown1 = 0) {
  // index section length = u32 fileCount + per-file (u32 nameLen + name + u32 off + u32 size)
  let indexLen = 4;
  for (const f of files) {
    indexLen += 4 + Buffer.byteLength(f.name, "utf8") + 4 + 4;
  }
  const bodyStart = 14 + indexLen;
  let bodyLen = 0;
  for (const f of files) bodyLen += f.data.length;

  const out = Buffer.alloc(bodyStart + bodyLen);
  let o = 0;
  out.writeUInt8(0xbe, o); o += 1;
  out.writeUInt32BE(unknown1, o); o += 4;
  out.writeUInt32BE(indexLen, o); o += 4;
  out.writeUInt32BE(bodyLen, o); o += 4;
  out.writeUInt8(0xed, o); o += 1;
  out.writeUInt32BE(files.length, o); o += 4;

  // First pass: compute body offsets
  let bodyCursor = bodyStart;
  const offsets = [];
  for (const f of files) {
    offsets.push(bodyCursor);
    bodyCursor += f.data.length;
  }
  // Write index entries
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    const nameBuf = Buffer.from(f.name, "utf8");
    out.writeUInt32BE(nameBuf.length, o); o += 4;
    nameBuf.copy(out, o); o += nameBuf.length;
    out.writeUInt32BE(offsets[i], o); o += 4;
    out.writeUInt32BE(f.data.length, o); o += 4;
  }
  // Write bodies
  for (let i = 0; i < files.length; i++) {
    files[i].data.copy(out, offsets[i]);
  }
  return out;
}

// ── helpers ─────────────────────────────────────────────────────────
function readDirFiles(dir) {
  const files = [];
  function walk(d) {
    for (const ent of readdirSync(d, { withFileTypes: true })) {
      const full = join(d, ent.name);
      if (ent.isDirectory()) walk(full);
      else {
        const rel = "/" + relative(dir, full).split(sep).join("/");
        files.push({ name: rel, data: readFileSync(full) });
      }
    }
  }
  walk(dir);
  return files;
}

// ── verification ────────────────────────────────────────────────────
function verifyCrypto(encPath, appid) {
  const orig = readFileSync(encPath);
  const plain = decryptV1MMWX(orig, appid);
  const reenc = encryptV1MMWX(plain, appid);
  const identical = reenc.equals(orig);
  console.log(`原始加密包: ${orig.length} bytes`);
  console.log(`解密后明文: ${plain.length} bytes (header 0x${plain[0].toString(16)})`);
  console.log(`重加密结果: ${reenc.length} bytes`);
  console.log(identical
    ? "✅ 加密往返【字节级一致】encrypt(decrypt(x)) == x"
    : "❌ 加密往返不一致!");
  if (!identical) {
    // find first diff
    const n = Math.min(reenc.length, orig.length);
    for (let i = 0; i < n; i++) {
      if (reenc[i] !== orig[i]) {
        console.log(`  首个差异 @ byte ${i}: orig=0x${orig[i].toString(16)} reenc=0x${reenc[i].toString(16)}`);
        break;
      }
    }
    if (reenc.length !== orig.length) console.log(`  长度差: orig=${orig.length} reenc=${reenc.length}`);
  }
  return identical;
}

function verifyPack(encPath, appid) {
  const orig = readFileSync(encPath);
  const plain = decryptV1MMWX(orig, appid);
  const parsed = parseWxapkg(plain);
  console.log(`解密明文: ${plain.length} bytes, ${parsed.fileCount} files`);
  console.log(`  indexLen=${parsed.indexInfoLength} bodyLen=${parsed.bodyInfoLength}`);
  const repacked = packWxapkg(parsed.files, parsed.unknown1);
  const reparsed = parseWxapkg(repacked);
  // Compare file sets + content
  let ok = reparsed.fileCount === parsed.fileCount;
  let contentOk = true;
  for (let i = 0; i < parsed.fileCount; i++) {
    const a = parsed.files[i], b = reparsed.files[i];
    if (a.name !== b.name || !a.data.equals(b.data)) { contentOk = false; break; }
  }
  const byteIdentical = repacked.equals(plain);
  console.log(`重打包: ${repacked.length} bytes, ${reparsed.fileCount} files`);
  console.log(`  文件名+内容一致: ${contentOk ? "✅" : "❌"}`);
  console.log(`  与原明文字节级一致: ${byteIdentical ? "✅" : "⚠️ 否(可能 offset 布局不同,但内容一致即可用)"}`);
  // Full re-encrypt round trip through pack
  const reenc = encryptV1MMWX(repacked, appid);
  const redecrypt = decryptV1MMWX(reenc, appid);
  const fullOk = redecrypt.equals(repacked);
  console.log(`  pack→encrypt→decrypt 往返一致: ${fullOk ? "✅" : "❌"}`);
  return ok && contentOk && fullOk;
}

function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "verify-crypto") {
    const [encPath, appid] = rest;
    process.exit(verifyCrypto(encPath, appid) ? 0 : 1);
  } else if (cmd === "verify-pack") {
    const [encPath, appid] = rest;
    process.exit(verifyPack(encPath, appid) ? 0 : 1);
  } else if (cmd === "decrypt") {
    const [inPath, appid, outPath] = rest;
    const plain = decryptV1MMWX(readFileSync(inPath), appid);
    writeFileSync(outPath, plain);
    console.log(`解密 → ${outPath} (${plain.length} bytes)`);
  } else if (cmd === "encrypt") {
    const [inPath, appid, outPath] = rest;
    const enc = encryptV1MMWX(readFileSync(inPath), appid);
    writeFileSync(outPath, enc);
    console.log(`加密 → ${outPath} (${enc.length} bytes)`);
  } else if (cmd === "pack") {
    const [dir, outPath] = rest;
    const files = readDirFiles(dir);
    const buf = packWxapkg(files);
    writeFileSync(outPath, buf);
    console.log(`打包 ${files.length} 文件 → ${outPath} (${buf.length} bytes)`);
  } else {
    console.error("用法: verify-crypto|verify-pack|decrypt|encrypt|pack — 见文件头注释");
    process.exit(1);
  }
}

main();
