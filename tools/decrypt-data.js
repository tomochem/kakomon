#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function fromBase64url(value) {
  return Buffer.from(value, "base64url");
}

function compact(value) {
  return JSON.stringify(value);
}

function buildDataJs(payload) {
  return [
    "// 復号したローカル作業用データ。公開リポジトリには入れない。",
    `window.EXAM_DATA = ${compact(payload.examData)};`,
    `window.UNIT_ORDER = ${compact(payload.unitOrder || [])};`,
    `window.EXAM_STATS = ${compact(payload.examStats || null)};`,
    ""
  ].join("\n");
}

function readPassphrase() {
  const passphrase = process.env.KAKOMON_PASSPHRASE;
  if (!passphrase) {
    throw new Error("Set KAKOMON_PASSPHRASE before running decrypt-data.js.");
  }
  return passphrase;
}

function main() {
  const inputPath = path.resolve(process.argv[2] || "data.enc.json");
  const outputPath = path.resolve(process.argv[3] || "data.js");
  const envelope = JSON.parse(fs.readFileSync(inputPath, "utf8"));

  if (envelope.format !== "kakomon-encrypted-data" || envelope.version !== 1) {
    throw new Error("Unsupported encrypted data format.");
  }

  const key = crypto.pbkdf2Sync(
    readPassphrase(),
    fromBase64url(envelope.salt),
    envelope.iterations,
    32,
    "sha256"
  );
  const encrypted = fromBase64url(envelope.ciphertext);
  const authTag = encrypted.subarray(encrypted.length - 16);
  const ciphertext = encrypted.subarray(0, encrypted.length - 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, fromBase64url(envelope.iv));
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const payload = JSON.parse(plaintext.toString("utf8"));

  fs.writeFileSync(outputPath, buildDataJs(payload), "utf8");
  console.log(`Wrote ${path.relative(process.cwd(), outputPath)}`);
}

try {
  main();
} catch (err) {
  console.error(err.message);
  process.exit(1);
}
