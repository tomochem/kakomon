#!/usr/bin/env node
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const FORMAT = "kakomon-encrypted-data";
const VERSION = 1;
const ITERATIONS = 310000;

function base64url(buffer) {
  return Buffer.from(buffer).toString("base64url");
}

function usage() {
  const name = path.basename(process.argv[1]);
  console.error(`Usage: node tools/${name} [input-data.js] [output-data.enc.json]`);
  console.error("Set KAKOMON_PASSPHRASE or enter a passphrase when prompted.");
}

function readHidden(prompt) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) {
      reject(new Error("KAKOMON_PASSPHRASE is required when stdin is not interactive."));
      return;
    }

    let value = "";
    process.stdout.write(prompt);
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");

    const onData = char => {
      if (char === "\u0003") {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdout.write("\n");
        reject(new Error("Canceled."));
        return;
      }
      if (char === "\r" || char === "\n") {
        process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdin.off("data", onData);
        process.stdout.write("\n");
        resolve(value);
        return;
      }
      if (char === "\b" || char === "\u007f") {
        value = value.slice(0, -1);
        return;
      }
      value += char;
    };

    process.stdin.on("data", onData);
  });
}

async function getPassphrase() {
  const passphrase = process.env.KAKOMON_PASSPHRASE || await readHidden("Passphrase: ");
  if (!passphrase || passphrase.length < 12) {
    throw new Error("Passphrase must be at least 12 characters.");
  }
  return passphrase;
}

function loadDataJs(inputPath) {
  const code = fs.readFileSync(inputPath, "utf8");
  const context = { window: {} };
  vm.runInNewContext(code, context, { filename: inputPath });

  if (!context.window.EXAM_DATA || !Array.isArray(context.window.EXAM_DATA.universities)) {
    throw new Error("window.EXAM_DATA was not found in data.js.");
  }

  return {
    examData: context.window.EXAM_DATA,
    unitOrder: context.window.UNIT_ORDER || [],
    examStats: context.window.EXAM_STATS || null
  };
}

async function main() {
  const inputPath = path.resolve(process.argv[2] || "data.js");
  const outputPath = path.resolve(process.argv[3] || "data.enc.json");

  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    usage();
    return;
  }

  const passphrase = await getPassphrase();
  const payload = loadDataJs(inputPath);
  const plaintext = Buffer.from(JSON.stringify(payload), "utf8");
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(passphrase, salt, ITERATIONS, 32, "sha256");
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);

  const envelope = {
    format: FORMAT,
    version: VERSION,
    kdf: "PBKDF2-SHA-256",
    iterations: ITERATIONS,
    salt: base64url(salt),
    iv: base64url(iv),
    ciphertext: base64url(encrypted)
  };

  fs.writeFileSync(outputPath, JSON.stringify(envelope, null, 2) + "\n", "utf8");
  console.log(`Wrote ${path.relative(process.cwd(), outputPath)}`);
}

main().catch(err => {
  console.error(err.message);
  process.exit(1);
});
