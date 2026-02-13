#!/usr/bin/env node

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";
import { spawnSync } from "node:child_process";

const ROOT_DIR = process.cwd();
const DEFAULT_CONFIG_PATH = path.join(ROOT_DIR, "web-vault.config.json");
const DEFAULTS = {
  releaseRepo: "dani-garcia/bw_web_builds",
  tag: "v2026.1.1",
  assetPattern: "bw_web_v*.tar.gz",
  sourceSubdir: ".",
  targetDir: "static/web-vault",
  keepSourceMaps: false,
};

function parseArgs(argv) {
  const args = {};
  for (let i = 2; i < argv.length; i += 1) {
    const current = argv[i];
    const next = argv[i + 1];

    if (current === "--config") {
      args.configPath = next;
      i += 1;
      continue;
    }
    if (current === "--repo") {
      args.releaseRepo = next;
      i += 1;
      continue;
    }
    if (current === "--release-repo") {
      args.releaseRepo = next;
      i += 1;
      continue;
    }
    if (current === "--tag") {
      args.tag = next;
      i += 1;
      continue;
    }
    if (current === "--source-subdir") {
      args.sourceSubdir = next;
      i += 1;
      continue;
    }
    if (current === "--asset-pattern") {
      args.assetPattern = next;
      i += 1;
      continue;
    }
    if (current === "--target-dir") {
      args.targetDir = next;
      i += 1;
      continue;
    }
    if (current === "--keep-sourcemaps") {
      args.keepSourceMaps = true;
      continue;
    }
    if (current === "--drop-sourcemaps") {
      args.keepSourceMaps = false;
      continue;
    }

    throw new Error(`不支持的参数: ${current}`);
  }
  return args;
}

function readJson(filePath) {
  if (!fs.existsSync(filePath)) {
    return {};
  }

  const raw = fs.readFileSync(filePath, "utf8");
  return JSON.parse(raw);
}

function runOrThrow(command, commandArgs, options = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd: options.cwd,
    encoding: "utf8",
    stdio: "pipe",
  });

  if (result.status !== 0) {
    const stderr = (result.stderr || "").trim();
    const stdout = (result.stdout || "").trim();
    const details = stderr || stdout || "未知错误";
    throw new Error(`命令执行失败: ${command} ${commandArgs.join(" ")}\n${details}`);
  }

  return result;
}

function normalizeVersion(tag) {
  return tag.startsWith("v") ? tag.slice(1) : tag;
}

function parseBool(value, defaultValue) {
  if (value === undefined || value === null) {
    return defaultValue;
  }
  if (typeof value === "boolean") {
    return value;
  }
  const normalized = String(value).trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }
  return defaultValue;
}

function relativeDepth(base, maybeChild) {
  const relative = path.relative(base, maybeChild);
  if (!relative || relative === ".") {
    return 0;
  }
  return relative.split(path.sep).length;
}

function listDirectories(root) {
  const stack = [root];
  const dirs = [];

  while (stack.length > 0) {
    const current = stack.pop();
    dirs.push(current);
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      stack.push(path.join(current, entry.name));
    }
  }

  return dirs;
}

function chooseBestSourceDir(extractedRoot, sourceSubdir) {
  const preferred = path.resolve(extractedRoot, sourceSubdir);
  const preferredBuild = path.join(preferred, "build");
  const directCandidates = [preferred, preferredBuild];
  for (const dir of directCandidates) {
    if (fs.existsSync(path.join(dir, "index.html"))) {
      return dir;
    }
  }

  const allDirs = listDirectories(extractedRoot);
  const candidates = [];
  for (const dir of allDirs) {
    if (!fs.existsSync(path.join(dir, "index.html"))) {
      continue;
    }

    let score = 0;
    if (fs.existsSync(path.join(dir, "vw-version.json"))) {
      score += 100;
    }
    if (fs.existsSync(path.join(dir, "version.json"))) {
      score += 50;
    }
    if (fs.existsSync(path.join(dir, "manifest.json"))) {
      score += 20;
    }
    if (fs.existsSync(path.join(dir, "locales"))) {
      score += 20;
    }
    if (fs.existsSync(path.join(dir, "images"))) {
      score += 10;
    }

    const depth = relativeDepth(extractedRoot, dir);
    score -= depth;
    candidates.push({ dir, score, depth });
  }

  if (candidates.length === 0) {
    throw new Error(
      `未找到 web-vault 构建目录。解压目录 ${extractedRoot} 下不存在 index.html。`,
    );
  }

  candidates.sort((a, b) => {
    if (b.score !== a.score) {
      return b.score - a.score;
    }
    return a.depth - b.depth;
  });

  return candidates[0].dir;
}

function currentVersion(targetDir) {
  const indexPath = path.join(targetDir, "index.html");
  const versionPath = path.join(targetDir, "vw-version.json");
  if (!fs.existsSync(indexPath) || !fs.existsSync(versionPath)) {
    return null;
  }

  try {
    const data = readJson(versionPath);
    return typeof data.version === "string" ? data.version : null;
  } catch {
    return null;
  }
}

function cleanupAssets(targetDir, keepSourceMaps) {
  if (!fs.existsSync(targetDir)) {
    return { removedMapFiles: 0 };
  }

  let removedMapFiles = 0;
  const files = [];
  const stack = [targetDir];
  while (stack.length > 0) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else {
        files.push(fullPath);
      }
    }
  }

  if (!keepSourceMaps) {
    for (const filePath of files) {
      if (!filePath.endsWith(".map")) {
        continue;
      }
      fs.rmSync(filePath, { force: true });
      removedMapFiles += 1;
    }
  }

  return { removedMapFiles };
}

function main() {
  const cli = parseArgs(process.argv);
  const configPath = cli.configPath
    ? path.resolve(ROOT_DIR, cli.configPath)
    : DEFAULT_CONFIG_PATH;
  const fileConfig = readJson(configPath);

  const effective = {
    releaseRepo:
      process.env.BW_WEB_BUILDS_RELEASE_REPO ??
      process.env.BW_WEB_BUILDS_REPO ??
      process.env.BW_WEB_BUILDS_REPO_URL ??
      cli.releaseRepo ??
      fileConfig.releaseRepo ??
      DEFAULTS.releaseRepo,
    tag:
      process.env.BW_WEB_BUILDS_TAG ??
      cli.tag ??
      fileConfig.tag ??
      DEFAULTS.tag,
    assetPattern:
      process.env.BW_WEB_BUILDS_ASSET_PATTERN ??
      cli.assetPattern ??
      fileConfig.assetPattern ??
      DEFAULTS.assetPattern,
    sourceSubdir:
      process.env.BW_WEB_BUILDS_SOURCE_SUBDIR ??
      cli.sourceSubdir ??
      fileConfig.sourceSubdir ??
      DEFAULTS.sourceSubdir,
    targetDir:
      process.env.BW_WEB_BUILDS_TARGET_DIR ??
      cli.targetDir ??
      fileConfig.targetDir ??
      DEFAULTS.targetDir,
    keepSourceMaps: parseBool(
      process.env.BW_WEB_BUILDS_KEEP_SOURCEMAPS ?? cli.keepSourceMaps ?? fileConfig.keepSourceMaps,
      DEFAULTS.keepSourceMaps,
    ),
  };

  const targetAbs = path.resolve(ROOT_DIR, effective.targetDir);
  const expectedVersion = normalizeVersion(effective.tag);
  const existingVersion = currentVersion(targetAbs);

  if (existingVersion === expectedVersion) {
    const cleaned = cleanupAssets(targetAbs, effective.keepSourceMaps);
    if (cleaned.removedMapFiles > 0) {
      console.log(
        `[web-vault] 已是目标版本 ${expectedVersion}，跳过下载；已清理 sourcemap ${cleaned.removedMapFiles} 个。`,
      );
    } else {
      console.log(`[web-vault] 已是目标版本 ${expectedVersion}，跳过同步。`);
    }
    return;
  }

  runOrThrow("gh", ["--version"]);
  runOrThrow("tar", ["--version"]);

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "warden-web-vault-"));
  const extractDir = path.join(tempDir, "extracted");

  try {
    fs.mkdirSync(extractDir, { recursive: true });

    console.log(
      `[web-vault] 下载 release 资产 ${effective.releaseRepo}@${effective.tag} (${effective.assetPattern}) ...`,
    );
    runOrThrow("gh", [
      "release",
      "download",
      effective.tag,
      "-R",
      effective.releaseRepo,
      "-p",
      effective.assetPattern,
      "-D",
      tempDir,
      "--clobber",
    ]);

    const assets = fs
      .readdirSync(tempDir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith(".tar.gz"))
      .map((entry) => path.join(tempDir, entry.name));

    if (assets.length === 0) {
      throw new Error("未下载到 .tar.gz 资产，请检查 tag 或 assetPattern。");
    }
    if (assets.length > 1) {
      throw new Error(
        `匹配到多个 .tar.gz 资产，请缩小 assetPattern。当前匹配: ${assets
          .map((p) => path.basename(p))
          .join(", ")}`,
      );
    }

    const assetFile = assets[0];
    console.log(`[web-vault] 解压 ${path.basename(assetFile)} ...`);
    runOrThrow("tar", ["-xzf", assetFile, "-C", extractDir]);

    const sourceAbs = chooseBestSourceDir(extractDir, effective.sourceSubdir);

    fs.rmSync(targetAbs, { recursive: true, force: true });
    fs.mkdirSync(targetAbs, { recursive: true });
    fs.cpSync(sourceAbs, targetAbs, { recursive: true, force: true });
    fs.writeFileSync(
      path.join(targetAbs, "vw-version.json"),
      `${JSON.stringify({ version: expectedVersion })}\n`,
      "utf8",
    );
    const cleaned = cleanupAssets(targetAbs, effective.keepSourceMaps);

    console.log(
      `[web-vault] 同步完成 -> ${effective.targetDir} (${expectedVersion})，来源目录: ${sourceAbs}，清理 sourcemap ${cleaned.removedMapFiles} 个。`,
    );
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

main();
