import { readFile, writeFile, mkdir, copyFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { stripTypeScriptTypes } from "node:module";
import { parseOptions, packageManifest } from "./build-support.mjs";

const root = path.dirname(fileURLToPath(import.meta.url));
const platforms = { win32: "windows", linux: "linux", darwin: "macos" };
const architectures = { x64: "x86_64", arm64: "aarch64" };
const platform = `${platforms[process.platform]}_${architectures[process.arch]}`;
if (!platforms[process.platform] || !architectures[process.arch]) throw new Error("Unsupported demonstration build platform");

/** Argument arrays keep paths out of shell evaluation and preserve the real exit status of each build step. */
function run(program, args) {
  const result = spawnSync(program, args, { cwd: root, stdio: "inherit", shell: false });
  if (result.error || result.status !== 0) throw new Error(`Build command failed: ${program}`);
}

const { paths: options, nativeOnly } = parseOptions(process.argv.slice(2));
const targetDirectory = options.get("--target-dir") ?? path.join(root, "target");
run("cargo", ["build", "--release", "--manifest-path", path.join(root, "Cargo.toml"), "--target-dir", targetDirectory]);
const staging = path.join(root, "staging", nativeOnly ? "native" : "full");
await mkdir(path.join(staging, "bin"), { recursive: true });
if (!nativeOnly) await mkdir(path.join(staging, "web"), { recursive: true });
await mkdir(path.join(root, "dist"), { recursive: true });
const executable = process.platform === "win32" ? "workbench-demo.exe" : "workbench-demo";
const packageExecutable = process.platform === "win32" ? "bin/backend.exe" : "bin/backend";
await copyFile(path.join(targetDirectory, "release", executable), path.join(staging, packageExecutable));
if (!nativeOnly) {
  for (const asset of ["index.html", "style.css", "main.js"]) await copyFile(path.join(root, "web", asset), path.join(staging, "web", asset));
  const sdk = await readFile(path.join(root, "../../frontend/index.ts"), "utf8");
  await writeFile(path.join(staging, "web/sdk.js"), stripTypeScriptTypes(sdk, { mode: "strip" }));
}
const manifest = packageManifest(JSON.parse(await readFile(path.join(root, "manifest.template.json"), "utf8")), platform, packageExecutable, nativeOnly);
const manifestPath = path.join(staging, "manifest.json");
await writeFile(manifestPath, JSON.stringify(manifest, null, 2));
const output = options.get("--out") ?? path.join(root, "dist", `workbench-demo-1.0.0-${nativeOnly ? "native-" : ""}${platform}.tar`);
const packArgs = ["pack", "--manifest", manifestPath, "--assets", staging, "--out", output];
if (options.has("--tool")) run(options.get("--tool"), packArgs);
else run("cargo", ["run", "--manifest-path", path.join(root, "../../tools/Cargo.toml"), "--bin", "kerminal-plugin", "--", ...packArgs]);
console.log(`Unsigned development artifact: ${output}`);
