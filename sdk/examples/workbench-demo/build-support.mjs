import path from "node:path";

/** Flags are parsed before building so malformed invocations cannot leave a half-built package behind. */
export function parseOptions(args) {
  const paths = new Map();
  let nativeOnly = false;
  for (let index = 0; index < args.length; index++) {
    const name = args[index];
    if (name === "--native-only" && !nativeOnly) { nativeOnly = true; continue; }
    if (!["--tool", "--out", "--target-dir"].includes(name) || paths.has(name) || !args[index + 1] || args[index + 1].startsWith("--")) {
      throw new Error("Usage: node build.mjs [--native-only] [--tool PATH] [--out PATH] [--target-dir PATH]");
    }
    paths.set(name, path.resolve(args[++index]));
  }
  return { paths, nativeOnly };
}

/** Native releases omit every WebView contribution and asset instead of advertising an unavailable host surface. */
export function packageManifest(template, platform, packageExecutable, nativeOnly) {
  const manifest = structuredClone(template);
  manifest.platforms = [platform];
  manifest.entrypoints.process = [{ platform, path: packageExecutable }];
  manifest.files[0].path = packageExecutable;
  if (nativeOnly) {
    const removed = new Set(Object.entries(manifest.entrypoints.views).filter(([, view]) => view.kind === "webview").map(([id]) => id));
    for (const id of removed) delete manifest.entrypoints.views[id];
    manifest.contributions.content_types = manifest.contributions.content_types.filter(content => !removed.has(content.view));
    manifest.files = manifest.files.filter(file => !file.path.startsWith("web/"));
  }
  return manifest;
}
