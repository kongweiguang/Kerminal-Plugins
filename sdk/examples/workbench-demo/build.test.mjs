import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { parseOptions, packageManifest } from "./build-support.mjs";

const template = JSON.parse(await readFile(new URL("./manifest.template.json", import.meta.url), "utf8"));

test("native-only packages contain only supported contributions and no frontend files", () => {
  const manifest = packageManifest(template, "linux_x86_64", "bin/backend", true);
  assert.deepEqual(manifest.platforms, ["linux_x86_64"]);
  assert.deepEqual(manifest.entrypoints.process, [{ platform: "linux_x86_64", path: "bin/backend" }]);
  assert.deepEqual(manifest.files.map(file => file.path), ["bin/backend"]);
  assert.equal(manifest.contributions.content_types.length, 1);
  for (const contribution of [...manifest.contributions.content_types, ...manifest.contributions.tools, ...manifest.contributions.settings_pages]) {
    assert.equal(manifest.entrypoints.views[contribution.view].kind, "native");
  }
  for (const host of manifest.contributions.host_types) assert.ok(manifest.entrypoints.views[host.form]);
  assert.ok(template.entrypoints.views["example.workbench.web-page"]);
  assert.ok(packageManifest(template, "windows_x86_64", "bin/backend.exe", false).entrypoints.views["example.workbench.web-page"]);
});

test("flag parsing rejects missing values and repeated flags before a build starts", () => {
  assert.equal(parseOptions(["--native-only", "--out", "native.tar"]).nativeOnly, true);
  for (const args of [["--out"], ["--out", "--native-only"], ["--native-only", "--native-only"], ["--out", "a", "--out", "b"], ["--unknown"]]) {
    assert.throws(() => parseOptions(args), /Usage:/);
  }
});
