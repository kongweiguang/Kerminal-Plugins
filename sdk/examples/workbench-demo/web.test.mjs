import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import vm from "node:vm";

const source = (await readFile(new URL("./web/main.js", import.meta.url), "utf8")).replace(/^import .*;\r?\n/, "");

/** The actual page script runs against minimal DOM events; the host promise controls delivery and uncertainty. */
async function page(saveState) {
  const elements = new Map();
  for (const id of ["#note", "#save", "#confirm", "#recover", "#status"]) elements.set(id, { disabled: true, value: "", textContent: "", events: new Map(), addEventListener(type, callback) { this.events.set(type, callback); } });
  class PluginError extends Error { constructor(code) { super(code); this.code = code; } }
  const client = { saveState, readState: async () => ({ message: "" }), on() {}, dispose() {} };
  vm.runInNewContext(source, { document: { querySelector: id => elements.get(id) }, connect: () => client, applyTheme() {}, PluginError, addEventListener() {}, console });
  await new Promise(resolve => setImmediate(resolve));
  return { elements, PluginError };
}

test("editing while a save is in flight cannot send a second write", async () => {
  let finish; let calls = 0;
  const { elements } = await page(() => { calls++; return new Promise(resolve => { finish = resolve; }); });
  const note = elements.get("#note"); const save = elements.get("#save");
  note.value = "first"; note.events.get("input")();
  const pending = save.events.get("click")();
  note.value = "second"; note.events.get("input")();
  assert.equal(save.disabled, true);
  await save.events.get("click")();
  assert.equal(calls, 1);
  finish({}); await pending;
  assert.equal(save.disabled, false);
  assert.match(elements.get("#status").textContent, /newer changes/);
});

test("explicit unknown write remains blocked until readback even after more typing", async () => {
  let rejectWrite; let calls = 0;
  const { elements, PluginError } = await page(() => { calls++; return new Promise((_, reject) => { rejectWrite = reject; }); });
  const note = elements.get("#note"); const save = elements.get("#save");
  note.value = "draft"; note.events.get("input")();
  const pending = save.events.get("click")();
  rejectWrite(new PluginError("outcome_unknown")); await pending;
  note.value = "new draft"; note.events.get("input")();
  assert.equal(save.disabled, true);
  await save.events.get("click")(); assert.equal(calls, 1);
  assert.equal(elements.get("#recover").disabled, false);
  await elements.get("#recover").events.get("click")();
  assert.equal(save.disabled, false);
  assert.equal(note.value, "new draft");
});
