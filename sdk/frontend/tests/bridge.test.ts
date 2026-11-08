import { test } from "node:test";
import assert from "node:assert/strict";
import { PluginClient, PluginError } from "../index.ts";

/** The fake transport controls receipt timing, including stale and malformed results. */
function fixture() {
  const sent: unknown[] = [];
  let deliver: (value: unknown) => void = () => {};
  let detached = false;
  const client = new PluginClient({
    postMessage: message => sent.push(message),
    subscribe: listener => { deliver = listener; return () => { detached = true; }; },
  });
  return { client, sent, deliver: (value: unknown) => deliver(value), detached: () => detached };
}

test("correlates receipts, preserves null, and ignores stale or ambiguous envelopes", async () => {
  const f = fixture();
  const result = f.client.invoke("sample.run");
  f.deliver({ version:1, id:999, result:"stale" });
  f.deliver({ version:1, id:1, result:"ambiguous", error:{} });
  f.deliver({ version:1, id:1, result:null });
  assert.equal(await result, null);
  assert.equal(f.sent.length, 1);
  f.client.dispose();
  assert.equal(f.detached(), true);
});

test("operation uncertainty keeps the operation identity and never triggers replay", async () => {
  const f = fixture();
  const result = f.client.invoke("sample.write");
  f.deliver({ version:1, id:1, error:{ code:"outcome_unknown", message:"Check result", operation_id:"op-1" } });
  await assert.rejects(result, (error: PluginError) => error.code === "outcome_unknown" && error.operationId === "op-1");
  assert.equal(f.sent.length, 1);
  f.client.dispose();
});

test("bounds pending requests and disposal rejects waiters without cancelling backend writes", async () => {
  const f = fixture();
  const pending = Array.from({ length:32 }, () => f.client.invoke("sample.run").catch(error => error));
  await assert.rejects(f.client.invoke("sample.extra"), (error: PluginError) => error.code === "busy");
  assert.equal(f.sent.length, 32);
  f.client.dispose();
  for (const result of await Promise.all(pending)) assert.equal(result.code, "view_closed");
  await assert.rejects(f.client.readState(), (error: PluginError) => error.code === "disposed");
});

test("event subscription disposal and malformed input remain local", () => {
  const f = fixture();
  const seen: unknown[] = [];
  f.client.on("theme", () => { throw new Error("subscriber bug"); });
  const unsubscribe = f.client.on("theme", value => seen.push(value));
  f.deliver({ version:1, event:"theme", payload:{ mode:"dark" } });
  unsubscribe();
  f.deliver({ version:1, event:"theme", payload:{ mode:"light" } });
  assert.deepEqual(seen, [{ mode:"dark" }]);
  f.client.dispose();
});
