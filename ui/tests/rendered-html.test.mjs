import assert from "node:assert/strict";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(new Request("http://localhost/", { headers: { accept: "text/html" } }), {
    ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
  }, { waitUntil() {}, passThroughOnException() {} });
}

test("server-renders the AgentSec control room", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /AgentSec/);
  assert.match(html, /Authorization control room/);
  assert.match(html, /Detection/);
  assert.match(html, /Ingestion/);
  assert.match(html, /Triage/);
  assert.match(html, /Judgment/);
  assert.match(html, /Escalation/);
  assert.match(html, /Response/);
  assert.match(html, /Forge live event/);
  assert.match(html, /Waiting for a sanitized EC2 decision/);
  assert.doesNotMatch(html, /codex-preview/);
  assert.doesNotMatch(html, /react-loading-skeleton/);
});
