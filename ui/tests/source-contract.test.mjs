import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("source contains the complete analyst decision surface", async () => {
  const [page, css, layout, packageJson] = await Promise.all([
    readFile(new URL("app/page.tsx", root), "utf8"),
    readFile(new URL("app/globals.css", root), "utf8"),
    readFile(new URL("app/layout.tsx", root), "utf8"),
    readFile(new URL("package.json", root), "utf8"),
  ]);

  for (const stage of ["Detection", "Ingestion", "Triage", "Judgment", "Escalation", "Response"]) {
    assert.match(page, new RegExp(stage));
  }
  for (const view of ["Overview", "Incidents", "Policies", "Evaluations", "Integrations"]) {
    assert.match(page, new RegExp(view));
  }
  assert.match(page, /Forge live event/);
  assert.match(page, /http:\/\/127\.0\.0\.1:8765/);
  assert.match(page, /\/api\/alerts/);
  assert.match(page, /\/api\/forge/);
  for (const detail of ["AUTHORITATIVE TRACE", "Why this alert is valid", "Confirmed policy violation", "MVP TRACE", "Score contributions", "Authority intersection", "Codex shadow", "Most-restrictive combiner", "Finding audit"]) {
    assert.match(page, new RegExp(detail));
  }
  assert.doesNotMatch(page, /const alerts: Alert\[\] = \[/);
  assert.match(page, /0%/);
  assert.match(page, /100%/);
  assert.match(css, /@media \(max-width: 600px\)/);
  assert.match(css, /prefers-reduced-motion/);
  assert.match(layout, /og\.png/);
  assert.doesNotMatch(page, /SkeletonPreview|codex-preview/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
});
