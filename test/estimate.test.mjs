// test/estimate.test.mjs — run with `node --test` (Node 18+, no dependencies).
import { test } from "node:test";
import assert from "node:assert/strict";
import { estimateRun, quote, CHARS_PER_TOKEN, ASSUMED_MAX_TOKENS } from "../lib/estimate.mjs";

// A tiny fixed price table so the assertions don't move when real prices change.
// $1/1M in, $10/1M out — the 10x split keeps input and output contributions
// distinguishable in the arithmetic below.
const priceOf = (m) => ({ "cheap/model": [1, 10], "dear/model": [2, 20] })[m];

const P = { name: "proposer", model: "cheap/model", max_tokens: 1000, systemChars: 0 };
const A = { name: "adv-1", model: "cheap/model", max_tokens: 1000, systemChars: 0 };

test("ceiling counts every call at its max_tokens cap", () => {
  // 1 round, 1 proposer + 1 adversary, empty task and system prompts.
  //   proposer in  = 0                          out = 1000
  //   adversary in = proposer cap (1000)        out = 1000
  const e = estimateRun({ taskChars: 0, rounds: 1, mode: "harden", proposer: P, adversaries: [A], priceOf });
  assert.equal(e.calls, 2);
  // out: 2000 tok @ $10/1M = $0.02 ; in: 1000 tok @ $1/1M = $0.001
  assert.equal(e.ceilingUsd.toFixed(6), (0.02 + 0.001).toFixed(6));
});

test("the task is charged once per call, not once per run", () => {
  // Every agent re-sends the artifact each round — that is what makes a long
  // artifact expensive, and the estimate has to show it.
  const chars = 4000;                       // = 1000 tokens at CHARS_PER_TOKEN
  const one = estimateRun({ taskChars: 0,     rounds: 1, mode: "harden", proposer: P, adversaries: [A], priceOf });
  const two = estimateRun({ taskChars: chars, rounds: 1, mode: "harden", proposer: P, adversaries: [A], priceOf });
  // 2 calls × 1000 extra input tokens @ $1/1M = $0.002
  assert.equal((two.ceilingUsd - one.ceilingUsd).toFixed(6), (0.002).toFixed(6));
  assert.equal(chars / CHARS_PER_TOKEN, 1000);
});

test("later rounds cost more than the first (the draft and critiques feed back)", () => {
  const r1 = estimateRun({ taskChars: 0, rounds: 1, mode: "harden", proposer: P, adversaries: [A], priceOf });
  const r2 = estimateRun({ taskChars: 0, rounds: 2, mode: "harden", proposer: P, adversaries: [A], priceOf });
  const r3 = estimateRun({ taskChars: 0, rounds: 3, mode: "harden", proposer: P, adversaries: [A], priceOf });
  // Superlinear: round 2 costs strictly more than round 1 did, because the
  // proposer now re-reads its own draft plus every critique.
  assert.ok(r2.ceilingUsd - r1.ceilingUsd > r1.ceilingUsd);
  // ...but growth is bounded, not compounding — the prior critique is truncated,
  // so each subsequent round adds the same increment rather than an escalating one.
  assert.equal((r3.ceilingUsd - r2.ceilingUsd).toFixed(9), (r2.ceilingUsd - r1.ceilingUsd).toFixed(9));
});

test("rounds are a ceiling — early convergence is never assumed", () => {
  // The estimate must price 5 rounds even though most runs converge sooner.
  // Quoting against the converged case is how you lose money on a stubborn run.
  const e = estimateRun({ taskChars: 0, rounds: 5, mode: "harden", proposer: P, adversaries: [A], priceOf });
  assert.equal(e.rounds, 5);
  assert.equal(e.calls, 10);   // 5 proposer + 5 adversary
});

test("each adversary is priced with its own model", () => {
  const dear = { name: "adv-dear", model: "dear/model", max_tokens: 1000, systemChars: 0 };
  const e = estimateRun({ taskChars: 0, rounds: 1, mode: "harden", proposer: P, adversaries: [A, dear], priceOf });
  const rowA = e.rows.find(r => r.name === "adv-1");
  const rowD = e.rows.find(r => r.name === "adv-dear");
  // dear/model is exactly 2x cheap/model on both sides, on identical token counts.
  assert.equal(rowD.usd.toFixed(9), (rowA.usd * 2).toFixed(9));
});

test("readiness mode is a single call, no panel, no rounds", () => {
  const e = estimateRun({ taskChars: 0, rounds: 5, mode: "readiness", proposer: P, adversaries: [A], priceOf });
  assert.equal(e.calls, 1);
  assert.equal(e.rounds, 1);   // --rounds is irrelevant to a single-shot gate
  assert.equal(e.ceilingUsd.toFixed(6), (0.01).toFixed(6));  // 1000 out @ $10/1M
});

test("vibe-app skips the proposer in round 1", () => {
  // Round 1 the attacker reviews the raw artifact; there is no draft to defend.
  const e = estimateRun({ taskChars: 0, rounds: 1, mode: "vibe-app", proposer: P, adversaries: [A], priceOf });
  assert.equal(e.calls, 1);
  assert.equal(e.rows.find(r => r.name === "proposer").calls, 0);
});

test("an unpriced model is reported, not silently counted as free", () => {
  // Silently dropping an agent would make the ceiling LOWER than the true cost —
  // the one direction of error that loses money on a quote.
  const unknown = { name: "adv-x", model: "who/knows", max_tokens: 1000, systemChars: 0 };
  const e = estimateRun({ taskChars: 0, rounds: 1, mode: "harden", proposer: P, adversaries: [unknown], priceOf });
  assert.deepEqual(e.unpriced, ["who/knows"]);
  assert.equal(e.rows.find(r => r.name === "adv-x").usd, null);
});

test("an agent with no max_tokens is flagged as an assumed cap", () => {
  const uncapped = { name: "adv-loose", model: "cheap/model", systemChars: 0 };
  const e = estimateRun({ taskChars: 0, rounds: 1, mode: "harden", proposer: P, adversaries: [uncapped], priceOf });
  assert.deepEqual(e.assumedCaps, ["adv-loose"]);
  // Its output is priced at the assumed cap rather than being treated as zero.
  assert.equal(e.rows.find(r => r.name === "adv-loose").outTok, ASSUMED_MAX_TOKENS);
});

test("system prompts are charged, once per call", () => {
  const withSys = { ...A, systemChars: 4000 };   // 1000 tokens
  const bare = estimateRun({ taskChars: 0, rounds: 2, mode: "harden", proposer: P, adversaries: [A], priceOf });
  const sys  = estimateRun({ taskChars: 0, rounds: 2, mode: "harden", proposer: P, adversaries: [withSys], priceOf });
  // 2 adversary calls × 1000 tokens @ $1/1M = $0.002
  assert.equal((sys.ceilingUsd - bare.ceilingUsd).toFixed(6), (0.002).toFixed(6));
});

test("quote applies the markup and defaults to 10x", () => {
  assert.equal(quote(1.23), 12.3);
  assert.equal(quote(1.23, 1), 1.23);
  assert.equal(quote(0), 0);
});

test("the estimate always declares itself approximate", () => {
  // The input side is a chars/4 rule of thumb, so no caller should ever render
  // this as an exact figure.
  const e = estimateRun({ taskChars: 100, rounds: 1, mode: "harden", proposer: P, adversaries: [A], priceOf });
  assert.equal(e.approximate, true);
});
