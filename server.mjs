#!/usr/bin/env node
// server.mjs — a local web UI for the red-team loop.
//
//   node server.mjs          # then open http://localhost:3000
//
// This is a SINGLE-USER LOCAL TOOL. It binds to 127.0.0.1 only, so nothing
// outside this machine can reach it, and there is deliberately no auth, no
// accounts and no rate limiting — the security model is "the only person who
// can reach this is the person sitting at this keyboard". Do not put it behind
// a public tunnel or change the bind address without adding all three: an open
// instance spends the OPENROUTER_API_KEY of whoever is running it, and a run is
// dollars, not cents.
//
// The key itself never reaches the browser. The server reads it from its own
// environment and hands it to the child process; the page only ever sees model
// names, prices and run events.
//
// How a run works: the browser POSTs its choices, the server spawns
// `orchestrate.mjs --events`, and pipes the child's NDJSON stdout to the page as
// Server-Sent Events. The engine is untouched by the UI — the CLI is still the
// only thing that runs a loop, so anything you can do here you can do from a
// terminal, and vice versa.
//
// Zero dependencies, matching the rest of the project: node:http and SSE are
// enough, so `npm install` stays a no-op.

import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, resolve, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { PRICING, CHOOSABLE } from "./lib/pricing.mjs";
import { estimateRun, quote } from "./lib/estimate.mjs";
import { loadDotenv } from "./lib/env.mjs";

const __dir = dirname(fileURLToPath(import.meta.url));
// Read .env before anything checks for the key, so starting the server with a
// .env in place behaves the same as exporting it by hand. The child process
// inherits the loaded value through env: process.env in runStream().
loadDotenv(__dir);
const PORT = Number(process.env.PORT) || 3000;
const HOST = "127.0.0.1";           // see the header — local only, on purpose.

// The modes the UI offers, in the order they appear. `blurb` is what the page
// shows under each one; keep it honest about what the mode actually does,
// because picking the wrong one wastes a paid run.
const MODES = [
  { id: "review",    label: "Code",    blurb: "Produces a triaged defect list to hand to a coding agent. Does not rewrite your code." },
  { id: "vibe-app",  label: "App / idea", blurb: "An attacker hunts concrete UX, validation and workflow defects; the proposer rebuts or concedes each one." },
  { id: "harden",    label: "Argument / problem", blurb: "Builds an answer and defends it against the panel, revising until the objections stop landing." },
  { id: "readiness", label: "Readiness check", blurb: "One cheap call that decides whether an artifact is even coherent enough to be worth testing. No panel." },
];

// Which config backs each mode. The UI overrides the models via --defend/--attack,
// but the config still supplies the system prompts and the mode's shape.
const MODE_CONFIG = {
  review:    "agents.review.json",
  "vibe-app": "agents.vibeapp.json",
  harden:    "agents.redpen.json",
  readiness: "agents.readiness.json",
};

const json = (res, code, body) => {
  const s = JSON.stringify(body);
  res.writeHead(code, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(s) });
  res.end(s);
};

// How many adversaries a config ships with, and their system prompt sizes — the
// estimate needs both, and reading them here keeps the UI from having to know
// anything about config file layout.
function readConfig(name) {
  const p = join(__dir, name);
  if (!existsSync(p)) return null;
  try { return JSON.parse(readFileSync(p, "utf8")); } catch { return null; }
}
function systemChars(agent, configName) {
  if (agent?.systemFile) {
    const p = resolve(dirname(join(__dir, configName)), agent.systemFile);
    try { return readFileSync(p, "utf8").length; } catch { return 0; }
  }
  return (agent?.system ?? "").length;
}

// Build the estimate inputs for a proposed run, using the real config the run
// would use and the models the user actually picked.
function estimateFor({ mode, defend, attack, rounds, taskChars }) {
  const configName = MODE_CONFIG[mode];
  const cfg = readConfig(configName);
  if (!cfg) return null;
  const advCount = mode === "readiness" ? 0 : (cfg.adversaries?.length ?? 0);
  const picked = attack.slice(0, Math.max(advCount, 0));

  const proposer = {
    name: cfg.proposer?.name ?? "proposer",
    model: defend ?? cfg.proposer?.model,
    max_tokens: cfg.proposer?.max_tokens,
    systemChars: systemChars(cfg.proposer, configName),
  };
  const adversaries = (cfg.adversaries ?? []).slice(0, advCount).map((a, i) => ({
    name: a.name ?? `adversary ${i + 1}`,
    model: picked[i] ?? a.model,
    max_tokens: a.max_tokens,
    systemChars: systemChars(a, configName),
  }));
  return estimateRun({ taskChars, rounds, mode, proposer, adversaries, priceOf: (m) => PRICING[m] });
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${HOST}:${PORT}`);

  // ── the page ──────────────────────────────────────────────────────────────
  if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
    const html = readFileSync(join(__dir, "public", "index.html"));
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    return res.end(html);
  }

  // ── what the UI can offer ─────────────────────────────────────────────────
  // Models, prices and modes all come from the same source the CLI uses, so the
  // dropdowns can never offer something --defend/--attack would reject.
  if (req.method === "GET" && url.pathname === "/api/options") {
    const configured = Object.fromEntries(Object.entries(MODE_CONFIG).map(([mode, name]) => {
      const cfg = readConfig(name);
      return [mode, {
        config: name,
        adversaries: (cfg?.adversaries ?? []).map(a => ({ name: a.name, model: a.model })),
        proposer: cfg?.proposer ? { name: cfg.proposer.name, model: cfg.proposer.model } : null,
      }];
    }));
    return json(res, 200, {
      models: CHOOSABLE.map(m => ({ slug: m, priceIn: PRICING[m][0], priceOut: PRICING[m][1] })),
      modes: MODES,
      configured,
      hasKey: !!process.env.OPENROUTER_API_KEY,
    });
  }

  // ── pre-run cost ceiling ──────────────────────────────────────────────────
  if (req.method === "POST" && url.pathname === "/api/estimate") {
    const body = await readBody(req);
    const est = estimateFor({
      mode: body.mode, defend: body.defend, attack: body.attack ?? [],
      rounds: Number(body.rounds) || 3, taskChars: (body.task ?? "").length,
    });
    if (!est) return json(res, 400, { error: `unknown mode: ${body.mode}` });
    return json(res, 200, { ...est, quoteUsd: quote(est.ceilingUsd, Number(body.markup) || 10) });
  }

  // ── run, streamed ─────────────────────────────────────────────────────────
  if (req.method === "POST" && url.pathname === "/api/run") {
    const body = await readBody(req);
    return runStream(res, body);
  }

  // ── a finished transcript ─────────────────────────────────────────────────
  // Only ever serves .md files out of runs/, and resolves the path before
  // checking it, so a crafted name can't walk out of that directory.
  if (req.method === "GET" && url.pathname === "/api/transcript") {
    const name = url.searchParams.get("name") ?? "";
    const runsDir = join(__dir, "runs");
    const p = resolve(runsDir, name);
    if (!p.startsWith(runsDir + "/") || extname(p) !== ".md" || !existsSync(p)) {
      return json(res, 404, { error: "no such transcript" });
    }
    res.writeHead(200, { "content-type": "text/markdown; charset=utf-8" });
    return res.end(readFileSync(p));
  }

  json(res, 404, { error: "not found" });
});

function readBody(req) {
  return new Promise((ok, no) => {
    let n = 0; const chunks = [];
    req.on("data", (c) => {
      n += c.length;
      // A local tool still shouldn't let a runaway paste exhaust memory. 5 MB is
      // far above any artifact worth pressure-testing.
      if (n > 5_000_000) { no(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => { try { ok(JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}")); } catch (e) { no(e); } });
    req.on("error", no);
  });
}

// Spawn the CLI and relay its NDJSON events to the browser as SSE.
function runStream(res, body) {
  const mode = body.mode ?? "harden";
  const configName = MODE_CONFIG[mode];
  if (!configName) return json(res, 400, { error: `unknown mode: ${mode}` });
  if (!body.task || !String(body.task).trim()) return json(res, 400, { error: "nothing to test — the artifact is empty" });

  const argv = ["--events", "--config", join(__dir, configName), "--task", String(body.task),
    "--rounds", String(Number(body.rounds) || 3), "--mode", mode];
  // Only pass a model flag when the user actually chose one; otherwise the
  // config's own model stands, which is what "leave it alone" should mean.
  if (body.defend) argv.push("--defend", String(body.defend));
  if (Array.isArray(body.attack) && body.attack.length && mode !== "readiness") {
    argv.push("--attack", body.attack.join(","));
  }

  // Only demand the key if this run will actually reach OpenRouter. Picking a
  // model via --defend/--attack re-points that agent at the openrouter adapter,
  // so a chosen model implies the key; otherwise it depends on what the config
  // itself uses. A cli-adapter config (see agents.clitest.json) needs no key at
  // all, and refusing to run it would be wrong — the failure has to be about
  // what the run needs, not about what the common case happens to need.
  const cfg = readConfig(configName);
  const usesOpenRouter = !!body.defend
    || (Array.isArray(body.attack) && body.attack.length > 0 && mode !== "readiness")
    || [cfg?.proposer, ...(cfg?.adversaries ?? [])].some(a => a?.adapter === "openrouter");
  if (usesOpenRouter && !process.env.OPENROUTER_API_KEY) {
    return json(res, 400, { error: "OPENROUTER_API_KEY is not set in the server's environment — start the server with it exported." });
  }

  res.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache",
    "connection": "keep-alive",
    // Some proxies buffer SSE into uselessness; harmless locally, correct anywhere.
    "x-accel-buffering": "no",
  });
  const send = (obj) => res.write(`data: ${JSON.stringify(obj)}\n\n`);

  const child = spawn(process.execPath, [join(__dir, "orchestrate.mjs"), ...argv], {
    cwd: __dir,
    // The API key is inherited here and ONLY here — it never crosses into the page.
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  // NDJSON reassembly: a JSON object can be split across chunk boundaries, so
  // buffer and only parse on a newline. Anything unparseable is surfaced rather
  // than dropped — a silently swallowed line would show as a run that just stops.
  let buf = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buf += chunk;
    let i;
    while ((i = buf.indexOf("\n")) !== -1) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (!line) continue;
      try { send(JSON.parse(line)); }
      catch { send({ type: "stream-error", message: `unparseable event line: ${line.slice(0, 200)}` }); }
    }
  });

  // The child's stderr is where a crash or a config error lands. Forward it so a
  // failure shows up in the UI instead of the run appearing to hang.
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (c) => { stderr += c; send({ type: "stderr", text: c }); });

  child.on("error", (e) => {
    send({ type: "fatal", message: `could not start the run: ${e.message}` });
    res.end();
  });
  child.on("close", (code) => {
    // exit 0 converged · 1 aborted · 2 hit the round limit · 3 not ready.
    // A non-zero code with no `done` event means it died before it could report.
    send({ type: "exit", code, stderr: stderr.slice(-2000) });
    res.end();
  });

  // If the browser goes away (tab closed, reload), stop paying for the run.
  res.on("close", () => { if (!child.killed) child.kill("SIGTERM"); });
}

server.listen(PORT, HOST, () => {
  const keyed = process.env.OPENROUTER_API_KEY ? "key loaded" : "NO OPENROUTER_API_KEY — runs will fail";
  console.log(`redteam-loop UI  →  http://${HOST}:${PORT}   (${keyed})`);
});
