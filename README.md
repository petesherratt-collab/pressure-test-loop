# pressure-test-loop

A small, dependency-free **multi-agent adversarial loop**. A *proposer* drafts an
answer; a *red team* of adversary models attacks it; the critiques feed back into
the next draft — for N rounds or until the stop criterion is met.

```
input ──► PROPOSER (drafts / revises)
             ▲                  │ draft
             │ critiques        ▼
          ADVERSARIES ◄── attack the draft (Gemini, GPT/Codex, …)
          loop until converged or round limit
```

Each round is written to a Markdown transcript in `runs/`, ending with a
per-agent cost table for API-based runs.

The same engine powers the **Pressure Test** service family (vibe-coded apps,
business ideas, arguments, app UX, pitch decks) — see
[Pressure Test services](#pressure-test-services-attackerproposer-pairs) below.

## Quick start (no setup)

Runs entirely on the local [`claude`](https://docs.anthropic.com/en/docs/claude-code) CLI:

```bash
node orchestrate.mjs --task "Design a fair rate limiter for a public API"
# or: npm run redteam -- --task "..."
```

## True multi-model red team via OpenRouter

[OpenRouter](https://openrouter.ai) gives you Claude, Gemini and GPT through one
key. Set `OPENROUTER_API_KEY`, then either pick a **tier preset**:

```bash
node orchestrate.mjs --task "..." --config agents.vibeapp.json --tier good
```

| tier | proposer | attacker/adversaries | rough cost profile |
|------|----------|----------------------|--------------------|
| `fable` | `anthropic/claude-fable-5` | `openai/gpt-5.5` | premium ($10/$50 + $5/$30 per 1M tok) |
| `frontier` | `anthropic/claude-opus-4.8` | `openai/gpt-5.5` | high ($5/$25 + $5/$30) |
| `good` | `anthropic/claude-sonnet-4.6` | `google/gemini-3.5-flash` | mid ($3/$15 + $1.50/$9) |
| `open` | `deepseek/deepseek-v4-pro` | `qwen/qwen3-max` | open-weights, pennies |

`--tier` overrides every agent in the config to the `openrouter` adapter with
that tier's model — proposer and attackers always land on **different vendors**,
so a tier never reintroduces the same-family correlation the loop warns about.
Everything else in the config (system prompts, timeouts) is untouched; omit
`--tier` to use the config's own agents as-is. Slugs/prices were verified against
`openrouter.ai/api/v1/models` on 2026-07-08 — re-verify before editing `TIERS`
or `PRICING` in `orchestrate.mjs`.

Or pin models per-agent in a config:

```bash
node orchestrate.mjs \
  --task "Write a function to merge overlapping intervals" \
  --config agents.openrouter.json \
  --rounds 4
```

## True multi-model red team with local CLIs (Claude + Gemini + Codex)

Drive the vendors' own terminal agents — handy on your own machine, where you
install once and reuse your existing ChatGPT/Google logins instead of per-token
API keys:

```bash
# install (Node 18+)
npm i -g @google/gemini-cli      # provides `gemini`
npm i -g @openai/codex           # provides `codex`

# auth once
gemini                           # Google login, or set GEMINI_API_KEY
codex login                      # ChatGPT account, or set OPENAI_API_KEY

# run the loop across all three
node orchestrate.mjs --task "..." --config agents.cli.json
```

| CLI | install | how it's invoked | auth |
|-----|---------|------------------|------|
| Claude | [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `claude -p`, prompt on stdin | already signed in |
| Gemini | `npm i -g @google/gemini-cli` | `gemini`, prompt on stdin | `gemini` login or `GEMINI_API_KEY` |
| Codex  | `npm i -g @openai/codex` | `codex exec`, prompt on stdin | `codex login` or `OPENAI_API_KEY` |

> **Prompt delivery.** `agents.cli.json` feeds every tool the prompt on **stdin**
> (`"promptVia": "stdin"`) — the most portable form, and the only safe one on
> **Windows**, where these CLIs are `.cmd` shims and a multi-line prompt can't be
> passed as a command argument. If a tool ignores stdin on your platform, switch
> that agent to `"promptVia": "arg"` and append its prompt flag (e.g.
> `["gemini", "-p"]`). **`"arg"` is rejected on Windows** and the run fails fast:
> there the command goes through the shell, so a prompt containing the reviewed
> file's contents would let shell metacharacters in an untrusted artifact inject
> commands. Use stdin on Windows.

## Options

| flag | meaning |
|------|---------|
| `--task "<text>"` | the task / artifact to work on |
| `--file <path>` | read the task from a file instead |
| `--config <path>` | agent config (default `agents.local.json`) |
| `--mode <mode>` | `harden` (default), `review`, `readiness`, or `vibe-app` — see [Modes](#four-modes) |
| `--tier <name>` | model preset: `fable`, `frontier`, `good`, or `open` (needs `OPENROUTER_API_KEY`) |
| `--rounds <n>` | max proposer/critique rounds, 1..50 (default 3) |
| `--stop <mode>` | convergence test: `severity` (default), `confidence`, or `verdict` (ignored in vibe-app mode) |
| `--floor <tier>` | severity mode: `critical\|important\|cosmetic` (default `cosmetic`). vibe-app mode: `critical\|high\|medium\|low` (default `low`) |
| `--threshold <n>` | confidence mode: stop when every adversary is below this, 1..100 (default 30) |
| `--probe <kind>` | review mode only: run an attack lens instead of a general review — currently `injection` (costs calls) |
| `--no-injscan` | silence the default injection-detection scan of the artifact |
| `--out <path>` | transcript path (default `runs/<timestamp>.md`) |
| `--quiet` | less console output |

Exit codes: `0` converged, `1` aborted (proposer/panel failure or bad input),
`2` ran out of rounds without converging — so callers/CI can tell the outcomes apart.

## Configuring agents

A config has one `proposer` and one or more `adversaries`. Each agent picks an
**adapter**:

- **`cli`** — spawn a local command; reply read from stdout. Set `"command"`
  (e.g. `["claude", "-p"]`, `["gemini"]`, `["codex", "exec"]`) and `"promptVia"`:
  `"stdin"` (default, pipe the prompt in) or `"arg"` (append it as the last
  argument). See `agents.cli.json`.
- **`openrouter`** — POST to OpenRouter. Set `"model"` to any ID from
  <https://openrouter.ai/models> (e.g. `anthropic/claude-sonnet-4.6`,
  `google/gemini-3.5-flash`, `openai/gpt-5.5`). Reads `OPENROUTER_API_KEY`
  (override per-agent with `"apiKeyEnv"`).

```jsonc
{
  "proposer":   { "name": "Claude", "adapter": "openrouter", "model": "anthropic/claude-sonnet-4.6" },
  "adversaries": [
    { "name": "Gemini", "adapter": "openrouter", "model": "google/gemini-3.5-flash" },
    { "name": "Codex",  "adapter": "openrouter", "model": "openai/gpt-5.5" }
  ]
}
```

### Per-agent options (all optional)

| field | adapters | meaning |
|-------|----------|---------|
| `system` / `systemFile` | all | system prompt inline, or read from a file (path is relative to the config file — good for long personas) |
| `timeoutMs` | cli, openrouter | kill/abort this agent's call after N ms (default 180000) |
| `retries` | cli, openrouter | extra attempts on a transient failure, with backoff (default 1; set 0 to disable) |
| `maxOutputBytes` | cli | truncate + kill if stdout exceeds this (default 2 MB) |
| `apiKeyEnv` | openrouter | env var holding the key (default `OPENROUTER_API_KEY`) |
| `priceIn`, `priceOut` | openrouter | USD per 1M tokens for cost reporting, if the model isn't in the built-in `PRICING` table |
| `referer`, `title` | openrouter | optional `HTTP-Referer` / `X-Title` attribution (or set `OPENROUTER_REFERER` / `OPENROUTER_TITLE`) |
| `max_tokens`, `temperature` | openrouter | passed through to the API |

### Safety notes

- **Configs are trusted code.** A `cli` agent runs `agent.command` verbatim on your
  machine — only run configs you wrote or audited. The loader validates *shape*
  (known adapter, `command` is a string array, `promptVia` ∈ {stdin,arg}, …) but
  cannot validate *intent*.
- **Convergence is not a correctness proof.** It means no adversary objected above
  the bar this round. Strict parsing, per-run nonces on the untrusted-data fences,
  and a per-call token that a verdict line must carry to be counted make convergence
  hard to *forge* — an injected or echoed verdict in the reviewed content can't
  converge the loop. Correlated reviewers still share blind spots, so the loop warns
  when an adversary is the same model *family* as the proposer. Use decorrelated
  reviewers and read the critiques; don't treat a clean run as certification.
- **Reviewing untrusted artifacts is not a security boundary.** The nonces above stop
  the parser from trusting a verdict the model never authored, but they cannot stop a
  model being *persuaded* by instructions embedded in the artifact to render a lenient
  verdict of its own. This is the irreducible limit of an LLM judge: a hostile input
  can still manipulate the *judgement*. Treat a converged run on attacker-controlled
  content as suggestive, never as a clearance. Every run also does a free, heuristic
  **injection scan** of the artifact and prints a heads-up (not a verdict) when it sees
  steering/verdict-forging patterns; silence it with `--no-injscan`, or actively
  red-team an artifact's injection surface with `--mode review --probe injection`.

### Adding a new transport

Adapters live in the `ADAPTERS` map in `orchestrate.mjs`. Each is
`async (agent, system, user) => string`. Add a key (e.g. a direct Anthropic or
Gemini SDK call) and reference it by name from any agent's `"adapter"` field.

## Four modes

- **`harden`** (default) — the proposer *builds and defends* an answer; the adversaries
  attack it; it gets stronger each round. Use it on arguments, designs, plans, pitches.
- **`review`** — point it at a **file** and it produces a *sharpened, triaged defect
  list*, not a rewrite. The proposer writes a defect review; the adversaries cross-check
  it for **missed or mis-graded** defects (a missed `Critical` bug is a `Critical` gap);
  it converges when nothing significant is left unflagged. The output is a brief you hand
  to a coding agent (e.g. Claude Code) to *apply with full repo context and tests*.
- **`readiness`** — a single-shot **intake gate**, not a loop: one agent checks whether
  the submission is coherent and substantial enough to be worth red-teaming, and answers
  `READY` / `NOT READY` with reasons (`agents.readiness.json`). Run it before a paid
  multi-round run so contradictory or too-thin input gets bounced for free.
- **`vibe-app`** — the **attacker/proposer pairing mode** used by all Pressure Test
  services (the name predates its generalization). One adversary (the *attacker*)
  attacks the submitted artifact directly in round 1 — no proposer call, the artifact
  is the draft. From round 2 the proposer writes a *rebuttal document* per finding
  (the artifact itself is never rewritten) and the attacker reprices its findings
  against it. Convergence uses its own four-tier **finding-severity** scale
  (`LOW/MEDIUM/HIGH/CRITICAL`, nonce-gated `TOP-SEVERITY:` line) with `--floor`
  defaulting to `low`. The transcript's **Final output** is the attacker's final
  findings — the verdict — not the last rebuttal.

```bash
# review a file, then hand the result to whatever does the work
node orchestrate.mjs --config agents.review.json --file ./src/pipeline.jsx --rounds 4
```

## Pressure Test services (attacker/proposer pairs)

Five services, one engine — same mechanics (`--mode vibe-app`), different attack
taxonomy and personas per artifact type. Each has a ready-made config wiring the
split persona files in `prompts/`:

| service | config | attacker hunts for |
|---------|--------|--------------------|
| Vibe-coded app | `agents.vibeapp.json` | UX confusion, hallucinated features, missing validation, brittle workflows, light security hygiene |
| Business idea | `agents.businessidea.json` | unproven demand, unit-economics breakdown, competitive blind spots, GTM implausibility, market-sizing inflation |
| Argument / essay | `agents.argument.json` | logical fallacies, evidence gaps, unaddressed counter-theses, scope overreach, strawmen |
| App UX flow | `agents.appux.json` | onboarding friction, trust-signal gaps, orientation loss, dead ends, mismatched affordances |
| Pitch deck | `agents.pitchdeck.json` | narrative incoherence, unaddressed objections, traction inflation, ask/use-of-funds mismatch, slide ambiguity |

```bash
# gate the submission first (free-tier front door), then run the paid service
node orchestrate.mjs --mode readiness --config agents.readiness.json --file order.md
node orchestrate.mjs --config agents.businessidea.json --tier good --file order.md
```

The default configs run both roles on the local `claude` CLI (zero setup, but
same-family — fine for smoke tests). For real runs use `--tier`, which puts the
attacker and proposer on different vendors. The combined reference docs
(`prompts/<service>-attacker-proposer.md`) and the shared scaffold
(`prompts/attacker-proposer-shared-template.md`) document how the pairs are built;
to add a sixth service, split a new pair into two files, point a new
`agents.<service>.json` at them with `"mode": "vibe-app"`, and no engine change
is needed.

## How convergence works

Three stop criteria for harden/review (vibe-app mode always uses its own
finding-severity scale, described above):

**`severity` (default).** Each adversary grades its *single strongest remaining
objection* by **consequence**, and tags **effort** separately, ending with a final line:

```
SEVERITY: <CRITICAL|IMPORTANT|COSMETIC|NONE> | EFFORT: <QUICK-FIX|STRUCTURAL>
```

- **SEVERITY** = the consequence *if true*, in three ordinal bands:
  - `CRITICAL` — breaks the case, or is exploitable by untrusted input. Look now.
  - `IMPORTANT` — degrades quality, or bites a real user under real conditions. Look soon.
  - `COSMETIC` — true but inconsequential (e.g. a wrong version number). Batch it.
- **EFFORT** = how hard the fix is — *orthogonal* to severity. A `CRITICAL` bug can be
  a `QUICK-FIX`; an `IMPORTANT` one can be `STRUCTURAL`. Effort never changes severity.

This is the fix for the bug it replaced: a single "confidence" number rated *how sure
the reviewer was*, so a certain-but-trivial version typo scored ~95% and floated to the
top while a hedged-but-load-bearing injection seam sank. Now severity rates *consequence*,
so the typo is `COSMETIC` and the seam is `CRITICAL` regardless of certainty. **Only
SEVERITY drives the loop** (effort is triage metadata — sort by "biggest bang per
keystroke"). It stops when every adversary's top objection is at/below `--floor` (default
`cosmetic` — nothing `CRITICAL` or `IMPORTANT` left; cosmetic nits don't block a ship).
The console shows the round-to-round movement, e.g. `IMPORTANT · structural  (CRITICAL → IMPORTANT)`.

**`confidence`.** Each adversary ends with a `TOP-CONFIDENCE: <0-100>` line; the
loop stops when every adversary is below `--threshold` (default 30). The original
numeric mode — kept, but note it has the certainty/severity conflation that
`severity` mode fixes.

**`verdict`.** The older binary mode: each adversary ends with `VERDICT: PASS` or
`VERDICT: REVISE`; the loop stops when all return a clean final `PASS`.

**Repricing memory.** From round 2 on, each adversary is shown *its own* previous
critique and score and asked to reprice the *delta* against the revised draft —
implementing the Red Pen's "move the tier on rebuttal" rule. Without this, some
models anchor on a flat band (e.g. a constant 65 every round); with it, the
console shows the movement, e.g. `top objection 42  (64 → 42)`. Memory is
per-adversary and only the immediately previous review is carried (head-truncated),
so prompts stay bounded; an errored round keeps the prior memory.

In all modes a missing/garbled signal, or an errored adversary, counts as "not
satisfied" and never converges the loop (fail-closed). It otherwise runs until
`--rounds`. The final output and a full per-round transcript are saved under `runs/`.

## Cost tracking

OpenRouter calls report token usage; the run prints a per-call and total cost line
and appends a per-agent cost table to the transcript. Prices come from the
`PRICING` table in `orchestrate.mjs` (USD per 1M tokens, verified against
openrouter.ai — re-verify when adding models) or per-agent `priceIn`/`priceOut`.
`cli` agents don't report usage, so their runs show no cost table.

### The Red Pen adversary

`prompts/red-pen.md` is a committed adversarial-critic persona (attacks the
load-bearing premise, scores by tier, never writes the fix). `agents.redpen.json`
wires it onto the local Gemini + Codex CLIs:

```bash
node orchestrate.mjs --task "Your argument or design here" \
  --config agents.redpen.json --threshold 30 --rounds 5
```

Point any agent at it with `"systemFile": "prompts/red-pen.md"`.

> What a converged run means: **ready for real-world experimentation, not a
> gold standard.** Convergence says the reviewers ran out of above-threshold
> objections — not that the case is correct. With correlated reviewers (e.g. the
> same model proposing and attacking — the loop warns when it detects this) a
> shared blind spot converges silently. Use decorrelated reviewers, read the
> critiques, and treat a clean run as a green light to *test in reality*, not a
> certificate of correctness.

## Tests

Pure parsing/convergence logic lives in `lib/parse.mjs` and is covered by
`node --test` (`npm test`) — verdict/confidence/severity parsing, the vibe-app
finding-severity scale, readiness parsing, the injection cases, and threshold
behaviour. CI (`.github/workflows/ci.yml`) runs the syntax check, JSON
validation, and tests on every push.

## Troubleshooting the local CLIs

A failing adversary doesn't crash the run — it's logged as `ERROR` in that
round's transcript so the others continue. Common ones:

- **Gemini: `Please set an Auth method` (exit 41)** — not signed in. Run `gemini`
  once and complete the Google login, or set `GEMINI_API_KEY` in your environment.
- **Codex: `Not inside a trusted directory and --skip-git-repo-check was not
  specified`** — `agents.cli.json` already passes `--skip-git-repo-check`; if you
  changed the command, add that flag back. Also run `codex login` (or set
  `OPENAI_API_KEY`) first.
- **Codex: `Reading prompt from stdin...` then nothing** — it *is* reading stdin;
  any error after that line is auth or the trust check above.

## License

MIT — see [LICENSE](LICENSE).
