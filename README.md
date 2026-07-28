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

## Quick start

Every shipped config runs through [OpenRouter](https://openrouter.ai) — one key,
every vendor. Set `OPENROUTER_API_KEY` ([get one](https://openrouter.ai/keys)) and go:

```bash
export OPENROUTER_API_KEY=sk-or-...
node orchestrate.mjs --task "Design a fair rate limiter for a public API"
# or: npm run redteam -- --task "..."
```

The default config (`agents.local.json`) is Claude in three framings — same
family, fine for smoke tests. For a decorrelated panel use
`--config agents.redpen.json` (Claude vs Gemini vs GPT) or a `--tier` preset.

## True multi-model red team

OpenRouter gives you Claude, Gemini and GPT through one key. Either pick a
**tier preset**:

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

### Choosing models per role

`--defend` sets the model for the defender (the proposer); `--attack` sets it for
the attacker (every adversary). Neither needs a config edit:

```bash
node orchestrate.mjs --task "..." \
  --defend anthropic/claude-opus-4.8 \
  --attack openai/gpt-5.5
```

Precedence is **config < `--tier` < `--defend`/`--attack`**, so a tier can be the
base and one side swapped — cheap defender, expensive attacker, or the reverse:

```bash
# `good` tier, but let GPT do the attacking
node orchestrate.mjs --task "..." --tier good --attack openai/gpt-5.5
```

**`--attack` takes a list**, mapped onto the adversaries in config order, so a
multi-vendor panel stays multi-vendor:

```bash
# agents.redpen.json has two adversaries: Gemini, then GPT
node orchestrate.mjs --config agents.redpen.json --task "..." \
  --attack openai/gpt-5.5,google/gemini-3.5-flash
#   adversary 1 (Red Pen · Gemini) → openai/gpt-5.5
#   adversary 2 (Red Pen · GPT)    → google/gemini-3.5-flash
```

A single slug still broadcasts to every adversary — convenient on a one-adversary
config, but on a panel it collapses every reviewer onto one model, which is
exactly the correlation the loop warns about. The list form is the safe default.
A list whose length is neither 1 nor the adversary count is an error naming the
adversaries it found, rather than a silent mis-assignment.

Either flag also re-points that agent at the `openrouter` adapter, so it works on
top of any config. Choices are limited to the slugs in the `PRICING` table in
`orchestrate.mjs` — that way a typo or a retired slug fails immediately instead
of as a 400 mid-run, and every choosable model has a known cost. Pass a bad value
to print the list with prices; add a `PRICING` row to make a new model choosable.

Picking the same family for both sides is allowed — you'll get the decorrelation
warning and the run continues.

Or pin models per-agent in a config:

```bash
node orchestrate.mjs \
  --task "Write a function to merge overlapping intervals" \
  --config agents.openrouter.json \
  --rounds 4
```

### Picking an adversary: non-reasoning beats reasoning

The single most important property of a model in the **adversary** seat is not how
clever it is. It is whether it *reasons*.

An adversary's turn only counts if it ends in a nonce-signed verdict line. On
OpenRouter, `max_tokens` caps hidden reasoning and visible content **together**,
so a reasoning model working on a large artifact can spend its entire budget
thinking and return `content: ""`. That is not a slow seat or a bad critique —
it is a seat that stops gating convergence while still billing you.

Measured on the same 30k-char Python artifact, three rounds, identical proposer
and identical second adversary — only the first seat changed:

| first seat | cost | calls | retries | outcome |
|---|---|---|---|---|
| `qwen/qwen3-coder-plus` | **$1.31** | **9** | **0** | verdict on the first call, every round |
| `google/gemini-3.5-flash` | $1.62 | 11 | 2 | re-asked twice; capitulated to NONE early in an earlier run |
| `moonshotai/kimi-k2.7-code` | $1.35 | 12 | 3 | **mute all three rounds** — 8000 tokens of reasoning, no content |
| `moonshotai/kimi-k2.7-code` + `reasoning: {effort: low}` | $1.42 | 13 | 5 | recovered twice on retry, dropped from the panel in round 3 |

Nine calls is the no-retry minimum for 3 rounds × 2 adversaries. Only the
non-reasoning seat hit it.

Qwen's critiques were **not** thinner for being cheaper — 2100–2300 characters
against GPT's 2085–3196 — and it found a defect the others missed (an unbounded
`find_element(By.XPATH, "//*")` whose memory cost lands *before* the size guard
that was supposed to bound it).

**Rules of thumb:**

- Prefer a **non-reasoning** model in adversary seats. `lib/pricing.mjs` exports
  `REASONING_MODELS` with measured evidence for each entry.
- **Probe before seating an unmeasured model.** One call, ~$0.02: read
  `usage.completion_tokens_details.reasoning_tokens` and check whether
  `message.content` is non-empty.
- If you must seat a reasoning model, **raise that agent's `max_tokens`** (24000
  worked for Kimi where 8000 did not). `"reasoning": {"effort": "low"}` is *not*
  a fix — Kimi produced 8857 reasoning tokens under it, more than the whole cap.
- Watch the clock as well as the bill. A round waits on its **slowest** seat, so
  one verbose reasoning adversary sets the pace for the entire panel: the 24000-token
  Kimi run was heading past 45 minutes where the Qwen run finished in a few.

An empty reply is now a hard error naming the cause, so this failure announces
itself instead of quietly degrading the panel.

## Driving local CLIs instead (opt-in)

No shipped config uses it, but the `cli` adapter is still in the engine: it
spawns a vendor's own terminal agent and reads the reply from stdout, so a run
goes through your existing Claude/ChatGPT/Google logins rather than per-token
API billing. To use it, hand-edit an agent block — replace `"model"` with
`"command"` and set the adapter:

```jsonc
{
  "name": "Red Pen · Codex",
  "adapter": "cli",
  "command": ["codex", "exec", "--skip-git-repo-check"],
  "promptVia": "stdin"
}
```

| CLI | install | how it's invoked | auth |
|-----|---------|------------------|------|
| Claude | [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `claude -p`, prompt on stdin | already signed in |
| Gemini | `npm i -g @google/gemini-cli` | `gemini`, prompt on stdin | `gemini` login or `GEMINI_API_KEY` |
| Codex  | `npm i -g @openai/codex` | `codex exec`, prompt on stdin | `codex login` or `OPENAI_API_KEY` |

Caveat: CLI agents don't report token usage, so a run that uses them has no cost
table. `--tier` also drops `command` and forces every agent back onto OpenRouter.

> **Prompt delivery.** Feed every tool the prompt on **stdin**
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
| `--defend <slug>` | model for the defender (proposer) — see [Choosing models per role](#choosing-models-per-role) |
| `--attack <list>` | model(s) for the attackers — one per adversary, comma-separated, or one for all |
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

- **`openrouter`** — POST to OpenRouter. Used by every shipped config. Set
  `"model"` to any ID from <https://openrouter.ai/models> (e.g.
  `anthropic/claude-sonnet-4.6`, `google/gemini-3.5-flash`, `openai/gpt-5.5`).
  Reads `OPENROUTER_API_KEY` (override per-agent with `"apiKeyEnv"`).
- **`cli`** — spawn a local command; reply read from stdout. Set `"command"`
  (e.g. `["claude", "-p"]`, `["gemini"]`, `["codex", "exec"]`) and `"promptVia"`:
  `"stdin"` (default, pipe the prompt in) or `"arg"` (append it as the last
  argument). Opt-in only — see [Driving local CLIs](#driving-local-clis-opt-in).

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

The service configs run both roles on Claude via OpenRouter (same-family — fine
for smoke tests). For real runs use `--tier`, which puts the attacker and
proposer on different vendors. The combined reference docs
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

## Troubleshooting

A failing adversary doesn't crash the run — it's logged as `ERROR` in that
round's transcript so the others continue. Common ones:

**OpenRouter (all shipped configs):**

- **`Missing API key: set OPENROUTER_API_KEY`** — export it, or point that agent
  at a different env var with `"apiKeyEnv"`.
- **`OpenRouter 400: ... is not a valid model ID`** — the slug is stale or an
  alias. Alias forms like `*-latest` and `*-pro-latest` are **not** valid here;
  copy the literal id from the model's page at <https://openrouter.ai/models>.
- **`OpenRouter 402`** — out of credit on the key.
- **`$? (no price for slug)` in the cost table** — the model isn't in `PRICING`
  in `orchestrate.mjs`. Tokens are still counted; add a row, or set `"priceIn"` /
  `"priceOut"` on the agent.

**Local CLIs (only if you opted into the `cli` adapter):**

- **Gemini: `Please set an Auth method` (exit 41)** — not signed in. Run `gemini`
  once and complete the Google login, or set `GEMINI_API_KEY` in your environment.
- **Codex: `Not inside a trusted directory and --skip-git-repo-check was not
  specified`** — add `--skip-git-repo-check` to the command. Also run
  `codex login` (or set `OPENAI_API_KEY`) first.
- **Codex: `Reading prompt from stdin...` then nothing** — it *is* reading stdin;
  any error after that line is auth or the trust check above.

## License

MIT — see [LICENSE](LICENSE).
