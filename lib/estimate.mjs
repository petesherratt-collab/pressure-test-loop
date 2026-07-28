// lib/estimate.mjs — what a run can cost, computed BEFORE it runs.
//
// You cannot predict a run's cost, because you cannot predict how much a model
// will choose to write. What you CAN do is bound it: every call is capped by
// that agent's `max_tokens`, which the API enforces. So this module computes a
// **ceiling** — the cost if every single call ran to its cap and never stopped
// early — not a guess at the typical case.
//
// That distinction is the whole point. A ceiling is the number to quote against:
// the real run lands at or under it, so a price set from it cannot be undercut by
// a chatty model. A "typical" estimate would be a guess dressed up as a number,
// and the first verbose run blows through it.
//
// Two caveats, both stated rather than hidden:
//
//  1. The OUTPUT side is a true ceiling — `max_tokens` is a hard API-enforced cap.
//  2. The INPUT side is an approximation. We know exactly what text goes into each
//     prompt (task + system + the previous draft and critiques), but converting
//     characters to tokens is a ~4:1 rule of thumb, not a tokenizer. Input is the
//     cheaper half of every price pair here, and it is bounded by the same
//     max_tokens caps on the text being fed back, so the error is small and
//     bounded — but it is an estimate, and `approximate: true` says so.
//
// Rounds are also a ceiling: a run that converges in round 2 of 5 never pays for
// rounds 3-5. So the ceiling assumes NO early convergence — the genuine worst case.

// Rule of thumb across current tokenizers for English prose and code. Used only
// for the input side; see the header note.
export const CHARS_PER_TOKEN = 4;

// If an agent doesn't pin max_tokens, we can't bound its output from the config.
// We assume this and flag it, rather than silently pretending the run is bounded.
export const ASSUMED_MAX_TOKENS = 4096;

// Mirrors PREV_REVIEW_CAP in orchestrate.mjs — the prior critique is head-truncated
// to this many characters before being fed back, which is what stops prompt growth
// from compounding round over round.
export const PREV_REVIEW_CAP = 3000;

const toTokens = (chars) => Math.ceil(chars / CHARS_PER_TOKEN);

// One agent's contribution to the ceiling. `priceOf(model)` returns [in, out] USD
// per 1M tokens, or undefined for a slug we have no price for.
function agentCost(agent, inTok, outTok, priceOf) {
  const price = agent.priceIn != null && agent.priceOut != null
    ? [agent.priceIn, agent.priceOut]
    : priceOf(agent.model);
  if (!price) return { usd: null, inTok, outTok };
  return { usd: (inTok / 1e6) * price[0] + (outTok / 1e6) * price[1], inTok, outTok };
}

/**
 * Ceiling cost for a run, in USD.
 *
 * @param {object}   o
 * @param {number}   o.taskChars    Length of the submitted artifact, in characters.
 * @param {number}   o.rounds       Max rounds (the ceiling assumes none are skipped).
 * @param {string}   o.mode         "harden" | "review" | "readiness" | "vibe-app".
 * @param {object}   o.proposer     { name, model, max_tokens?, systemChars?, priceIn?, priceOut? }
 * @param {object[]} o.adversaries  Same shape, one per adversary.
 * @param {Function} o.priceOf      (model) => [usdPerMinput, usdPerMoutput] | undefined
 */
export function estimateRun({ taskChars, rounds, mode, proposer, adversaries = [], priceOf }) {
  const cap = (a) => a.max_tokens ?? ASSUMED_MAX_TOKENS;
  const assumedCaps = [proposer, ...adversaries].filter(a => a && a.max_tokens == null).map(a => a.name);

  const taskTok = toTokens(taskChars);
  const sysTok = (a) => toTokens(a.systemChars ?? 0);
  const rows = [];

  // readiness is a single call — one gate, no panel, no rounds.
  if (mode === "readiness") {
    const inTok = taskTok + sysTok(proposer);
    rows.push({ name: proposer.name, model: proposer.model, calls: 1,
      ...agentCost(proposer, inTok, cap(proposer), priceOf) });
    return summarise(rows, { rounds: 1, assumedCaps });
  }

  const propCap = cap(proposer);
  // Ceiling on the critique text fed back to the proposer: each adversary's full
  // output cap. (The proposer sees critiques untruncated; only the adversaries'
  // view of the PRIOR round is capped — see PREV_REVIEW_CAP below.)
  const critiquesTok = adversaries.reduce((n, a) => n + cap(a), 0);

  let propIn = 0, propCalls = 0;
  const advIn = adversaries.map(() => 0);
  let advCalls = 0;

  for (let round = 1; round <= rounds; round++) {
    // vibe-app round 1 skips the proposer entirely — the attacker goes first
    // against the raw artifact, so there is no draft to defend yet.
    const proposerRuns = !(mode === "vibe-app" && round === 1);
    if (proposerRuns) {
      // Round 1 has no prior draft or critiques to carry; later rounds do.
      propIn += taskTok + sysTok(proposer) + (round > 1 ? propCap + critiquesTok : 0);
      propCalls += 1;
    }
    adversaries.forEach((a, i) => {
      // Every adversary sees: its persona, the artifact, the current draft
      // (bounded by the proposer's cap), and the head-truncated prior critique.
      advIn[i] += sysTok(a) + taskTok + propCap + (round > 1 ? toTokens(PREV_REVIEW_CAP) : 0);
    });
    advCalls += adversaries.length;
  }

  rows.push({ name: proposer.name, model: proposer.model, calls: propCalls,
    ...agentCost(proposer, propIn, propCap * propCalls, priceOf) });
  adversaries.forEach((a, i) => {
    rows.push({ name: a.name, model: a.model, calls: rounds,
      ...agentCost(a, advIn[i], cap(a) * rounds, priceOf) });
  });

  return summarise(rows, { rounds, assumedCaps });
}

function summarise(rows, { rounds, assumedCaps }) {
  const unpriced = rows.filter(r => r.usd == null).map(r => r.model);
  const ceilingUsd = rows.reduce((n, r) => n + (r.usd ?? 0), 0);
  return {
    ceilingUsd,
    rows,
    rounds,
    calls: rows.reduce((n, r) => n + r.calls, 0),
    // True => at least one agent's cost is missing from ceilingUsd entirely,
    // so the total is a FLOOR on the ceiling, not a ceiling. Callers must say so.
    unpriced,
    // True => at least one agent didn't pin max_tokens, so its share of the
    // ceiling rests on ASSUMED_MAX_TOKENS rather than on a real cap.
    assumedCaps,
    // The input side is always a chars/4 approximation — see the header.
    approximate: true,
  };
}

/**
 * What to charge, given a ceiling and a markup. Kept here so the CLI, the web UI
 * and any future quoting tool cannot drift apart on the arithmetic.
 */
export function quote(ceilingUsd, multiple = 10) {
  return ceilingUsd * multiple;
}
