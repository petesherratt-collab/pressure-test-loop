// lib/pricing.mjs — the one list of models this tool will run, and what they cost.
//
// This table is load-bearing in three places, which is why it lives here rather
// than inside orchestrate.mjs:
//   - the CLI validates --defend/--attack against it, so a typo or a retired slug
//     fails before the run instead of as a 400 mid-round;
//   - the cost table at the end of a run prices real usage from it;
//   - the web UI builds its model dropdowns and its pre-run estimate from it.
// A model that isn't here isn't choosable, and anything choosable has a price.
//
// Per-model USD per 1M tokens, [input, output]. Verify any slug AND price at
// openrouter.ai/models before adding a row, and re-verify periodically —
// providers change prices, and a stale row here silently misprices every quote.
// Slugs/prices last verified 2026-07-08.
export const PRICING = {
  "anthropic/claude-sonnet-4.5": [3, 15],
  "anthropic/claude-sonnet-4.6": [3, 15],
  "anthropic/claude-haiku-4.5":  [1, 5],
  "anthropic/claude-opus-4.8":   [5, 25],
  "google/gemini-2.5-flash":     [0.30, 2.50],
  "google/gemini-2.5-pro":       [1.25, 10],
  "google/gemini-3.5-flash":     [1.50, 9],
  "openai/gpt-5.5":              [5, 30],
  "anthropic/claude-fable-5":    [10, 50],
  "deepseek/deepseek-v4-pro":    [0.43, 0.87],
  "qwen/qwen3-max":              [0.78, 3.90],
  // Coding-tuned attackers. Added for the review/code modes, where the frontier
  // generalists are priced for reasoning breadth this seat doesn't need. Note
  // kimi-k2.7-code and qwen3-coder-plus are CHEAPER than gemini-3.5-flash on both
  // sides, so trading the Gemini seat for one of them costs nothing to try.
  // Moonshot and Alibaba are also different labs from Anthropic/OpenAI/Google,
  // so they widen the panel's decorrelation rather than narrowing it.
  "moonshotai/kimi-k3":          [3.00, 15.00],
  "moonshotai/kimi-k2.7-code":   [0.73, 3.50],
  "qwen/qwen3-coder-plus":       [0.65, 3.25],
  "z-ai/glm-5.2":                [0.77, 2.42],
};

export const CHOOSABLE = Object.keys(PRICING);

export const priceOf = (model) => PRICING[model];

// ── the reasoning trap ───────────────────────────────────────────────────────
// Models that split their completion into hidden `reasoning` and visible
// `content`. This matters more than capability when picking an ADVERSARY,
// because an adversary's turn only counts if it ends in a nonce-signed verdict
// line. OpenRouter's max_tokens caps reasoning + content TOGETHER, so a model
// that thinks hard about a large artifact can spend the whole budget before
// writing anything — and an empty reply is a seat that silently stops gating
// convergence while still billing.
//
// Measured, not guessed: each of these was probed against the same 8k artifact
// at max_tokens 8000 and the reasoning_tokens read off the usage block.
//   moonshotai/kimi-k2.7-code   8000 reasoning, 0 content   <- mute
//   z-ai/glm-5.2                8650 reasoning, 0 content   <- mute
//   x-ai/grok-4.5               6497 reasoning, 395 content <- reasons, but answers
//   qwen/qwen3-coder-plus          0 reasoning, 663 content
//   mistralai/mistral-medium-3-5   0 reasoning, 474 content
// Slugs NOT listed here are simply unmeasured — absence is not a claim that a
// model doesn't reason. Probe before seating a new one; it costs about $0.02.
//
// If you must seat a reasoning model: raise ITS max_tokens (24000 worked for
// kimi where 8000 did not — though it still went mute intermittently, and
// tripled the run's wall-clock, because the round waits on its slowest seat).
// `"reasoning": {"effort":"low"}` is NOT a fix — kimi produced 8857 reasoning
// tokens under it, more than the entire cap.
export const REASONING_MODELS = new Set([
  "moonshotai/kimi-k2.7-code",
  "z-ai/glm-5.2",
  "x-ai/grok-4.5",
]);

export const reasons = (model) => REASONING_MODELS.has(model);

// The vendor a slug comes from. Used to warn when the proposer and its
// adversaries share a lab — a panel that agrees because it thinks alike isn't
// a red team, it's an echo. Kept next to the table so a new row's vendor prefix
// is obvious at the point you add it.
export const vendorOf = (model) => (typeof model === "string" ? model.split("/")[0] : null);

export function choosableMenu() {
  return CHOOSABLE.map(m => `  ${m.padEnd(30)} $${PRICING[m][0]}/$${PRICING[m][1]} per 1M tok`).join("\n");
}
