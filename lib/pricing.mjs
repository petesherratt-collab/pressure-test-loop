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
};

export const CHOOSABLE = Object.keys(PRICING);

export const priceOf = (model) => PRICING[model];

// The vendor a slug comes from. Used to warn when the proposer and its
// adversaries share a lab — a panel that agrees because it thinks alike isn't
// a red team, it's an echo. Kept next to the table so a new row's vendor prefix
// is obvious at the point you add it.
export const vendorOf = (model) => (typeof model === "string" ? model.split("/")[0] : null);

export function choosableMenu() {
  return CHOOSABLE.map(m => `  ${m.padEnd(30)} $${PRICING[m][0]}/$${PRICING[m][1]} per 1M tok`).join("\n");
}
