// lib/env.mjs — load a .env file sitting next to the project, if there is one.
//
// The missing-key error has always told people to put the key "in your
// environment / .env". Nothing actually read a .env file, so anyone who followed
// that advice got the same missing-key error with their key sitting in a file a
// metre away. This closes that gap.
//
// Zero dependencies: process.loadEnvFile is built into Node (20.12+/21+). On an
// older runtime it simply doesn't exist, and we skip — package.json still claims
// node >=18, and a .env is a convenience, never the only way in. Exporting the
// variable in your shell works everywhere and always takes precedence.
//
// Precedence: a variable already set in the real environment WINS. loadEnvFile
// does not overwrite existing values, which is what you want — an explicit
// `OPENROUTER_API_KEY=... npm start` must beat whatever is in the file.

import { existsSync } from "node:fs";

/**
 * Load `<dir>/.env` into process.env if it exists. Returns true if a file was
 * read. Never throws: a malformed or unreadable .env must not stop a run that
 * might not need it at all (a cli-adapter config needs no key).
 */
export function loadDotenv(dir) {
  if (typeof process.loadEnvFile !== "function") return false;
  const path = `${dir}/.env`;
  if (!existsSync(path)) return false;
  try {
    process.loadEnvFile(path);
    return true;
  } catch {
    // A broken .env is worth mentioning but not worth dying over — the real
    // environment may already carry the key.
    console.error(`Warning: could not parse ${path}; ignoring it.`);
    return false;
  }
}
