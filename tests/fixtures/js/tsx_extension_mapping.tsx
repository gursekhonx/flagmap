// .tsx extension mapping + dedicated TypeScript/TSX grammar (patterns.py's
// EXTENSION_LANGUAGE and ast_engine.py's _PARSERS_BY_EXT, v1.23.0). Found via
// a real-corpus audit of CyberSci's own official past-challenges repo
// (CyberSci/PastChallenges): nationals-2024-25's defence challenges ship
// real React+Remix frontends (voter_registry, candidate_registry) whose
// route/component files are .tsx — previously an extension with NO entry
// in EXTENSION_LANGUAGE at all, so scanner.iter_source_files() skipped every
// one of them outright (`if not lang: continue`), completely invisible to
// both the regex layer and the JS AST taint engine.
//
// Mapped to the same "js" language tag .ts already uses (same SINKS/regex
// rules), BUT — unlike plain .js — parsing real .tsx needs its own grammar,
// not plain tree-sitter-javascript's. The `interface` block below isn't a
// localized, recoverable error under the plain JS grammar: its error
// recovery folds the interface AND everything parsed after it — including
// the real function body and its real sinks — into one bogus
// statement_block/labeled_statement subtree, which silently breaks the
// taint walker for the rest of the file (confirmed via direct AST dumps
// before this fix shipped). ast_engine.py now selects a dedicated
// tree-sitter-typescript grammar for .ts/.tsx by real file extension
// (_PARSERS_BY_EXT), which parses this exact shape with no error at all and
// produces identical node-type names to plain JS for every construct the
// taint walker relies on — so all three sinks below, not just the one after
// the interface block that plain JS's recovery happened not to swallow, are
// expected to fire.

interface StationProps {
  req: { query: Record<string, string> };
}

export default function Station({ req }: StationProps) {
  const stationId: string = req.query.id;

  // Cross-statement taint through a typed variable — the kind of flow
  // that was simply never reachable before this extension existed, since
  // the file itself was never opened.
  const result = db.query("SELECT * FROM stations WHERE id = " + stationId);  // ruleid: SQL Injection

  fetch("http://" + stationId + "/status");  // ruleid: SSRF (Server-Side Request Forgery)

  return <div dangerouslySetInnerHTML={{ __html: stationId }} />;  // ruleid: Cross-Site Scripting (XSS) — DOM-based
}
