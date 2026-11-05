/*
 * Safe counterparts to forin_prefix_pollution_vuln.ts, each missing one
 * of the four required signals: (1) a for...in loop, (2) a .startsWith()
 * prefix check on the loop variable, (3) a .slice()-derived variable from
 * it, (4) a bracket assignment using that derived variable.
 */

// Missing signals 2-4: an ordinary, extremely common shallow-copy loop.
// No prefix filter and no .slice() at all - this is completely benign
// and must never be flagged just because it's a for...in + bracket-write.
function shallowCopy(obj: any): any {
  const out: any = {};
  for (const key in obj) {  // safe: Prototype Pollution
    out[key] = obj[key];
  }
  return out;
}

// Has signals 1-2 (loop + prefix check) but the matched prefix is used
// directly, with no .slice()-derived variable and no bracket assignment
// at all - just a boolean check, nothing is ever copied anywhere.
function hasProp(data: any, prefix: string): boolean {
  for (const field in data) {  // safe: Prototype Pollution
    if (field.startsWith(prefix)) {
      return true;
    }
  }
  return false;
}

// Has signals 1-3 (loop, prefix check, .slice()-derived variable) but the
// derived variable is only ever pushed into an array, never used as a
// bracket-assignment key anywhere - signal 4 never fires.
function collectSuffixes(data: any): string[] {
  const suffixes: string[] = [];
  for (const entry in data) {  // safe: Prototype Pollution
    if (entry.startsWith("tag.")) {
      const suffix = entry.slice(4);
      suffixes.push(suffix);
    }
  }
  return suffixes;
}
