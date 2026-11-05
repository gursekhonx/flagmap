/*
 * Mirrors DownUnderCTF 2024's real "prisoner-processor" web challenge
 * (src/app/src/index.ts) almost verbatim: a for...in loop over an
 * attacker-controlled object, filtered by a literal prefix, stripped
 * with .slice(), and written straight into a bracket assignment on a
 * fresh plain object with no __proto__/constructor denylist. A request
 * key named "signed.__proto__" survives the prefix filter and pollutes
 * Object.prototype.
 */

const SIGNED_PREFIX = "signed.";

const getSignedData = (data: any): any => {
  const signedParams: any = {};
  for (const param in data) {
    if (param.startsWith(SIGNED_PREFIX)) {
      const keyName = param.slice(SIGNED_PREFIX.length);
      signedParams[keyName] = data[param];  // ruleid: Prototype Pollution
    }
  }
  return signedParams;
};
