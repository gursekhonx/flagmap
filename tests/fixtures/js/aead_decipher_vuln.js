// Fixture for aead_decipher_guard.py (v1.46.0). Mirrors LA CTF 2023
// "zero-trust" (no .final() on the decipher — note the encrypting object
// shares the name `cipher` and DOES call .final()) and 2026 "single-trust"
// (.final() present, but no authTagLength, so a 1-byte tag is accepted).
function makeAuth(data) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  return [iv, cipher.getAuthTag(), ct];
}

function readAuthZeroTrust(iv, authTag, ct) {
  const cipher = crypto.createDecipheriv("aes-256-gcm", key, iv);  // ruleid: Weak Cryptography
  cipher.setAuthTag(authTag);
  return JSON.parse(cipher.update(ct).toString("utf8"));
}

function readAuthSingleTrust(iv, authTag, ct) {
  const cipher = crypto.createDecipheriv("aes-256-gcm", key, iv);  // ruleid: Weak Cryptography
  cipher.setAuthTag(authTag);
  return JSON.parse(Buffer.concat([cipher.update(ct), cipher.final()]).toString("utf8"));
}
