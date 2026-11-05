// Safe: .final() verifies the tag and authTagLength pins its size; and a
// non-AEAD mode (CBC) isn't this check's business.
function readAuth(iv, authTag, ct) {
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });  // safe: Weak Cryptography
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

function readCbc(iv, ct) {
  const d = crypto.createDecipheriv("aes-256-cbc", key, iv);  // safe: Weak Cryptography
  return Buffer.concat([d.update(ct), d.final()]);
}
