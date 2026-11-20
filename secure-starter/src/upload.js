// A6 File upload — validate magic bytes + size, random name, store outside web root, never execute.
const crypto = require('crypto');
const ALLOWED = new Set(['image/png', 'image/jpeg', 'application/pdf']);
const MAX_BYTES = 5 * 1024 * 1024;

async function acceptUpload(buf, sniffType, store) {
  if (buf.length > MAX_BYTES) throw new Error('too large');
  if (!ALLOWED.has(sniffType(buf))) throw new Error('type not allowed');   // check content, not extension
  const name = crypto.randomUUID();                                        // discard the client filename
  await store('/var/app-uploads/' + name, buf);                            // outside web root, non-executable
  return name;
}
module.exports = { acceptUpload };
