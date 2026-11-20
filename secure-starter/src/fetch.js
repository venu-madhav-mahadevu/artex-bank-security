// A5 SSRF — allow-list hosts, force https, block internal ranges, no redirects.
const ALLOWED_HOSTS = new Set(['api.partner.example.com', 'cdn.example.com']);

function isInternal(host) {
  return /^(127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|\[?::1\]?)/.test(host)
      || host === 'localhost' || host === 'metadata.google.internal';
}

async function outboundFetch(rawUrl) {
  const u = new URL(rawUrl);
  if (u.protocol !== 'https:') throw new Error('blocked: non-https');
  if (!ALLOWED_HOSTS.has(u.hostname)) throw new Error('blocked: host not allow-listed');
  if (isInternal(u.hostname)) throw new Error('blocked: internal address');
  return fetch(u, { redirect: 'error' });   // never auto-follow into internal hosts
}
// On cloud: require IMDSv2 so a stray SSRF can't read instance credentials.
module.exports = { outboundFetch };
