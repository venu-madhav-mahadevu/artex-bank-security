// A11 Deepfake/liveness — verdict computed server-side; a client flag is never trusted.
async function verifyIdentity(frames, livenessService) {
  const verdict = await livenessService.evaluate(frames);
  if (!verdict.live || verdict.virtualCamera) throw new Error('liveness failed');
  return true;
}
// NEVER do: if (req.body.livenessPassed) approve();
module.exports = { verifyIdentity };
