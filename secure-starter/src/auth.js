// A1 (rate limit + MFA) and A3 (server-side role, no header trust)
const rateLimit = require('express-rate-limit');

// Throttle every auth endpoint; lock out bursts.
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, standardHeaders: true });

async function login(req, res) {
  const user = await verifyPassword(req.body.email, req.body.password);
  if (!user) return res.status(401).end();

  // Phishing-resistant MFA is required, not optional.
  if (!(await verifyMfa(user, req.body.otp))) return res.status(401).end();

  req.session.userId = user.id;
  req.session.role = user.role;        // role comes from the server session...
}

function requireAdmin(req, res, next) {
  if (req.session.role !== 'admin') return res.status(403).end();  // ...never from a client header
  next();
}

// Step-up: re-verify MFA before money movement / beneficiary / limit changes.
function requireStepUp(req, res, next) {
  if (!req.session.stepUpAt || Date.now() - req.session.stepUpAt > 5 * 60 * 1000)
    return res.status(401).json({ reason: 'step_up_required' });
  next();
}

module.exports = { loginLimiter, login, requireAdmin, requireStepUp };
// mount: app.post('/login', loginLimiter, login)
