// A7 (secrets from env/vault) and A8 (hardened cookies, debug off).
const config = {
  stripeKey: process.env.STRIPE_KEY,       // never hardcode; rotate immediately if exposed
  databaseUrl: process.env.DATABASE_URL,
  debug: false,                            // never true in production
};

const cookieOptions = { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 3600000 };

// Do NOT expose /debug, /actuator, admin consoles on the public internet.
module.exports = { config, cookieOptions };
