// A2 SQL injection — parameterized queries only, never string concatenation.
async function getUser(db, id) {
  return db.query('SELECT * FROM users WHERE id = $1', [id]);          // bound parameter
}
async function searchAccounts(db, term) {
  return db.query('SELECT * FROM accounts WHERE name = $1', [term]);   // bound parameter
}
// Also: least-privilege DB account (no DROP/DDL for the app user).
module.exports = { getUser, searchAccounts };
