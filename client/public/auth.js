const crypto = require('node:crypto');

// The server never gets the password: it gets a secret derived from it.
// The private key is encrypted with another key, derived with a random salt,
// so the server cannot use what it receives to decrypt it.
function deriveAuthSecret(name, password) {
  return crypto.pbkdf2Sync(password, 'e2e-chat-auth:' + name, 100000, 32, 'sha256').toString('hex');
}

module.exports = { deriveAuthSecret };
